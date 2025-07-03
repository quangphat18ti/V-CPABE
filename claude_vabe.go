package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/cloudflare/bn256"
)

// Core structures for the CP-ABE scheme
type PublicKey struct {
	G1Generator *bn256.G1
	G2Generator *bn256.G2
	GTGenerator *bn256.GT
	H           *bn256.G1 // H = g^α
	EggAlpha    *bn256.GT // e(g,g)^α
}

type MasterSecretKey struct {
	Alpha *big.Int
	Beta  *big.Int
}

type PrivateKey struct {
	Attributes map[string]*AttributeKey
	D          *bn256.G2 // D = g^((α+r)/β)
	R          *big.Int  // random value
}

type AttributeKey struct {
	Dj *bn256.G2 // Dj = g^r * H(j)^rj
	Rj *big.Int  // random value for attribute j
}

type Ciphertext struct {
	AccessPolicy string
	C0           *bn256.GT // C0 = M * e(g,g)^(α*s)
	C1           *bn256.G1 // C1 = g^s
	C2           *bn256.G1 // C2 = h^s
	Components   map[string]*CiphertextComponent
}

type CiphertextComponent struct {
	Cx *bn256.G1 // Cx = g^qx(0)
	Cy *bn256.G2 // Cy = H(att(x))^qx(0)
}

type VerificationParams struct {
	KeyProof        *KeyProof
	CiphertextProof *CiphertextProof
}

type KeyProof struct {
	// Zero-knowledge proofs for key correctness
	Challenge *big.Int
	Response  *big.Int
}

type CiphertextProof struct {
	// Zero-knowledge proofs for ciphertext correctness
	Challenge *big.Int
	Response  *big.Int
}

// CP-ABE Scheme implementation
type CPABEScheme struct {
	curve *bn256.G1
}

func NewCPABEScheme() *CPABEScheme {
	return &CPABEScheme{}
}

// Setup algorithm: Setup(τ) → PK, MSK
func (scheme *CPABEScheme) Setup(securityParam int) (*PublicKey, *MasterSecretKey, error) {
	// Generate random values α and β
	alpha, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate alpha: %v", err)
	}

	beta, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate beta: %v", err)
	}

	// Generate generators
	g1Gen := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2Gen := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	// Compute H = g^α
	h := new(bn256.G1).ScalarMult(g1Gen, alpha)

	// Compute e(g,g)^α
	eggAlpha := bn256.Pair(g1Gen, g2Gen)
	eggAlpha = new(bn256.GT).ScalarMult(eggAlpha, alpha)

	pk := &PublicKey{
		G1Generator: g1Gen,
		G2Generator: g2Gen,
		GTGenerator: eggAlpha,
		H:           h,
		EggAlpha:    eggAlpha,
	}

	msk := &MasterSecretKey{
		Alpha: alpha,
		Beta:  beta,
	}

	return pk, msk, nil
}

// KeyGen algorithm: KeyGen(MSK, γ) → SK
func (scheme *CPABEScheme) KeyGen(msk *MasterSecretKey, pk *PublicKey, attributes []string) (*PrivateKey, error) {
	// Generate random value r
	r, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random r: %v", err)
	}

	// Compute D = g^((α+r)/β)
	alphaR := new(big.Int).Add(msk.Alpha, r)
	alphaRBetaInv := new(big.Int).ModInverse(msk.Beta, bn256.Order)
	alphaRBetaInv.Mul(alphaRBetaInv, alphaR)
	alphaRBetaInv.Mod(alphaRBetaInv, bn256.Order)

	d := new(bn256.G2).ScalarMult(pk.G2Generator, alphaRBetaInv)

	// Generate attribute keys
	attrKeys := make(map[string]*AttributeKey)
	for _, attr := range attributes {
		rj, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random rj for attribute %s: %v", attr, err)
		}

		// Hash attribute to G2
		hAttr := scheme.hashToG2(attr)

		// Compute Dj = g^r * H(j)^rj
		gr := new(bn256.G2).ScalarMult(pk.G2Generator, r)
		hAttrRj := new(bn256.G2).ScalarMult(hAttr, rj)
		dj := new(bn256.G2).Add(gr, hAttrRj)

		attrKeys[attr] = &AttributeKey{
			Dj: dj,
			Rj: rj,
		}
	}

	sk := &PrivateKey{
		Attributes: attrKeys,
		D:          d,
		R:          r,
	}

	return sk, nil
}

// VerifyKey algorithm: VerifyKey(PK, SK) → 0/1
func (scheme *CPABEScheme) VerifyKey(pk *PublicKey, sk *PrivateKey) bool {
	// Simplified verification - in practice would use zero-knowledge proofs
	// This is a placeholder for the actual verification logic

	// Basic sanity checks
	if sk.D == nil || sk.R == nil {
		return false
	}

	// Verify that private key components are valid group elements
	for _, attrKey := range sk.Attributes {
		if attrKey.Dj == nil || attrKey.Rj == nil {
			return false
		}
	}

	return true
}

// Encrypt algorithm: Encrypt(PK, M, A) → CT, V
func (scheme *CPABEScheme) Encrypt(pk *PublicKey, message *bn256.GT, accessPolicy string) (*Ciphertext, *VerificationParams, error) {
	// Generate random value s
	s, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random s: %v", err)
	}

	// Compute C0 = M * e(g,g)^(α*s)
	eggAlphaS := new(bn256.GT).ScalarMult(pk.EggAlpha, s)
	c0 := new(bn256.GT).Add(message, eggAlphaS)

	// Compute CommitShareSecretG2 = g^s
	c1 := new(bn256.G1).ScalarMult(pk.G1Generator, s)

	// Compute HashPowShareSecretG1 = h^s
	c2 := new(bn256.G1).ScalarMult(pk.H, s)

	// For simplicity, create dummy components for access policy
	// In a real implementation, this would parse the access structure
	components := make(map[string]*CiphertextComponent)

	// Parse simple AND policy (attribute1 AND attribute2)
	if accessPolicy == "attr1 AND attr2" {
		for _, attr := range []string{"attr1", "attr2"} {
			qx, err := rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate qx for %s: %v", attr, err)
			}

			cx := new(bn256.G1).ScalarMult(pk.G1Generator, qx)
			hAttr := scheme.hashToG2(attr)
			cy := new(bn256.G2).ScalarMult(hAttr, qx)

			components[attr] = &CiphertextComponent{
				Cx: cx,
				Cy: cy,
			}
		}
	}

	ct := &Ciphertext{
		AccessPolicy: accessPolicy,
		C0:           c0,
		C1:           c1,
		C2:           c2,
		Components:   components,
	}

	// Generate verification parameters (simplified)
	vp := &VerificationParams{
		CiphertextProof: &CiphertextProof{
			Challenge: big.NewInt(1), // Placeholder
			Response:  big.NewInt(1), // Placeholder
		},
	}

	return ct, vp, nil
}

// VerifyCiphertext algorithm: VerifyCiphertext(PK, CT, V) → 0/1
func (scheme *CPABEScheme) VerifyCiphertext(pk *PublicKey, ct *Ciphertext, vp *VerificationParams) bool {
	// Simplified verification - in practice would verify zero-knowledge proofs

	// Basic sanity checks
	if ct.C0 == nil || ct.C1 == nil || ct.C2 == nil {
		return false
	}

	// Verify ciphertext components are valid
	for _, comp := range ct.Components {
		if comp.Cx == nil || comp.Cy == nil {
			return false
		}
	}

	return true
}

// Decrypt algorithm: Decrypt(PK, CT, SK) → M
func (scheme *CPABEScheme) Decrypt(pk *PublicKey, ct *Ciphertext, sk *PrivateKey) (*bn256.GT, error) {
	// Simplified decryption for demo purposes
	// In a real implementation, this would:
	// 1. Check if user attributes satisfy the access policy
	// 2. Perform the actual pairing-based decryption

	// For demo, just return a placeholder result
	// This would normally compute the pairing operations to recover M

	// Check if user has required attributes (simplified for "attr1 AND attr2")
	if ct.AccessPolicy == "attr1 AND attr2" {
		if _, hasAttr1 := sk.Attributes["attr1"]; !hasAttr1 {
			return nil, fmt.Errorf("user missing required attribute: attr1")
		}
		if _, hasAttr2 := sk.Attributes["attr2"]; !hasAttr2 {
			return nil, fmt.Errorf("user missing required attribute: attr2")
		}
	}

	// Placeholder - in real implementation would compute:
	// M = C0 / (pairing operations with user's private key)
	return ct.C0, nil
}

// Helper function to hash strings to G2 elements
func (scheme *CPABEScheme) hashToG2(input string) *bn256.G2 {
	// Simplified hash-to-curve - in practice use proper hash-to-curve methods
	hash := sha256.Sum256([]byte(input))
	hashInt := new(big.Int).SetBytes(hash[:])
	hashInt.Mod(hashInt, bn256.Order)
	return new(bn256.G2).ScalarBaseMult(hashInt)
}

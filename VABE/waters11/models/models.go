package models

import (
	. "cpabe-prototype/VABE/access-policy"
	"github.com/cloudflare/bn256"
	"math/big"
)

type Secrete big.Int

type SecurityParameter struct{}

type Message bn256.GT

type PublicKey struct {
	G1       *bn256.G1 // Generator of G1
	G2       *bn256.G2 // Generator of G2
	G1A      *bn256.G1 // g1^a
	EggAlpha *bn256.GT // e(g1^α, g2)
}

type MasterSecretKey struct {
	Alpha *big.Int  // α, the master secret
	G2A   *bn256.G2 // g1^a
}

// SecretKey represents a user's secret key
type SecretKey struct {
	AttrList []string
	K0       *bn256.G2 // K0 = g2^{α+at}
	L        *bn256.G2 // L = g2^t
	K        map[string]*AttributeKey
}

type SecretKeyProof struct{}

// AttributeKey represents keys for each attribute
type AttributeKey struct {
	K1 *bn256.G1 // hash[attr]^rand
}

// Ciphertext represents encrypted data
type Ciphertext struct {
	EncryptedData []byte
	RandGT        *bn256.GT // Random GT used for encryption
	Policy        AccessPolicy
	C0            *bn256.G1 // C0 = g1^s
	CM            *bn256.GT // C_m = e(g1^α, g2)^s * M
	C             []*AttributeCiphertext
}

// AttributeCiphertext represents ciphertext components for each attribute
type AttributeCiphertext struct {
	C1 *bn256.G1 // C1 = g1^{a * share} * H[attr]^{-random}
	C2 *bn256.G2 // C2 = g2^{rand}
}

type CiphertextProof struct {
	CommitRootSecretG2     *bn256.G2             // Commitment to the secret
	InnerNodeCiphertexts   []AttributeCiphertext // Commitments to the share secrets of inner nodes
	EggCommitAllPolynomial [][]*bn256.GT         // Commitments to all polynomial coefficients of all inner nodes
	EggASecret             *bn256.GT             // Commitment to the secret in GT
}

type VerificationParams struct {
	KeyProof        *SecretKeyProof
	CiphertextProof *CiphertextProof
}

/*
package models

import (
	. "cpabe-prototype/VABE/access-policy"
	"github.com/cloudflare/bn256"
	"math/big"
)

type Secrete big.Int

// PublicKey represents the public parameters
type PublicKey struct {
	G1       *bn256.G1
	G2       *bn256.G2
	G1A        *bn256.G2 // G1A = g2^β
	EggAlpha *bn256.GT
}

// MasterSecretKey represents the master secret key
type MasterSecretKey struct {
	Alpha    *big.Int
	G2A *bn256.G1
}

// SecretKey represents a user's secret key
type SecretKey struct {
	AttrList []string
	K0       *bn256.G1 // K0 = g1^(α+r)/B
	K        map[string]*AttributeKey
}

type SecretKeyProof struct {
	V *bn256.GT // e(g1, g2)^r
}

// AttributeKey represents keys for each attribute
type AttributeKey struct {
	K1 *bn256.G1 // CommitRandomSecretG2 = (g1^rand) * hash[attr]^rand
	K2 *bn256.G2 //  HashPowShareSecretG1 = g2^rand
}

// Ciphertext represents encrypted data
type Ciphertext struct {
	EncryptedData []byte
	RandGT        *bn256.GT // Random GT used for encryption
	Policy        AccessPolicy
	C0            *bn256.G2 // C0 = h^s
	CM            *bn256.GT // C_m = e(g1^α, g2)^s * M
	C             []*AttributeCiphertext
}

// AttributeCiphertext represents ciphertext components for each attribute
type AttributeCiphertext struct {
	C1 *bn256.G2 // C1 = g2^share
	C2 *bn256.G1 // C2 = G1A[attr]^share
}

type CiphertextProof struct {
	CommitRootSecretG2            *bn256.G1     // Commitment to the secret
	InnerNodeCiphertexts []*bn256.G2   // Commitments to the share secrets of inner nodes
	EggCommitAllPolynomial         [][]*bn256.G2 // Commitments to all polynomial coefficients of all inner nodes
}

type VerificationParams struct {
	KeyProof        *SecretKeyProof
	CiphertextProof *CiphertextProof
}

*/

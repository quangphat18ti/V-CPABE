package bsw07

import (
	. "cpabe-prototype/VABE/access-policy"
	"crypto/rand"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
	"time"
)

type BSW07S struct {
	Verbose bool
	salt    []byte // salt for hashing to G1, can be used to ensure uniqueness
}

func NewBSW07S(verbose bool, salt []byte) *BSW07S {
	if salt == nil {
		salt = []byte("default_salt") // Default salt if none provided
	}

	return &BSW07S{
		Verbose: verbose,
		salt:    salt,
	}
}

func (scheme *BSW07S) hashToG1(data []byte) (*bn256.G1, error) {
	hash := bn256.HashG1(data, scheme.salt)
	if hash == nil {
		return nil, fmt.Errorf("failed to hash data to G1")
	}
	return hash, nil
}

// Setup generates the public key and master secret key for the BSW07 scheme.
func (scheme *BSW07S) Setup() (*PublicKey, *MasterSecretKey, error) {
	start := time.Now()
	defer func() {
		fmt.Printf("Setup time: %v\n", time.Since(start))
	}()

	if scheme.Verbose {
		fmt.Println("Setup algorithm:")
	}

	// Generate random elements
	_, g1, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random g1: %w", err)
	}

	_, g2, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random g2: %w", err)
	}

	// Generate random αlpha
	alpha, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random alpha: %w", err)
	}

	// Generate random beta
	beta, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random beta: %w", err)
	}

	// Compute public key components
	h := new(bn256.G2).ScalarMult(g2, beta)

	//betaInv := new(big.Int).ModInverse(beta, bn256.Order)
	//f := new(bn256.G2).ScalarMult(g2, betaInv)

	// Compute e(g,g)^α
	g1Alpha := new(bn256.G1).ScalarMult(g1, alpha)
	eggAlpha := bn256.Pair(g1Alpha, g2)

	pk := &PublicKey{
		G1:       g1,
		G2:       g2,
		H:        h,
		EggAlpha: eggAlpha,
	}

	msk := &MasterSecretKey{
		Beta:    beta,
		G1Alpha: g1Alpha,
	}

	return pk, msk, nil
}

func (scheme *BSW07S) KeyGen(msk MasterSecretKey, pk PublicKey, userAttributes []string) (*SecretKey, *SecretKeyProof, error) {
	start := time.Now()
	defer func() {
		fmt.Printf("KeyGen time: %v\n", time.Since(start))
	}()

	if scheme.Verbose {
		fmt.Println("KeyGen algorithm:")
	}

	if len(userAttributes) == 0 {
		return nil, nil, fmt.Errorf("user attributes cannot be empty")
	}

	r, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random r: %w", err)
	}

	g1R := new(bn256.G1).ScalarMult(pk.G1, r)
	betaInv := new(big.Int).ModInverse(msk.Beta, bn256.Order)

	// k0 = (g1^alpha * g1^r)^(1/beta)
	temp := new(bn256.G1).Add(msk.G1Alpha, g1R)
	k0 := new(bn256.G1).ScalarMult(temp, betaInv)

	K := make(map[string]*AttributeKey)
	for _, attr := range userAttributes {
		rAttr, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate random r_attr for attribute %s: %w", attr, err)
		}

		// Hash attribute to G1
		attrHash, err := scheme.hashToG1([]byte(attr))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to hash attribute %s to G1: %w", attr, err)
		}

		attrHashR := new(bn256.G1).ScalarMult(attrHash, rAttr)

		// k_attr1 = g1^r * H(attr)^r_attr
		kAttr1 := new(bn256.G1).Add(g1R, attrHashR)

		// k_attr2 = g2^r_attr
		kAttr2 := new(bn256.G2).ScalarMult(pk.G2, rAttr)

		K[attr] = &AttributeKey{
			K1: kAttr1,
			K2: kAttr2,
		}
	}

	sk := &SecretKey{
		AttrList: userAttributes,
		K0:       k0,
		K:        K,
	}

	proof := &SecretKeyProof{
		V: bn256.Pair(g1R, pk.G2),
	}

	for _, attr := range userAttributes {
		hAttr, err := scheme.hashToG1([]byte(attr))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to hash attribute %s to G1: %w", attr, err)
		}

		k1 := new(bn256.G1).ScalarMult(hAttr, msk.Beta)
		k2 := new(bn256.G2).ScalarMult(pk.H, msk.Beta)

		sk.K[attr] = &AttributeKey{
			K1: k1,
			K2: k2,
		}
	}

	return sk, proof, nil
}

func (scheme *BSW07S) VerifyKey(pk PublicKey, sk SecretKey, proof SecretKeyProof) (bool, error) {
	panic("implement me")
}

func (scheme *BSW07S) Encrypt(pk PublicKey, msg *bn256.GT, policy AccessPolicy) (*Ciphertext, *CiphertextProof, error) {
	start := time.Now()
	defer func() {
		fmt.Printf("Encrypt time: %v\n", time.Since(start))
	}()

	if scheme.Verbose {
		fmt.Println("Encryption algorithm:")
	}

	// Generate random secrete
	s, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, err
	}

	rootNode := accesPolicyToAccessTree(pk, &policy, 1)
	if rootNode == nil {
		return nil, nil, fmt.Errorf("failed to convert access policy to tree")
	}

	secret := Secrete(*s)
	err = scheme.secretSharing(pk, secret, rootNode)
	if err != nil {
		return nil, nil, err
	}

	// Compute C = M * e(g,g)^αs
	eggS := new(bn256.GT).ScalarMult(pk.EggAlpha, s)
	c := new(bn256.GT).Add(msg, eggS)
	ciphertext := &Ciphertext{
		Policy: policy,
		C0:     new(bn256.G2).ScalarMult(pk.H, s),
		C:      make([]*AttributeCiphertext, 0),
		CM:     c,
	}

	ciphertextProof := &CiphertextProof{
		CommitRootSecretG1:            new(bn256.G1).ScalarMult(pk.G1, s),
		CommitShareSecretInnerNodesG2: make([]*bn256.G2, 0),
		CommitAllPolynomialG2:         make([][]*bn256.G2, 0),
	}

	scheme.collectCiphertext(rootNode, ciphertext, ciphertextProof)

	return ciphertext, ciphertextProof, nil
}

func randomPolynomial(threshold int) []big.Int {
	polynomial := make([]big.Int, threshold)
	for i := 1; i <= threshold; i++ {
		randCoefficient, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			panic("failed to generate random polynomial coefficient")
		}
		polynomial[i] = *randCoefficient
	}
	return polynomial
}

func (scheme *BSW07S) secretSharing(pk PublicKey, s Secrete, node *Node) error {
	node.Secrete = s

	if node.Threshold < 1 {
		return fmt.Errorf("threshold must be at least 1")
	}
	node.Polynomial = randomPolynomial(node.Threshold)
	node.Polynomial[0] = big.Int(s)

	if node.Type == LeafNodeType {
		if err := scheme.calculateLeafCipher(pk, node); err != nil {
			return fmt.Errorf("failed to calculate leaf cipher for node %s: %w", node.Attribute, err)
		}
	} else {
		for id, childNode := range node.Children {
			sharedSecret := scheme.devideShare(node.Polynomial, childNode.Index)
			err := scheme.secretSharing(pk, sharedSecret, childNode)
			if err != nil {
				return fmt.Errorf("failed to share secret with child node %d: %w", id, err)
			}
		}
	}

	if err := scheme.calculateInnerCipher(pk, node); err != nil {
		return fmt.Errorf("failed to calculate inner cipher for node %s: %w", node.Attribute, err)
	}
	return nil
}

func (scheme *BSW07S) devideShare(polynomial []big.Int, x int) Secrete {
	// With larrange interpolation, we need to compute f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n
	result := new(big.Int).Set(&polynomial[0])
	for i := 1; i < len(polynomial); i++ {
		xpowi := new(big.Int).Exp(big.NewInt(int64(x)), big.NewInt(int64(i)), bn256.Order)
		val_i := new(big.Int).Mul(&polynomial[i], xpowi)
		result = new(big.Int).Add(result, val_i)
		result = new(big.Int).Mod(result, bn256.Order)
	}

	secret := Secrete(*result)
	return secret
}

func (scheme *BSW07S) calculateLeafCipher(pk PublicKey, node *Node) error {
	secreteInt := big.Int(node.Secrete)
	node.LeafCipher.CommitShareSecretG2 = new(bn256.G2).ScalarMult(pk.G2, &secreteInt)

	hash, err := scheme.hashToG1([]byte(node.Attribute))
	if err != nil {
		return fmt.Errorf("failed to hash attribute %s to G1: %w", node.Attribute, err)
	}
	node.LeafCipher.HashPowShareSecretG1 = new(bn256.G1).ScalarMult(hash, &secreteInt)

	return nil
}

func (scheme *BSW07S) calculateInnerCipher(pk PublicKey, node *Node) error {
	secreteInt := big.Int(node.Secrete)
	node.InnerCipher.CommitShareSecretG2 = new(bn256.G2).ScalarMult(pk.G2, &secreteInt)

	node.InnerCipher.CommitPolynomialCoeffG2 = make([]*bn256.G2, node.Threshold)
	for i := 1; i < node.Threshold; i++ {
		node.InnerCipher.CommitPolynomialCoeffG2[i] = new(bn256.G2).ScalarMult(pk.G2, &node.Polynomial[i])
	}

	return nil
}

func (scheme *BSW07S) collectCiphertext(root *Node, ciphertext *Ciphertext, ciphertextProof *CiphertextProof) {
	if root.Type == LeafNodeType {
		ciphertext.C = append(ciphertext.C, &AttributeCiphertext{
			C1: root.LeafCipher.CommitShareSecretG2,
			C2: root.LeafCipher.HashPowShareSecretG1,
		})
	} else {
		ciphertextProof.CommitShareSecretInnerNodesG2 = append(ciphertextProof.CommitShareSecretInnerNodesG2, root.InnerCipher.CommitShareSecretG2)
		ciphertextProof.CommitAllPolynomialG2 = append(ciphertextProof.CommitAllPolynomialG2, root.InnerCipher.CommitPolynomialCoeffG2)

		for _, child := range root.Children {
			scheme.collectCiphertext(child, ciphertext, ciphertextProof)
		}
	}
}

func (scheme *BSW07S) Decrypt(pk PublicKey, ciphertext *Ciphertext, key *SecretKey) (*Message, error) {
	panic("implement me")
}

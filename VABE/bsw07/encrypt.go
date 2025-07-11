package bsw07

import (
	. "cpabe-prototype/VABE/access-policy"
	"crypto/rand"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
	"time"
)

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
	return computeLagrangeAtIndex(polynomial, x)
}

func computeLagrangeAtIndex(polynomial []big.Int, x int) Secrete {
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

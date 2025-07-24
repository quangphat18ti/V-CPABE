package waters11

import (
	. "cpabe-prototype/VABE/access-policy"
	"cpabe-prototype/VABE/waters11/models"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
	"time"
)

func (scheme *Waters11) Encrypt(pk models.PublicKey, msg []byte, policy AccessPolicy) (*models.Ciphertext, *models.CiphertextProof, error) {
	start := time.Now()
	defer func() {
		fmt.Printf("Encrypt time: %v\n", time.Since(start))
	}()

	if scheme.Verbose {
		fmt.Println()
		fmt.Println("---> Encryption phase <---:")
	}

	_, randomGT, err := bn256.RandomGT(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random GT: %w", err)
	}

	encryptedKey, err := gTToAESKey(randomGT)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert GT to AES key: %w", err)
	}
	if scheme.Verbose {
		encryptedKeyJson, _ := json.Marshal(encryptedKey)
		fmt.Println("Msg:", string(msg))
		fmt.Println("AES Encrypted key:", string(encryptedKeyJson))
	}

	encryptedFileContent, err := EncryptAES(encryptedKey, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt file content: %w", err)
	}

	// Generate random secrete
	s, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, err
	}

	index := 0
	rootNode := accesPolicyToAccessTree(&policy, &index)
	if rootNode == nil {
		return nil, nil, fmt.Errorf("failed to convert access policy to tree")
	}

	secret := models.Secrete(*s)
	err = scheme.secretSharing(pk, secret, rootNode)
	if err != nil {
		return nil, nil, err
	}

	// Compute C = M * e(g,g)^αs
	eggS := new(bn256.GT).ScalarMult(pk.EggAlpha, s)
	c := new(bn256.GT).Add(randomGT, eggS)
	ciphertext := &models.Ciphertext{
		//RandGT:        randomGT,
		EncryptedData: encryptedFileContent,
		Policy:        policy,
		C0:            new(bn256.G1).ScalarMult(pk.G1, s),
		C:             make([]*models.AttributeCiphertext, 0),
		CM:            c,
	}

	eggA := bn256.Pair(pk.G1A, pk.G2)
	eggASecret := new(bn256.GT).ScalarMult(eggA, s)
	ciphertextProof := &models.CiphertextProof{
		CommitRootSecretG2:     new(bn256.G2).ScalarMult(pk.G2, s),
		InnerNodeCiphertexts:   make([]models.AttributeCiphertext, 0),
		EggCommitAllPolynomial: make([][]*bn256.GT, 0),
		EggASecret:             eggASecret,
	}

	scheme.collectCiphertext(rootNode, ciphertext, ciphertextProof)

	return ciphertext, ciphertextProof, nil
}

func randomPolynomial(threshold int) []big.Int {
	polynomial := make([]big.Int, threshold)
	for i := 0; i < threshold; i++ {
		randCoefficient, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			panic("failed to generate random polynomial coefficient")
		}
		polynomial[i] = *randCoefficient
	}
	return polynomial
}

func (scheme *Waters11) secretSharing(pk models.PublicKey, s models.Secrete, node *models.Node) error {
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
		return nil
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

func (scheme *Waters11) devideShare(polynomial []big.Int, x int) models.Secrete {
	return computeLagrangeAtIndex(polynomial, x)
}

func computeLagrangeAtIndex(polynomial []big.Int, x int) models.Secrete {
	// With larrange interpolation, we need to compute f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n
	result := new(big.Int).Set(&polynomial[0])
	for i := 1; i < len(polynomial); i++ {
		xpowi := new(big.Int).Exp(big.NewInt(int64(x)), big.NewInt(int64(i)), bn256.Order)
		val_i := new(big.Int).Mul(&polynomial[i], xpowi)
		result = new(big.Int).Add(result, val_i)
		result = new(big.Int).Mod(result, bn256.Order)
	}

	secret := models.Secrete(*result)
	return secret
}

func (scheme *Waters11) calculateLeafCipher(pk models.PublicKey, node *models.Node) error {
	secreteInt := big.Int(node.Secrete)
	random, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return fmt.Errorf("failed to generate random number for leaf cipher: %w", err)
	}

	node.LeafCipher = &models.LeafNodeCiphertext{}
	node.LeafCipher.CommitRandomSecretG2 = new(bn256.G2).ScalarMult(pk.G2, random)

	hash, err := scheme.hashToG1([]byte(node.Attribute))
	if err != nil {
		return fmt.Errorf("failed to hash attribute %s to G1: %w", node.Attribute, err)
	}

	g1AShare := new(bn256.G1).ScalarMult(pk.G1A, &secreteInt)
	hashPowNegRand := new(bn256.G1).ScalarMult(hash, random)
	hashPowNegRand = new(bn256.G1).Neg(hashPowNegRand) // Negate the hashPowRandMulSecretG1
	node.LeafCipher.HashPowRandMulSecretG1 = new(bn256.G1).Add(g1AShare, hashPowNegRand)
	return nil
}

func (scheme *Waters11) calculateInnerCipher(pk models.PublicKey, node *models.Node) error {
	secreteInt := big.Int(node.Secrete)
	node.InnerCipher = &models.InnerNodeCiphertext{
		LeafNodeCiphertext: models.LeafNodeCiphertext{},
		EggAPolynomial:     make([]*bn256.GT, node.Threshold),
	}

	random, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return fmt.Errorf("failed to generate random number for leaf cipher: %w", err)
	}
	node.InnerCipher.CommitRandomSecretG2 = new(bn256.G2).ScalarMult(pk.G2, random)

	hash, err := scheme.hashToG1([]byte(node.Attribute))
	if err != nil {
		return fmt.Errorf("failed to hash attribute %s to G1: %w", node.Attribute, err)
	}

	g1AShare := new(bn256.G1).ScalarMult(pk.G1A, &secreteInt)
	hashPowNegRand := new(bn256.G1).ScalarMult(hash, random)
	hashPowNegRand = new(bn256.G1).Neg(hashPowNegRand) // Negate the hashPowRandMulSecretG1
	node.InnerCipher.HashPowRandMulSecretG1 = new(bn256.G1).Add(g1AShare, hashPowNegRand)

	node.InnerCipher.EggAPolynomial = make([]*bn256.GT, node.Threshold)
	for i := 0; i < node.Threshold; i++ {
		eggA := bn256.Pair(pk.G1A, pk.G2)
		node.InnerCipher.EggAPolynomial[i] = new(bn256.GT).ScalarMult(eggA, &node.Polynomial[i])
	}

	return nil
}

func (scheme *Waters11) collectCiphertext(root *models.Node, ciphertext *models.Ciphertext, ciphertextProof *models.CiphertextProof) {
	if root.Type == LeafNodeType {
		ciphertext.C = append(ciphertext.C, &models.AttributeCiphertext{
			C1: root.LeafCipher.HashPowRandMulSecretG1,
			C2: root.LeafCipher.CommitRandomSecretG2,
		})
	} else {
		ciphertextProof.InnerNodeCiphertexts = append(ciphertextProof.InnerNodeCiphertexts, models.AttributeCiphertext{
			C1: root.InnerCipher.HashPowRandMulSecretG1,
			C2: root.InnerCipher.CommitRandomSecretG2,
		})
		ciphertextProof.EggCommitAllPolynomial = append(ciphertextProof.EggCommitAllPolynomial, root.InnerCipher.EggAPolynomial)

		for _, child := range root.Children {
			scheme.collectCiphertext(child, ciphertext, ciphertextProof)
		}
	}
}

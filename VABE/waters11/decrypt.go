package waters11

import (
	"cpabe-prototype/VABE/waters11/models"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
	"time"
)

func (scheme *Waters11) Decrypt(pk models.PublicKey, ciphertext models.Ciphertext, key *models.SecretKey) ([]byte, error) {
	start := time.Now()
	defer func() {
		fmt.Printf("Decrypt time: %v\n", time.Since(start))
	}()

	if scheme.Verbose {
		fmt.Println()
		fmt.Println("Decryption:")
	}

	rootNode, err := scheme.recoverAccessTreeFromCiphertext(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to recover access tree from Ciphertext: %w", err)
	}

	mapAttr := make(map[string]bool)
	for _, attr := range key.AttrList {
		mapAttr[attr] = true
	}

	// check if the user's attributes match the access policy
	minAuthorizedSet, ok := rootNode.PruneTree(mapAttr)
	if !ok {
		return nil, fmt.Errorf("user attributes do not satisfy the access policy: %v", key.AttrList)
	}

	if scheme.Verbose {
		//err = models.SaveAccessTree("out/utils/access_tree_pruned_decrypt.json", rootNode)
		fmt.Printf("Pruned tree with minimum authorized set: %+v\n", minAuthorizedSet)
		prettyPrint(*rootNode)
	}

	prod, err := scheme.runDecryptRecursively(rootNode, key, big.NewInt(1))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt recursively: %w", err)
	}
	if prod == nil {
		return nil, fmt.Errorf("decryption failed")
	}

	// Compute Msg = CM * Prod / e(K0, C0)
	numer := bn256.Pair(ciphertext.C0, key.K0)
	denom := prod

	res := new(bn256.GT).Add(numer, new(bn256.GT).Neg(denom))

	// randomGT = CM/res
	randomGT := new(bn256.GT).Add(ciphertext.CM, new(bn256.GT).Neg(res))

	encryptedKey, err := gTToAESKey(randomGT)
	if err != nil {
		return nil, fmt.Errorf("failed to convert GT to AES key: %w", err)
	}

	msg, err := DecryptAES(encryptedKey, ciphertext.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file content: %w", err)
	}

	if scheme.Verbose {
		msgJson, _ := json.Marshal(msg)
		fmt.Println("Decrypted message:", string(msgJson))
	}

	return msg, nil
}

// runDecryptRecursively performs the recursive decryption process
func (scheme *Waters11) runDecryptRecursively(node *models.Node, key *models.SecretKey, weight *big.Int) (*bn256.GT, error) {
	// prod := ∏[e(D_ρ(u), C_u) / e(C'_u, D'_ρ(u))]^ω_u
	if node.IsLeaf {
		Di, exists := key.K[node.Attribute]
		if !exists {
			return nil, fmt.Errorf("no key found for attribute %s", node.Attribute)
		}

		eC := bn256.Pair(node.LeafCipher.HashPowRandMulSecretG1, key.L)
		eD := bn256.Pair(Di.K1, node.LeafCipher.CommitRandomSecretG2)

		res := new(bn256.GT).Add(eD, eC)
		return new(bn256.GT).ScalarMult(res, weight), nil
	}

	childrenIndexs := make([]*big.Int, 0)
	for _, child := range node.Children {
		childIndex := new(big.Int).SetInt64(int64(child.Index))
		childrenIndexs = append(childrenIndexs, childIndex)
	}

	prod := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	//	calculate larrange coefficients
	for _, child := range node.Children {
		childIndex := new(big.Int).SetInt64(int64(child.Index))

		lagrangeCoeff := computeLagrangeCoeff(childrenIndexs, childIndex, bn256.Order)
		if lagrangeCoeff == nil {
			return nil, fmt.Errorf("failed to compute Lagrange coefficient for child index %s", childIndex)
		}

		childWeight := new(big.Int).Mul(weight, lagrangeCoeff)
		childWeight.Mod(childWeight, bn256.Order)

		prodChild, err := scheme.runDecryptRecursively(child, key, childWeight)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt child node %s: %w", child.Attribute, err)
		}

		if prodChild != nil {
			prod = new(bn256.GT).Add(prod, prodChild)
		}
	}

	return prod, nil
}

package bsw07

import (
	. "cpabe-prototype/VABE/access-policy"
	"cpabe-prototype/VABE/bsw07/models"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/cloudflare/bn256"
	"io"
	"math/big"
	"strings"
)

func accesPolicyToAccessTree(policy *AccessPolicy, index *int) *models.Node {
	if policy.NodeType == LeafNodeType {
		*index++
		return &models.Node{
			Type:      LeafNodeType,
			Attribute: policy.Attribute,
			Index:     *index,
			IsLeaf:    true,
			Threshold: 1,
		}
	}

	children := make([]*models.Node, len(policy.Children))
	for i, child := range policy.Children {
		children[i] = accesPolicyToAccessTree(child, index)
	}

	threshold := 1
	if policy.NodeType == AndNodeType {
		threshold = len(children)
	}

	*index++
	return &models.Node{
		Type:      policy.NodeType,
		Children:  children,
		Index:     *index,
		Threshold: threshold,
	}
}

func computeLagrangeCoeff(positions []*big.Int, targetPos *big.Int, order *big.Int) *big.Int {
	// Δ_u(x) = ∏(x - j) / (i - j) cho j ∈ I, j ≠ i
	// Trong trường hợp này, x = 0, i = targetPos

	numerator := big.NewInt(int64(1))
	denominator := big.NewInt(int64(1))

	for _, j := range positions {
		if j.Cmp(targetPos) != 0 {
			// numerator *= (0 - j) = -j
			numerator.Mul(numerator, new(big.Int).Neg(j))

			// denominator *= (i - j)
			diff := big.NewInt(0).Sub(targetPos, j)
			denominator.Mul(denominator, diff)
		}
	}

	// Δ_u(0) = numerator / denominator = numerator * denominator^(-1) mod p
	denomInv := new(big.Int).ModInverse(denominator, order)
	if denomInv == nil {
		return nil // Không thể tính nghịch đảo, trả về nil
	}

	result := new(big.Int).Mul(numerator, denomInv)
	result.Mod(result, order)

	return result
}

func gTToAESKey(gt *bn256.GT) ([]byte, error) {
	// Convert GT to byte slice
	gtBytes := gt.Marshal()

	//gtJson, _ := json.Marshal(gtBytes)
	//fmt.Println("gTToAESKey:", string(gtJson))

	// Hash the GT bytes to get a proper AES key size (32 bytes for AES-256)
	hasher := sha256.New()
	hasher.Write(gtBytes)
	aesKey := hasher.Sum(nil)

	return aesKey, nil
}

// Encrypt encrypts plaintext using AES-GCM.
func EncryptAES(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts Ciphertext using AES-GCM.
func DecryptAES(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("Ciphertext too short")
	}

	nonce, encryptedMessage := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, encryptedMessage, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func prettyPrint(node models.Node) {
	var dfs func(models.Node, int)
	dfs = func(n models.Node, depth int) {
		fmt.Printf("%s- %s", strings.Repeat("  ", depth), n.Type)
		if n.Type == LeafNodeType {
			fmt.Printf(": %s", n.Attribute)
		}
		fmt.Println()
		for _, child := range n.Children {
			dfs(*child, depth+1)
		}
	}
	dfs(node, 0)
}

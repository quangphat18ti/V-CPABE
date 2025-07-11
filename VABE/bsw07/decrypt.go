package bsw07

import (
	"fmt"
	"time"
)

func (scheme *BSW07S) Decrypt(pk PublicKey, ciphertext *Ciphertext, key *SecretKey) (*Message, error) {
	start := time.Now()
	defer func() {
		fmt.Printf("Decrypt time: %v\n", time.Since(start))
	}()

	if scheme.Verbose {
		fmt.Println("Decryption algorithm:")
	}

	rootNode := accesPolicyToAccessTree(pk, &ciphertext.Policy, 1)
	if rootNode == nil {
		return nil, fmt.Errorf("failed to convert access policy to tree")
	}

	// check if the user's attributes match the access policy
	//if minAuthorizedSet, ok := rootNode.checkAttributes(key.AttrList); !ok {
	//	return nil, fmt.Errorf("user attributes do not satisfy the access policy: %v", )
	//}

	//prod := runDecryptRecursively(ciphertext, key, rootNode)
	//if prod == nil {
	//	return nil, fmt.Errorf("decryption failed")
	//}

	// Compute Msg = CM * Prod / e(K0, C0)
	//numer := new(bn256.GT).Add(ciphertext.CM, prod)
	//denom := bn256.Pair(key.K0, ciphertext.C0)
	//res := new(bn256.GT).Add(numer, new(bn256.GT).Neg(denom))
	//msg := Message(*res)
	//return &msg, nil

	return nil, fmt.Errorf("decryption not implemented yet")
}

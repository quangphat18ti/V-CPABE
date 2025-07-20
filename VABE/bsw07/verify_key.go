package bsw07

import (
	"cpabe-prototype/VABE/bsw07/models"
	"cpabe-prototype/pkg/utilities"
	"fmt"
	"github.com/cloudflare/bn256"
)

type VerifyKeyParams struct {
	pk             models.PublicKey
	sk             models.SecretKey
	keyProof       models.SecretKeyProof
	userAttributes []string
}

func (scheme *BSW07S) VerifyKey(params VerifyKeyParams) (bool, error) {
	if scheme.Verbose {
		fmt.Println("Verifying secret key...")
	}

	_, err := scheme.verifyNumComponents(params.sk, params.userAttributes)
	if err != nil {
		return false, err
	}

	// Verify the K0 in the secret key
	ok := scheme.verifyK0ConstructWithAlphaBeta(params.pk, params.sk, params.keyProof)
	if !ok {
		return false, fmt.Errorf("K0 does not match the expected value based on alpha and beta")
	}

	// Verify each component
	ok = scheme.verifyEachComponent(params.pk, params.sk, params.keyProof)
	if !ok {
		return false, fmt.Errorf("one or more components in the secret key do not match the expected values")
	}

	return ok, nil
}

func (scheme *BSW07S) verifyNumComponents(sk models.SecretKey, attributes []string) (bool, error) {
	// Deep Compare two Arrays
	ok := utilities.Equal(sk.AttrList, attributes)
	if !ok {
		if scheme.Verbose {
			fmt.Println("Secret key attributes do not match user attributes.")
		}
		return false, fmt.Errorf("attributes do not match")
	}

	//	Compare map sk.K is all has keys in attributes
	for _, attr := range sk.AttrList {
		if _, exists := sk.K[attr]; !exists {
			if scheme.Verbose {
				fmt.Printf("Secret key does not contain key for attribute: %s\n", attr)
			}
			return false, fmt.Errorf("secret key does not contain key for attribute: %s", attr)
		}
	}

	// Compare the size of sk.K with the size of attributes
	if len(sk.K) != len(sk.AttrList) {
		if scheme.Verbose {
			fmt.Println("Secret key does not have the same number of components as user attributes.")
		}
		return false, fmt.Errorf("secret key does not have the same number of components as user attributes")
	}

	return true, nil
}

func (scheme *BSW07S) verifyK0ConstructWithAlphaBeta(pk models.PublicKey, sk models.SecretKey, proof models.SecretKeyProof) bool {
	// e(K0, H) should equal e(g1, g2)^alpha * proof.V
	left := bn256.Pair(sk.K0, pk.H)
	right := new(bn256.GT).Add(pk.EggAlpha, proof.V)

	if !utilities.CompareGTByString(left, right) {
		if scheme.Verbose {
			fmt.Println("✗ K0 does not match the expected value based on alpha and beta.")
			//fmt.Printf("Expected: %s\n", right.String())
			//fmt.Printf("Got:      %s\n", left.String())
		}
		return false
	}

	if scheme.Verbose {
		fmt.Println("✓ K0 verification passed")
	}
	return true
}

func (scheme *BSW07S) verifyEachComponent(pk models.PublicKey, sk models.SecretKey, proof models.SecretKeyProof) bool {
	//	for each component in K[]: e(K[attr].D1, g2) = e(H[attr], K[attr].D2) * proof.V
	for attr, key := range sk.K {
		fmt.Printf("Verifying key for attribute %s\n", attr)
		if key == nil {
			if scheme.Verbose {
				fmt.Printf("Secret key does not contain key for attribute: %s\n", attr)
			}
			return false
		}

		left := bn256.Pair(key.K1, pk.G2)

		hashToG1, err := scheme.hashToG1([]byte(attr))
		if err != nil {
			if scheme.Verbose {
				fmt.Printf("Error hashing attribute %s: %v\n", attr, err)
			}
			return false
		}

		right := bn256.Pair(hashToG1, key.K2)
		right = new(bn256.GT).Add(right, proof.V)

		if !utilities.CompareGTByString(left, right) {
			if scheme.Verbose {
				fmt.Printf("✗ Component for attribute %s does not match the expected values.\n", attr)
				//fmt.Printf("Expected: %s\n", right.String())
				//fmt.Printf("Got:      %s\n", left.String())
			}
			return false
		}

		if scheme.Verbose {
			fmt.Printf("✓ Attribute %s verification passed\n", attr)
		}
	}
	return true
}

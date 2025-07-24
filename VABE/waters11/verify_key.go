package waters11

import (
	"cpabe-prototype/VABE/waters11/models"
	"cpabe-prototype/pkg/utilities"
	"errors"
	"fmt"
	"github.com/cloudflare/bn256"
)

type VerifyKeyParams struct {
	PublicKey      models.PublicKey
	SecretKey      models.SecretKey
	KeyProof       models.SecretKeyProof
	UserAttributes []string
}

func (scheme *Waters11) VerifyKey(params VerifyKeyParams) (bool, error) {
	if scheme.Verbose {
		fmt.Println("Verifying secret key...")
	}

	_, err := scheme.verifyNumComponents(params.SecretKey, params.UserAttributes)
	if err != nil {
		return false, err
	}

	// Verify the K0 in the secret key
	ok := scheme.verifyK0ConstructWithAAndAlpha(params.PublicKey, params.SecretKey, params.KeyProof)
	if !ok {
		return false, fmt.Errorf("K0 does not match the expected value based on alpha and beta")
	}

	// Verify each component
	ok = scheme.verifyEachComponent(params.PublicKey, params.SecretKey, params.KeyProof)
	if !ok {
		return false, fmt.Errorf("one or more components in the secret key do not match the expected values")
	}

	return ok, nil
}

func (scheme *Waters11) verifyNumComponents(sk models.SecretKey, attributes []string) (bool, error) {
	if sk.K0 == nil {
		return false, errors.New("K0 cannot be nil")
	}
	if sk.L == nil {
		return false, errors.New("L cannot be nil")
	}

	// Deep Compare two Arrays
	ok := utilities.Equal(sk.AttrList, attributes)
	if !ok {
		if scheme.Verbose {
			fmt.Println("Secret key attributes do not match user attributes.")
		}
		return false, fmt.Errorf("attributes do not match")
	}

	//	Compare map SecretKey.K is all has keys in attributes
	for _, attr := range sk.AttrList {
		if _, exists := sk.K[attr]; !exists {
			if scheme.Verbose {
				fmt.Printf("Secret key does not contain key for attribute: %s\n", attr)
			}
			return false, fmt.Errorf("secret key does not contain key for attribute: %s", attr)
		}
	}

	// Compare the size of SecretKey.K with the size of attributes
	if len(sk.K) != len(sk.AttrList) {
		if scheme.Verbose {
			fmt.Println("Secret key does not have the same number of components as user attributes.")
		}
		return false, fmt.Errorf("secret key does not have the same number of components as user attributes")
	}

	return true, nil
}

func (scheme *Waters11) verifyK0ConstructWithAAndAlpha(pk models.PublicKey, sk models.SecretKey, proof models.SecretKeyProof) bool {
	// e(g1, K0) should equal e(g1^a, L) * e(g1, g2^alpha)
	left := bn256.Pair(pk.G1, sk.K0)

	eggaL := bn256.Pair(pk.G1A, sk.L)
	right := new(bn256.GT).Add(eggaL, pk.EggAlpha)

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

func (scheme *Waters11) verifyEachComponent(pk models.PublicKey, sk models.SecretKey, proof models.SecretKeyProof) bool {
	//	for each component in K[]: e(Hash[attr], L) = e(K[attr].D1, g2)
	for attr, key := range sk.K {
		fmt.Printf("Verifying key for attribute %s\n", attr)
		if key == nil {
			if scheme.Verbose {
				fmt.Printf("Secret key does not contain key for attribute: %s\n", attr)
			}
			return false
		}

		hashToG1, err := scheme.hashToG1([]byte(attr))
		if err != nil {
			if scheme.Verbose {
				fmt.Printf("Error hashing attribute %s: %v\n", attr, err)
			}
			return false
		}

		left := bn256.Pair(hashToG1, sk.L)
		right := bn256.Pair(key.K1, pk.G2)

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

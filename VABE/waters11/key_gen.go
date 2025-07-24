package waters11

import (
	"cpabe-prototype/VABE/waters11/models"
	"crypto/rand"
	"fmt"
	"github.com/cloudflare/bn256"
	"time"
)

func (scheme *Waters11) KeyGen(msk models.MasterSecretKey, pk models.PublicKey, userAttributes []string) (*models.SecretKey, *models.SecretKeyProof, error) {
	start := time.Now()
	defer func() {
		fmt.Printf("KeyGen time: %v\n", time.Since(start))
	}()

	if scheme.Verbose {
		fmt.Println()
		fmt.Println("KeyGen algorithm:")
	}

	if len(userAttributes) == 0 {
		return nil, nil, fmt.Errorf("user attributes cannot be empty")
	}

	t, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random t: %w", err)
	}

	L := new(bn256.G2).ScalarMult(pk.G2, t)

	// k0 = g2^{alpha + a * t}
	g2AT := new(bn256.G2).ScalarMult(msk.G2A, t)
	g2Alpha := new(bn256.G2).ScalarMult(pk.G2, msk.Alpha)
	k0 := new(bn256.G2).Add(g2Alpha, g2AT)

	K := make(map[string]*models.AttributeKey)
	for _, attr := range userAttributes {
		// Hash attribute to G1
		attrHash, err := scheme.hashToG1([]byte(attr))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to hash attribute %s to G1: %w", attr, err)
		}

		kAttr1 := new(bn256.G1).ScalarMult(attrHash, t)

		K[attr] = &models.AttributeKey{
			K1: kAttr1,
		}
	}

	sk := &models.SecretKey{
		AttrList: userAttributes,
		K0:       k0,
		L:        L,
		K:        K,
	}

	proof := &models.SecretKeyProof{}

	//if scheme.Verbose {
	//	fmt.Println("Verifying generated keys...")
	//	if verified, _ := scheme.VerifyKey(VerifyKeyParams{PublicKey, *SecretKey, *Proof, UserAttributes}); verified {
	//		fmt.Println("✓ Secret key verification passed")
	//	} else {
	//		fmt.Println("✗ Secret key verification failed")
	//	}
	//}

	return sk, proof, nil
}

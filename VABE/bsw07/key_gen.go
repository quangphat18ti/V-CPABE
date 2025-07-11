package bsw07

import (
	"crypto/rand"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
	"time"
)

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

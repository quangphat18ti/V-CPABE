package bsw07

import (
	"crypto/rand"
	"github.com/cloudflare/bn256"
	"math/big"
	"testing"
)

func TestIdentityElement(t *testing.T) {
	// Create the identity element
	prod := new(bn256.GT).ScalarBaseMult(big.NewInt(0))

	// Create some non-identity element A
	randomValue, _ := rand.Int(rand.Reader, bn256.Order)
	A := new(bn256.GT).ScalarBaseMult(randomValue)

	// Calculate prod + A
	sum := new(bn256.GT).Add(prod, A)

	// Check if prod + A = A
	if sum.String() != A.String() {
		t.Errorf("The identity element test failed: prod + A != A")
		t.Errorf("prod: %s", prod.String())
		t.Errorf("A: %s", A.String())
		t.Errorf("sum: %s", sum.String())
	} else {
		t.Logf("Identity property verified: prod + A = A")
	}
}

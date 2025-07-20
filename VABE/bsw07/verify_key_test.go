package bsw07

import (
	"fmt"
	"strconv"
	"testing"
)

func TestSuccessFull(t *testing.T) {
	fmt.Println("\nTest VerifyKey: Success Case")
	attributes := []string{}
	for i := 0; i < 10; i++ {
		attributes = append(attributes, "attr__"+strconv.Itoa(i))
	}

	scheme := NewBSW07S(true, nil)

	pk, msk, err := scheme.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	sk, proof, err := scheme.KeyGen(*msk, *pk, attributes)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	ok, err := scheme.VerifyKey(VerifyKeyParams{
		pk:             *pk,
		sk:             *sk,
		keyProof:       *proof,
		userAttributes: attributes,
	})

	if err != nil {
		t.Errorf("VerifyKey failed: %v", err)
	}

	if !ok {
		t.Error("VerifyKey returned false, expected true")
	} else {
		t.Log("VerifyKey passed successfully")
	}
}

func TestNumberAttributes(t *testing.T) {
	fmt.Println("\nTest VerifyKey: Number of Attributes Mismatch Case")
	attributes := []string{}
	for i := 0; i < 10; i++ {
		attributes = append(attributes, "attr"+strconv.Itoa(i))
	}

	scheme := NewBSW07S(true, nil)

	pk, msk, err := scheme.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	sk, proof, err := scheme.KeyGen(*msk, *pk, attributes)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Modify the attributes to have a different number than the secret key
	attributes = append(attributes, "extra_attr")

	ok, err := scheme.VerifyKey(VerifyKeyParams{
		pk:             *pk,
		sk:             *sk,
		keyProof:       *proof,
		userAttributes: attributes,
	})

	if ok || err == nil {
		t.Error("VerifyKey should have failed due to mismatched number of attributes, but it passed")
	} else {
		t.Log("VerifyKey correctly failed due to mismatched number of attributes")
	}
}

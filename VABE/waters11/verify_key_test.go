package waters11

import (
	"fmt"
	"strconv"
	"testing"
)

func TestVerifyKeySuccessFull(t *testing.T) {
	fmt.Println("\nTest VerifyKey: Success Case")
	attributes := []string{}
	for i := 0; i < 10; i++ {
		attributes = append(attributes, "attr__"+strconv.Itoa(i))
	}

	scheme := NewWaters11(true, nil)

	pk, msk, err := scheme.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	sk, proof, err := scheme.KeyGen(*msk, *pk, attributes)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	ok, err := scheme.VerifyKey(VerifyKeyParams{
		PublicKey:      *pk,
		SecretKey:      *sk,
		KeyProof:       *proof,
		UserAttributes: attributes,
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

func TestVerifyKeyWrong(t *testing.T) {
	fmt.Println("\nTest VerifyKey: Wrong Case")
	attributes := []string{}
	for i := 0; i < 10; i++ {
		attributes = append(attributes, "attr__"+strconv.Itoa(i))
	}

	attributes_wrong := []string{}
	for i := 0; i < 10; i++ {
		attributes_wrong = append(attributes_wrong, "attr__wrong_"+strconv.Itoa(i))
	}

	scheme := NewWaters11(true, nil)

	pk, msk, err := scheme.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	sk, proof, err := scheme.KeyGen(*msk, *pk, attributes_wrong)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	sk.AttrList = attributes // Intentionally set the attributes to the correct ones
	for id, attr := range attributes_wrong {
		val, _ := sk.K[attr]
		delete(sk.K, attr) // Remove the wrong attribute keys
		sk.K[attributes[id]] = val
	}

	ok, err := scheme.VerifyKey(VerifyKeyParams{
		PublicKey:      *pk,
		SecretKey:      *sk,
		KeyProof:       *proof,
		UserAttributes: attributes,
	})

	fmt.Printf(" Expected: VerifyKey FAILED")
	if !ok {
		fmt.Println(" Result: FAILED!")
		fmt.Printf(" Error: %v\n", err)
	} else {
		fmt.Println(" Result: OK!")
		t.Errorf(" VerifyKey should have failed, but it passed")
	}
}

func TestVerifyKeyMoreAttributes(t *testing.T) {
	fmt.Println("\nTest VerifyKey: More Attributes")
	attributes := []string{}
	for i := 0; i < 10; i++ {
		attributes = append(attributes, "attr"+strconv.Itoa(i))
	}

	scheme := NewWaters11(true, nil)

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
		PublicKey:      *pk,
		SecretKey:      *sk,
		KeyProof:       *proof,
		UserAttributes: attributes,
	})

	if ok || err == nil {
		t.Error("VerifyKey should have failed due to mismatched number of attributes, but it passed")
	} else {
		t.Log("VerifyKey correctly failed due to mismatched number of attributes")
	}
}

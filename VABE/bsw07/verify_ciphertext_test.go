package bsw07

import (
	access_policy "cpabe-prototype/VABE/access-policy"
	"fmt"
	"strconv"
	"testing"
)

func TestVerifyCiphertextSuccessFull(t *testing.T) {
	fmt.Println("\nTest VerifyCiphertext: Success Case")
	attributes := []string{}
	for i := 0; i < 10; i++ {
		attributes = append(attributes, "attr__"+strconv.Itoa(i))
	}

	scheme := NewBSW07S(true, nil)

	pk, _, err := scheme.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	message := []byte("Test message for VerifyCiphertext")
	policyStr := "attr__0 and (attr__1 or attr__2)"
	accessPolicy, err := access_policy.FromString(policyStr)
	if err != nil {
		t.Fatalf("Failed to parse access policy: %v", err)
	}

	ciphertext, proof, err := scheme.Encrypt(*pk, message, *accessPolicy)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	verifyParams := VerifyCiphertextParams{
		PublicKey:    *pk,
		Ciphertext:   *ciphertext,
		Proof:        *proof,
		AccessPolicy: *accessPolicy,
	}
	ok, err := scheme.VerifyCiphertext(verifyParams)
	if err != nil {
		t.Errorf("Failed to verify Ciphertext: %v", err)
	}
	if !ok {
		t.Errorf("Ciphertext verification failed, expected success")
	} else {
		fmt.Println("Ciphertext verification succeeded")
	}
}

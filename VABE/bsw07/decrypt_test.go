package bsw07

import (
	access_policy "cpabe-prototype/VABE/access-policy"
	"fmt"
	"testing"
)

func TestDecryptHappyCase(t *testing.T) {
	fmt.Println("\nTest Decrypt: Success Case")

	var (
		attributes = []string{"teacher", "math", "hcmus"}
		policyStr  = "hcmus and (teacher and (physics or math))"
		ok         bool
		err        error
	)

	scheme := NewBSW07S(true, nil)
	pk, msk, err := scheme.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	key, keyProof, err := scheme.KeyGen(*msk, *pk, attributes)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	ok, err = scheme.VerifyKey(VerifyKeyParams{
		pk:             *pk,
		sk:             *key,
		keyProof:       *keyProof,
		userAttributes: attributes,
	})
	if err != nil {
		t.Fatalf("VerifyKey failed: %v", err)
	}

	message := []byte("Test message for VerifyCiphertext")
	accessPolicy, err := access_policy.FromString(policyStr)
	if err != nil {
		t.Errorf("Failed to parse access policy: %v", err)
	}

	ciphertext, proof, err := scheme.Encrypt(*pk, message, *accessPolicy)
	if err != nil {
		t.Errorf("Encryption failed: %v", err)
	}

	verifyParams := VerifyCiphertextParams{
		pk:           *pk,
		ciphertext:   *ciphertext,
		proof:        *proof,
		accessPolicy: *accessPolicy,
	}
	ok, err = scheme.VerifyCiphertext(verifyParams)
	if err != nil {
		t.Errorf("Failed to verify ciphertext: %v", err)
	}
	if !ok {
		t.Errorf("Ciphertext verification failed, expected success")
	} else {
		fmt.Println("Ciphertext verification succeeded")
	}

	decryptedMessage, err := scheme.Decrypt(*pk, *ciphertext, key)
	if err != nil {
		t.Errorf("Decryption failed: %v", err)
	}

	if string(decryptedMessage) != string(message) {
		fmt.Printf("Decrypted message does not match original message.\nExpected: '%s'\nGot: '%s'\n", message, decryptedMessage)
		t.Errorf("Decryption failed, expected message '%s', got '%s'", message, decryptedMessage)
	} else {
		fmt.Println("Decryption succeeded, message matches")
	}
}

func TestDecryptFailedCase(t *testing.T) {
	fmt.Println("\nTest Decrypt: Failed Case")

	var (
		attributes = []string{"teacher", "math"}
		policyStr  = "hcmus and (teacher and (physics or math))"
		ok         bool
		err        error
	)

	scheme := NewBSW07S(true, nil)
	pk, msk, err := scheme.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	key, keyProof, err := scheme.KeyGen(*msk, *pk, attributes)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	ok, err = scheme.VerifyKey(VerifyKeyParams{
		pk:             *pk,
		sk:             *key,
		keyProof:       *keyProof,
		userAttributes: attributes,
	})
	if err != nil {
		t.Fatalf("VerifyKey failed: %v", err)
	}

	message := []byte("Test message for VerifyCiphertext")
	accessPolicy, err := access_policy.FromString(policyStr)
	if err != nil {
		t.Errorf("Failed to parse access policy: %v", err)
	}

	ciphertext, proof, err := scheme.Encrypt(*pk, message, *accessPolicy)
	if err != nil {
		t.Errorf("Encryption failed: %v", err)
	}

	verifyParams := VerifyCiphertextParams{
		pk:           *pk,
		ciphertext:   *ciphertext,
		proof:        *proof,
		accessPolicy: *accessPolicy,
	}
	ok, err = scheme.VerifyCiphertext(verifyParams)
	if err != nil {
		t.Errorf("Failed to verify ciphertext: %v", err)
	}
	if !ok {
		t.Errorf("Ciphertext verification failed, expected success")
	} else {
		fmt.Println("Ciphertext verification succeeded")
	}

	_, err = scheme.Decrypt(*pk, *ciphertext, key)
	if err == nil {
		fmt.Printf("Expected FAILED decryption, but succeeded.\n")
		t.Errorf("Decryption succeeded, expected failure")
	}
}

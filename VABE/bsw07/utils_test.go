package bsw07

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
	"testing"
)

func TestLagrangeCoeff_OnePositions(t *testing.T) {
	// Test case: one position
	positions := []*big.Int{big.NewInt(2)}
	targetPos := big.NewInt(2)

	result := computeLagrangeCoeff(positions, targetPos, bn256.Order)

	fmt.Printf("\nTest 1 - One position:\n")
	fmt.Printf("  Positions: %v\n", positions)
	fmt.Printf("  Target: %d\n", targetPos)
	fmt.Printf("  Result: %s\n", result.String())

	expected := big.NewInt(1)
	if result.Cmp(expected) != 0 {
		t.Errorf("Expected 1, got %s", result.String())
	} else {
		fmt.Printf("  ✓ PASS: Result = 1\n")
	}
}

func TestLagrangeCoeff_MultiplePositions(t *testing.T) {
	// Test case: positions có nhiều giá trị
	positions := []int{1, 2, 3}
	positionsBig := make([]*big.Int, len(positions))
	for i, pos := range positions {
		positionsBig[i] = big.NewInt(int64(pos))
	}
	targetPos := big.NewInt(1)

	result := computeLagrangeCoeff(positionsBig, targetPos, bn256.Order)

	fmt.Printf("\nTest 2 - Multiple positions:\n")
	fmt.Printf("  Positions: %v\n", positions)
	fmt.Printf("  Target: %d\n", targetPos)
	fmt.Printf("  Result: %s\n", result.String())

	// Tính tay: Δ_1(0) = (0-2)(0-3) / (1-2)(1-3) = (-2)(-3) / (-1)(-2) = 6/2 = 3
	expected := big.NewInt(3)
	if result.Cmp(expected) != 0 {
		t.Errorf("Expected 3, got %s", result.String())
	} else {
		fmt.Printf("  ✓ PASS: Result = 3\n")
	}
}

func TestAESEncryptionDecryption(t *testing.T) {
	// Test data
	plaintext := []byte("This is a test message to encrypt and decrypt")

	// Generate a random key (or use a fixed key for testing)
	key := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	fmt.Printf("Size of key: %d bytes\n", len(key))

	// Encrypt the plaintext
	ciphertext, err := EncryptAES(key, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt the ciphertext
	decrypted, err := DecryptAES(key, ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Compare the original plaintext with the decrypted text
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption result doesn't match original plaintext")
		t.Errorf("Original: %s", plaintext)
		t.Errorf("Decrypted: %s", decrypted)
	} else {
		t.Logf("Encryption and decryption successful")
	}

	// Test with incorrect key
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	_, err = DecryptAES(ciphertext, wrongKey)
	if err == nil {
		t.Errorf("Decryption with wrong key should fail but didn't")
	}
}

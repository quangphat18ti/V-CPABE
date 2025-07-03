package main

import (
	"fmt"
	"github.com/cloudflare/bn256"
)

// Demo function
func main() {
	fmt.Println("=== Fully Verifiable CP-ABE Demo ===")

	scheme := NewCPABEScheme()

	// Setup
	fmt.Println("1. Running Setup...")
	pk, msk, err := scheme.Setup(256)
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ Setup completed")

	// Key Generation
	fmt.Println("2. Generating private key for user with attributes [attr1, attr2]...")
	userAttributes := []string{"attr1", "attr2"}
	sk, err := scheme.KeyGen(msk, pk, userAttributes)
	if err != nil {
		panic(err)
	}

	fmt.Println("✓ Private key generated")

	// Key Verification
	fmt.Println("3. Verifying private key...")
	if scheme.VerifyKey(pk, sk) {
		fmt.Println("✓ Private key verification passed")
	} else {
		fmt.Println("✗ Private key verification failed")
	}

	// Encryption
	fmt.Println("4. Encrypting message with access policy 'attr1 AND attr2'...")
	message := bn256.Pair(pk.G1Generator, pk.G2Generator) // Sample message in GT
	accessPolicy := "attr1 AND attr2"
	ct, vp, err := scheme.Encrypt(pk, message, accessPolicy)
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ Message encrypted")

	// Ciphertext Verification
	fmt.Println("5. Verifying ciphertext...")
	if scheme.VerifyCiphertext(pk, ct, vp) {
		fmt.Println("✓ Ciphertext verification passed")
	} else {
		fmt.Println("✗ Ciphertext verification failed")
	}

	// Decryption
	fmt.Println("6. Decrypting message...")
	decryptedMsg, err := scheme.Decrypt(pk, ct, sk)
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ Message decrypted successfully")

	// Simple verification that decrypted message matches original
	fmt.Printf("Original message == Decrypted message: %v\n", message.String() == decryptedMsg.String())

	fmt.Println("\n=== Demo completed successfully! ===")
}

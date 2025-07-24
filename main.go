package main

import (
	"cpabe-prototype/VABE"
	"cpabe-prototype/VABE/bsw07"
	"fmt"
	"os"
	"time"
)

var (
	cpabe = bsw07.NewBSW07Demo(false)
)

// Demo function
func main() {
	if len(os.Args) < 2 {
		fmt.Println("======= Help =======")
		fmt.Println("Usage: go run main.go <operation>")
		fmt.Println("Available operations: setup, keygen, encrypt, decrypt, verify_key, verify_ciphertext, full_flow")
		fmt.Println("====================")
		return
	}

	switch operation := os.Args[1]; operation {
	case "setup":
		_, err := cpabe.Setup(VABE.SetupParams{})
		if err != nil {
			fmt.Println("Setup Error:", err)
			return
		}
		fmt.Println("Setup completed successfully.")
	case "keygen":
		_, err := cpabe.KeyGen(VABE.KeyGenParams{})
		if err != nil {
			fmt.Println("Key Generation Error:", err)
			return
		}
		fmt.Println("Key generation completed successfully.")
	case "encrypt":
		_, err := cpabe.Encrypt(VABE.EncryptParams{})
		if err != nil {
			fmt.Println("Encryption Error:", err)
			return
		}
		fmt.Println("Encryption completed successfully.")
	case "decrypt":
		_, err := cpabe.Decrypt(VABE.DecryptParams{})
		if err != nil {
			fmt.Println("Decryption Error:", err)
			return
		}
		fmt.Println("Decryption completed successfully.")
	case "verify_key":
		ok := cpabe.VerifyKey(VABE.VerifyKeyParams{})
		if !ok {
			fmt.Println("Key verification failed.")
			return
		}
		fmt.Println("Key verification succeeded.")
	case "verify_ciphertext":
		ok := cpabe.VerifyCiphertext(VABE.VerifyCiphertextParams{})
		if !ok {
			fmt.Println("Ciphertext verification failed.")
			return
		}
		fmt.Println("Ciphertext verification succeeded.")
	case "full_flow":
		start := time.Now()
		defer func() {
			fmt.Printf("Encrypt time: %v\n", time.Since(start))
		}()
		// Full flow: setup, keygen, encrypt, decrypt
		_, err := cpabe.Setup(VABE.SetupParams{})
		if err != nil {
			fmt.Println("Setup Error:", err)
			return
		}
		fmt.Println("Setup completed successfully.")
		fmt.Println()

		_, err = cpabe.KeyGen(VABE.KeyGenParams{})
		if err != nil {
			fmt.Println("Key Generation Error:", err)
			return
		}
		fmt.Println("Key generation completed successfully.")
		fmt.Println()

		ok := cpabe.VerifyKey(VABE.VerifyKeyParams{})
		if !ok {
			fmt.Println("Key verification failed.")
			return
		}
		fmt.Println("Key verification succeeded.")
		fmt.Println()

		_, err = cpabe.Encrypt(VABE.EncryptParams{})
		if err != nil {
			fmt.Println("Encryption Error:", err)
			return
		}
		fmt.Println("Encryption completed successfully.")
		fmt.Println()

		ok = cpabe.VerifyCiphertext(VABE.VerifyCiphertextParams{})
		if !ok {
			fmt.Println("Ciphertext verification failed.")
			return
		}
		fmt.Println("Ciphertext verification succeeded.")
		fmt.Println()

		_, err = cpabe.Decrypt(VABE.DecryptParams{})
		if err != nil {
			fmt.Println("Decryption Error:", err)
			return
		}
		fmt.Println("Decryption completed successfully.")
		fmt.Println()

		fmt.Println("Full flow completed successfully.")
	default:
		fmt.Println("Unknown operation:", operation)
	}
}

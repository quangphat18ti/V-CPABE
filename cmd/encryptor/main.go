package main

import (
	access_policy "cpabe-prototype/VABE/access-policy"
	"cpabe-prototype/VABE/waters11"
	"cpabe-prototype/VABE/waters11/models"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mcuadros/go-defaults"
)

var (
	scheme *waters11.Waters11
	err    error
)

type EncryptParams struct {
	SchemePath    string `default:"in/schemes/bsw07_scheme.json"`
	PublicKeyPath string `default:"out/utils/public_key"`

	AccessPolicyPath    string `default:"in/utils/access_policy"`
	InputFilePath       string `default:"in/files/input_file.txt"`
	CipherTextPath      string `default:"out/ciphertexts/ciphertext"`
	CipherTextProofPath string `default:"out/ciphertexts/ciphertext_proof"`

	Verbose bool `default:"false"`
}

func parseArgs() EncryptParams {
	var params EncryptParams

	// Define command line flags
	schemePath := flag.String("scheme-path", "in/schemes/bsw07_scheme.json", "Path to the scheme file")
	publicKeyPath := flag.String("public-key-path", "out/utils/public_key", "Path to the public key")

	accessPolicyPath := flag.String("access-policy-path", "in/utils/access_policy", "Path to the access policy file")
	inputFilePath := flag.String("input-file-path", "in/files/input_file.txt", "Path to the input file to encrypt")
	ciphertextPath := flag.String("ciphertext-path", "out/ciphertexts/ciphertext", "Path to save the ciphertext")
	ciphertextProofPath := flag.String("ciphertext-proof-path", "out/ciphertexts/ciphertext_proof", "Path to save the ciphertext proof")

	verbose := flag.Bool("verbose", false, "Enable verbose output")
	help := flag.Bool("help", false, "Show help message")

	// Parse command line arguments
	flag.Parse()

	// Show help if requested
	if *help {
		fmt.Println("BSW07 Encryption Tool")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Set parameters
	params.SchemePath = *schemePath
	params.PublicKeyPath = *publicKeyPath
	params.AccessPolicyPath = *accessPolicyPath
	params.InputFilePath = *inputFilePath
	params.CipherTextPath = *ciphertextPath
	params.CipherTextProofPath = *ciphertextProofPath
	params.Verbose = *verbose

	defaults.SetDefaults(&params)
	return params
}

func encryptFile(params EncryptParams) error {
	if params.Verbose {
		fmt.Printf("Encrypting file with parameters:\n")
		fmt.Printf("  Scheme Path: %s\n", params.SchemePath)
		fmt.Printf("  Public Key Path: %s\n", params.PublicKeyPath)
		fmt.Printf("  Access Policy Path: %s\n", params.AccessPolicyPath)
		fmt.Printf("  Input File Path: %s\n", params.InputFilePath)
		fmt.Printf("  Ciphertext Path: %s\n", params.CipherTextPath)
		fmt.Printf("  Ciphertext Proof Path: %s\n", params.CipherTextProofPath)
		fmt.Println()
	}

	// Ensure output directories exist
	err := ensureDir(params.CipherTextPath)
	if err != nil {
		return fmt.Errorf("failed to create directory for ciphertext: %v", err)
	}

	err = ensureDir(params.CipherTextProofPath)
	if err != nil {
		return fmt.Errorf("failed to create directory for ciphertext proof: %v", err)
	}

	// Load the public key
	publicKey, err := models.LoadPublicKey(params.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load public key: %v", err)
	}

	// Load access policy
	accessPolicy, err := models.LoadAccessPolicy(params.AccessPolicyPath)
	if err != nil {
		return fmt.Errorf("failed to load access policy: %v", err)
	}

	if params.Verbose {
		fmt.Printf("Access policy loaded\n")
		access_policy.PrettyPrint(*accessPolicy)
	}

	// Read input file
	plaintext, err := os.ReadFile(params.InputFilePath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	if params.Verbose {
		fmt.Printf("Input file read, size: %d bytes\n", len(plaintext))
	}

	// Encrypt the file
	ciphertext, proof, err := scheme.Encrypt(*publicKey, plaintext, *accessPolicy)
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	// Save ciphertext
	err = models.SaveCiphertext(params.CipherTextPath, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to save ciphertext: %v", err)
	}

	// Save ciphertext proof
	err = models.SaveCiphertextProof(params.CipherTextProofPath, proof)
	if err != nil {
		return fmt.Errorf("failed to save ciphertext proof: %v", err)
	}

	if params.Verbose {
		fmt.Println("Ciphertext saved to:", params.CipherTextPath)
		fmt.Println("Ciphertext proof saved to:", params.CipherTextProofPath)
	}

	fmt.Println("File encryption completed successfully")
	return nil
}

func main() {
	params := parseArgs()

	// Load the scheme
	scheme, err = waters11.LoadScheme(params.SchemePath)
	scheme.Verbose = params.Verbose
	if err != nil {
		fmt.Printf("Failed to load scheme: %v\n", err)
		os.Exit(1)
	}

	err = encryptFile(params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func ensureDir(filePath string) error {
	dir := filepath.Dir(filePath)
	return os.MkdirAll(dir, 0755)
}

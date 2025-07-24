package main

import (
	access_policy "cpabe-prototype/VABE/access-policy"
	"cpabe-prototype/VABE/waters11"
	"cpabe-prototype/VABE/waters11/models"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mcuadros/go-defaults"
)

var (
	scheme *waters11.Waters11
	err    error
)

type DecryptParams struct {
	SchemePath    string `default:"in/schemes/bsw07_scheme.json"`
	PublicKeyPath string `default:"out/utils/public_key"`

	UserPrivateKeyPath  string `default:"out/keys/private_key"`
	PrivateKeyProofPath string `default:"out/keys/key_proof"`
	AttributePath       string `default:"in/utils/attributes"`

	AccessPolicyPath    string `default:"in/utils/access_policy"`
	CipherTextPath      string `default:"out/ciphertexts/ciphertext"`
	CipherTextProofPath string `default:"out/ciphertexts/ciphertext_proof"`
	OutputPath          string `default:"out/files/decrypted_file.txt"`

	Mode    string `default:"decrypt"` // Options: decrypt, verify-key, verify-ciphertext
	Verbose bool   `default:"false"`
}

func parseArgs() DecryptParams {
	var params DecryptParams

	// Define command line flags
	schemePath := flag.String("scheme-path", "in/schemes/bsw07_scheme.json", "Path to the scheme file")
	publicKeyPath := flag.String("public-key-path", "out/utils/public_key", "Path to the public key")

	privateKeyPath := flag.String("private-key-path", "out/keys/private_key", "Path to the user's private key")
	privateKeyProofPath := flag.String("private-key-proof-path", "out/keys/key_proof", "Path to the private key proof")
	attributePath := flag.String("attribute-path", "in/utils/attributes", "Path to the attributes file")

	accessPolicyPath := flag.String("access-policy-path", "in/utils/access_policy", "Path to the access policy file")
	ciphertextPath := flag.String("ciphertext-path", "out/ciphertexts/ciphertext", "Path to the ciphertext")
	ciphertextProofPath := flag.String("ciphertext-proof-path", "out/ciphertexts/ciphertext_proof", "Path to the ciphertext proof")
	outputPath := flag.String("output-path", "out/files/decrypted_file.txt", "Path to save the decrypted file")

	mode := flag.String("mode", "decrypt", "Operation mode: decrypt, verify-key, or verify-ciphertext")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	help := flag.Bool("help", false, "Show help message")

	// Parse command line arguments
	flag.Parse()

	// Show help if requested
	if *help {
		fmt.Println("BSW07 Decryption Tool")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Set parameters
	params.SchemePath = *schemePath
	params.PublicKeyPath = *publicKeyPath
	params.UserPrivateKeyPath = *privateKeyPath
	params.PrivateKeyProofPath = *privateKeyProofPath
	params.AccessPolicyPath = *accessPolicyPath
	params.AttributePath = *attributePath
	params.CipherTextPath = *ciphertextPath
	params.CipherTextProofPath = *ciphertextProofPath
	params.OutputPath = *outputPath
	params.Mode = *mode
	params.Verbose = *verbose

	defaults.SetDefaults(&params)
	return params
}

func Decrypt(params DecryptParams) ([]byte, error) {
	if params.Verbose {
		fmt.Printf("Decrypting file with parameters:\n")
		fmt.Printf("  Scheme Path: %s\n", params.SchemePath)
		fmt.Printf("  Public Key Path: %s\n", params.PublicKeyPath)
		fmt.Printf("  Private Key Path: %s\n", params.UserPrivateKeyPath)
		fmt.Printf("  Attribute Path: %s\n", params.AttributePath)
		fmt.Printf("  Ciphertext Path: %s\n", params.CipherTextPath)
		fmt.Printf("  Output Path: %s\n", params.OutputPath)
		fmt.Println()
	}

	// Load the public key
	publicKey, err := models.LoadPublicKey(params.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key: %v", err)
	}

	// Load the user's private key
	privateKey, err := models.LoadSecretKey(params.UserPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %v", err)
	}

	// Load the ciphertext
	ciphertext, err := models.LoadCiphertext(params.CipherTextPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ciphertext: %v", err)
	}

	// Load attributes
	attributes, err := models.LoadAttributes(params.AttributePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load attributes: %v", err)
	}

	if params.Verbose {
		fmt.Printf("Loaded %d attributes\n", len(attributes))
		for i, attr := range attributes {
			fmt.Printf("  Attribute %d: %s\n", i, attr)
		}
	}

	// Decrypt the ciphertext
	decrypted, err := scheme.Decrypt(*publicKey, *ciphertext, privateKey)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	return decrypted, nil
}

func VerifyKey(params DecryptParams) (bool, error) {
	if params.Verbose {
		fmt.Printf("Verifying key with parameters:\n")
		fmt.Printf("  Scheme Path: %s\n", params.SchemePath)
		fmt.Printf("  Public Key Path: %s\n", params.PublicKeyPath)
		fmt.Printf("  Private Key Path: %s\n", params.UserPrivateKeyPath)
		fmt.Printf("  Private Key Proof Path: %s\n", params.PrivateKeyProofPath)
		fmt.Printf("  Attribute Path: %s\n", params.AttributePath)
		fmt.Println()
	}

	// Load the public key
	publicKey, err := models.LoadPublicKey(params.PublicKeyPath)
	if err != nil {
		return false, fmt.Errorf("failed to load public key: %v", err)
	}

	// Load the user's private key
	privateKey, err := models.LoadSecretKey(params.UserPrivateKeyPath)
	if err != nil {
		return false, fmt.Errorf("failed to load private key: %v", err)
	}

	// Load the key proof
	keyProof, err := models.LoadSecretKeyProof(params.PrivateKeyProofPath)
	if err != nil {
		return false, fmt.Errorf("failed to load key proof: %v", err)
	}

	// Load attributes
	attributes, err := models.LoadAttributes(params.AttributePath)
	if err != nil {
		return false, fmt.Errorf("failed to load attributes: %v", err)
	}

	// Verify the key
	isVerified, err := scheme.VerifyKey(waters11.VerifyKeyParams{
		PublicKey:      *publicKey,
		SecretKey:      *privateKey,
		KeyProof:       *keyProof,
		UserAttributes: attributes,
	})
	return isVerified, nil
}

func VerifyCiphertext(params DecryptParams) (bool, error) {
	if params.Verbose {
		fmt.Printf("Verifying ciphertext with parameters:\n")
		fmt.Printf("  Scheme Path: %s\n", params.SchemePath)
		fmt.Printf("  Public Key Path: %s\n", params.PublicKeyPath)
		fmt.Printf("  Ciphertext Path: %s\n", params.CipherTextPath)
		fmt.Printf("  Ciphertext Proof Path: %s\n", params.CipherTextProofPath)
		fmt.Printf("  Access Policy Path: %s\n", params.AccessPolicyPath)
		fmt.Println()
	}

	// Load the public key
	publicKey, err := models.LoadPublicKey(params.PublicKeyPath)
	if err != nil {
		return false, fmt.Errorf("failed to load public key: %v", err)
	}

	// Load the ciphertext
	ciphertext, err := models.LoadCiphertext(params.CipherTextPath)
	if err != nil {
		return false, fmt.Errorf("failed to load ciphertext: %v", err)
	}

	// Load the ciphertext proof
	ciphertextProof, err := models.LoadCiphertextProof(params.CipherTextProofPath)
	if err != nil {
		return false, fmt.Errorf("failed to load ciphertext proof: %v", err)
	}

	// Load access policy
	accessPolicy, err := models.LoadAccessPolicy(params.AccessPolicyPath)
	if err != nil {
		return false, fmt.Errorf("failed to load access policy: %v", err)
	}

	if params.Verbose {
		fmt.Printf("Access policy loaded\n")
		access_policy.PrettyPrint(*accessPolicy)
	}

	// Verify the ciphertext
	isVerified, err := scheme.VerifyCiphertext(waters11.VerifyCiphertextParams{
		PublicKey:    *publicKey,
		Ciphertext:   *ciphertext,
		Proof:        *ciphertextProof,
		AccessPolicy: *accessPolicy,
	})

	if err != nil {
		return false, fmt.Errorf("ciphertext verification failed: %v", err)
	}
	return isVerified, nil
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

	switch params.Mode {
	case "decrypt":
		// Ensure output directory exists
		err := ensureDir(params.OutputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to create output directory: %v\n", err)
			os.Exit(1)
		}

		decrypted, err := Decrypt(params)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Save the decrypted content
		err = ioutil.WriteFile(params.OutputPath, decrypted, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to save decrypted file: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("File successfully decrypted and saved to %s\n", params.OutputPath)

	case "verify-key":
		isVerified, err := VerifyKey(params)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during key verification: %v\n", err)
			os.Exit(1)
		}

		if isVerified {
			fmt.Println("Key verification successful ✓")
		} else {
			fmt.Println("Key verification failed ✗")
			os.Exit(1)
		}

	case "verify-ciphertext":
		isVerified, err := VerifyCiphertext(params)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during ciphertext verification: %v\n", err)
			os.Exit(1)
		}

		if isVerified {
			fmt.Println("Ciphertext verification successful ✓")
		} else {
			fmt.Println("Ciphertext verification failed ✗")
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown mode '%s'. Valid modes are: decrypt, verify-key, verify-ciphertext\n", params.Mode)
		os.Exit(1)
	}
}

func ensureDir(filePath string) error {
	dir := filepath.Dir(filePath)
	return os.MkdirAll(dir, 0755)
}

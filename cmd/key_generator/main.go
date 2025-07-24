package main

import (
	"cpabe-prototype/VABE/waters11"
	"cpabe-prototype/VABE/waters11/models"
	"cpabe-prototype/pkg/utilities"
	"flag"
	"fmt"
	"os"

	"github.com/mcuadros/go-defaults"
)

var (
	scheme *waters11.Waters11
	err    error
)

var ensureDir = utilities.EnsureDir

type KeyGenParams struct {
	SchemePath          string `default:"in/schemes/bsw07_scheme.json"`
	PublicKeyPath       string `default:"out/utils/public_key"`
	MasterSecretKeyPath string `default:"out/utils/master_secret_key"`

	AttributePath       string `default:"in/utils/attributes"`
	UserPrivateKeyPath  string `default:"out/keys/private_key"`
	PrivateKeyProofPath string `default:"out/keys/key_proof"`
	Verbose             bool   `default:"false"`
}

func parseArgs() KeyGenParams {
	var params KeyGenParams

	// Define command line flags
	schemePath := flag.String("scheme-path", "in/schemes/bsw07_scheme.json", "Path to save/load the scheme file")
	publicKeyPath := flag.String("public-key-path", "out/utils/public_key", "Path to save the public key")
	masterSecretKeyPath := flag.String("master-secret-key-path", "out/utils/master_secret_key", "Path to save the master secret key")

	attributePath := flag.String("attribute-path", "in/utils/attributes", "Path to save the attributes")
	privateKeyPath := flag.String("private-key-path", "out/keys/private_key", "Path to save the user's private key")
	privateKeyProofPath := flag.String("private-key-proof-path", "out/keys/key_proof", "Path to save the private key proof")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	help := flag.Bool("help", false, "Show help message")

	// Parse command line arguments
	flag.Parse()

	// Show help if requested
	if *help {
		fmt.Println("BSW07 Key Generation Tool")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Set parameters
	params.SchemePath = *schemePath
	params.PublicKeyPath = *publicKeyPath
	params.MasterSecretKeyPath = *masterSecretKeyPath
	params.AttributePath = *attributePath
	params.UserPrivateKeyPath = *privateKeyPath
	params.PrivateKeyProofPath = *privateKeyProofPath
	params.Verbose = *verbose
	defaults.SetDefaults(&params)

	return params
}

func generateKey(params KeyGenParams) error {
	if params.Verbose {
		fmt.Printf("Generating keys with parameters:\n")
		fmt.Printf("  Scheme Path: %s\n", params.SchemePath)
		fmt.Printf("  Public Key Path: %s\n", params.PublicKeyPath)
		fmt.Printf("  Master Secret Key Path: %s\n", params.MasterSecretKeyPath)
		fmt.Printf("  Attribute Path: %s\n", params.AttributePath)
		fmt.Printf("  User Private Key Path: %s\n", params.UserPrivateKeyPath)
		fmt.Printf("  Private Key Proof Path: %s\n", params.PrivateKeyProofPath)
		fmt.Println()
	}

	// Ensure directories exist
	err := ensureDir(params.UserPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create directory for user private key: %v", err)
	}

	err = ensureDir(params.PrivateKeyProofPath)
	if err != nil {
		return fmt.Errorf("failed to create directory for private key proof: %v", err)
	}

	// Load the public key
	publicKey, err := models.LoadPublicKey(params.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load public key: %v", err)
	}

	// Load the master secret key
	masterSecretKey, err := models.LoadMasterSecretKey(params.MasterSecretKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load master secret key: %v", err)
	}

	// Load attributes from file
	attributes, err := models.LoadAttributes(params.AttributePath)
	if err != nil {
		return fmt.Errorf("failed to load attributes: %v", err)
	}

	if params.Verbose {
		fmt.Printf("Loaded %d attributes\n", len(attributes))
		for i, attr := range attributes {
			fmt.Printf("  Attribute %d: %s\n", i, attr)
		}
	}

	privateKey, proof, err := scheme.KeyGen(*masterSecretKey, *publicKey, attributes)
	if err != nil {
		return fmt.Errorf("key generation failed: %v", err)
	}

	err = models.SaveSecretKey(params.UserPrivateKeyPath, privateKey)
	if err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}

	err = models.SaveSecretKeyProof(params.PrivateKeyProofPath, proof)
	if err != nil {
		return fmt.Errorf("failed to save key proof: %v", err)
	}

	if params.Verbose {
		fmt.Println("Private key saved to:", params.UserPrivateKeyPath)
		fmt.Println("Key proof saved to:", params.PrivateKeyProofPath)
	}

	fmt.Println("Key generation completed successfully")
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

	err = generateKey(params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

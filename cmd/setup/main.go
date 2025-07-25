package main

import (
	"bytes"
	"cpabe-prototype/VABE/bsw07"
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

type SchemeSetupParams struct {
	SchemePath string `default:"in/schemes/scheme.json"`
	Salt       []byte `default:"default_salt"`
	Verbose    bool   `default:"false"`

	PublicKeyPath       string `default:"out/utils/public_key"`
	MasterSecretKeyPath string `default:"out/utils/master_secret_key"`
}

func parseArgs() SchemeSetupParams {
	var params SchemeSetupParams

	schemePath := flag.String("scheme-path", "in/schemes/scheme.json", "Path to save/load the scheme file")
	saltStr := flag.String("salt", "default_salt", "Salt value for hashing")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	publicKeyPath := flag.String("public-key-path", "out/utils/public_key", "Path to save the public key")
	masterSecretKeyPath := flag.String("master-secret-key-path", "out/utils/master_secret_key", "Path to save the master secret key")
	help := flag.Bool("help", false, "Show help message")

	flag.Parse()

	if *help {
		fmt.Println("BSW07 Scheme Setup Tool")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	params.SchemePath = *schemePath
	params.Salt = []byte(*saltStr)
	params.Verbose = *verbose
	params.PublicKeyPath = *publicKeyPath
	params.MasterSecretKeyPath = *masterSecretKeyPath

	defaults.SetDefaults(&params)
	return params
}

func createScheme(params SchemeSetupParams) error {
	if params.Verbose {
		fmt.Printf("Create BSW07 scheme with parameters:\n")
		fmt.Printf("  Scheme Path: %s\n", params.SchemePath)
		fmt.Printf("  Salt: %s\n", string(params.Salt))
		fmt.Printf("  Verbose: %v\n", params.Verbose)
		fmt.Println()
	}

	scheme = waters11.NewWaters11(params.Verbose, params.Salt)

	if params.Verbose {
		fmt.Printf("Created new BSW07 scheme\n")
	}

	err := ensureDir(params.SchemePath)
	if err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	err = waters11.SaveScheme(params.SchemePath, scheme)
	if err != nil {
		return fmt.Errorf("failed to save scheme: %v", err)
	}

	if params.Verbose {
		fmt.Printf("Scheme saved to: %s\n", params.SchemePath)
	}

	loadedScheme, err := bsw07.LoadScheme(params.SchemePath)
	if err != nil {
		return fmt.Errorf("failed to load scheme: %v", err)
	}

	if params.Verbose {
		fmt.Printf("Scheme loaded from: %s\n", params.SchemePath)
		fmt.Println("Verifying scheme integrity...")
	}

	if bytes.Compare(scheme.Salt, loadedScheme.Salt) != 0 {
		return fmt.Errorf("loaded scheme salt does not match original scheme salt")
	}

	if scheme.Verbose != loadedScheme.Verbose {
		return fmt.Errorf("loaded scheme verbose setting does not match original scheme verbose setting")
	}

	if params.Verbose {
		fmt.Println("✓ Salt verification passed")
		fmt.Println("✓ Verbose setting verification passed")
		fmt.Println("✓ Scheme setup completed successfully")
	} else {
		fmt.Println("Scheme setup completed successfully")
	}

	return nil
}

func setupScheme(params SchemeSetupParams) error {
	if params.Verbose {
		fmt.Printf("Setup BSW07 scheme with parameters:\n")
		fmt.Printf("  Public-key Path: %s\n", params.PublicKeyPath)
		fmt.Printf("  Master-secret-key Path: %v\n", params.MasterSecretKeyPath)
		fmt.Println()
	}

	err := ensureDir(params.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create directory for public key: %v", err)
	}

	err = ensureDir(params.MasterSecretKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create directory for master secret key: %v", err)
	}

	publicKey, masterSecretKey, err := scheme.Setup()
	if err != nil {
		return fmt.Errorf("failed to setup scheme: %v", err)
	}

	err = models.SavePublicKey(params.PublicKeyPath, publicKey)
	if err != nil {
		return fmt.Errorf("failed to save public key: %v", err)
	}

	err = models.SaveMasterSecretKey(params.MasterSecretKeyPath, masterSecretKey)
	if err != nil {
		return fmt.Errorf("failed to save master secret key: %v", err)
	}
	if params.Verbose {
		fmt.Println("Public Key saved to:", params.PublicKeyPath)
		fmt.Println("Master Secret Key saved to:", params.MasterSecretKeyPath)
	}
	fmt.Println("Scheme setup completed successfully")
	return nil
}

func main() {
	params := parseArgs()

	err = createScheme(params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	// Load the scheme
	scheme, err = waters11.LoadScheme(params.SchemePath)
	scheme.Verbose = params.Verbose
	if err != nil {
		fmt.Printf("Failed to load scheme: %v\n", err)
		os.Exit(1)
	}

	err = setupScheme(params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func ensureDir(filePath string) error {
	dir := filepath.Dir(filePath)
	return os.MkdirAll(dir, 0755)
}

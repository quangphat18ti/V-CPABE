package main

import (
	"cpabe-prototype/VABE/access-policy"
	"cpabe-prototype/VABE/bsw07/models"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	// Define command line flags
	//policyStr := flag.String("policy", "(student AND medical) OR admin", "Access policy string")
	policyPathStr := flag.String("policy_path", "in/utils/access_policy_string", "Path to the access policy file")
	outputPath := flag.String("output", "in/utils/access_policy", "Output file path")
	flag.Parse()

	// Read the policy string from the specified file
	policyByte, err := os.ReadFile(*policyPathStr)
	if err != nil || policyByte == nil {
		fmt.Printf("Error reading policy file: %v\n", err)
		os.Exit(1)
	}
	policyStr := string(policyByte)

	// Create output directory if it doesn't exist
	err = os.MkdirAll(filepath.Dir(*outputPath), 0755)
	if err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Create a new AccessPolicy instance
	var ap access_policy.AccessPolicy

	// Parse the policy string
	parsedPolicy, err := ap.FromString(policyStr)
	if err != nil {
		fmt.Printf("Error parsing policy string: %v\n", err)
		os.Exit(1)
	}

	// Print the parsed policy for debugging
	fmt.Printf("Parsed policy: %+v\n", parsedPolicy)

	// Save the policy to file
	err = models.SaveAccessPolicy(*outputPath, parsedPolicy)
	if err != nil {
		fmt.Printf("Error saving policy to file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Access policy successfully saved to %s\n", *outputPath)
}

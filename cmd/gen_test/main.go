package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
// Maximum depth of the policy tree
// maxDepth = 8
// Maximum number of attributes per level
// maxAttrsPerLevel = 5
)

// Configuration for test generation
type TestConfig struct {
	outputDir        string
	maxAttributes    int
	generateMatching bool
	generateNonMatch bool
}

// Generate a random attribute name
func generateAttribute(prefix string, i int) string {
	return fmt.Sprintf("%s_%d", prefix, i)
}

//// Generate a random policy string with the given number of attributes
//func generatePolicyString(numAttrs int) string {
//	if numAttrs <= 0 {
//		return ""
//	}
//
//	rand.Seed(time.Now().UnixNano())
//
//	attributes := make([]string, numAttrs)
//	for i := 0; i < numAttrs; i++ {
//		attributes[i] = generateAttribute("attr", i+1)
//	}
//
//	return generatePolicyExpr(attributes, 0, numAttrs, 0)
//}
//
//// Generate a policy expression recursively
//func generatePolicyExpr(attrs []string, start, end, depth int) string {
//	if end-start <= 0 {
//		return ""
//	}
//
//	if end-start == 1 || depth >= maxDepth {
//		return attrs[start]
//	}
//
//	// With some probability, just return a single attribute
//	if rand.Float32() < 0.3 && depth > 0 {
//		return attrs[start+rand.Intn(end-start)]
//	}
//
//	// Otherwise, create a composite expression
//	splitPoint := start + rand.Intn(end-start-1) + 1
//	leftExpr := generatePolicyExpr(attrs, start, splitPoint, depth+1)
//	rightExpr := generatePolicyExpr(attrs, splitPoint, end, depth+1)
//
//	// Choose operator
//	var op string
//	if rand.Float32() < 0.5 {
//		op = "and"
//	} else {
//		op = "or"
//	}
//
//	return fmt.Sprintf("(%s %s %s)", leftExpr, op, rightExpr)
//}

// Generate a random policy string with the given number of attributes
func generatePolicyString(numAttrs int) string {
	if numAttrs <= 0 {
		return ""
	}

	rand.Seed(time.Now().UnixNano())

	// Create unique attributes
	attributes := make([]string, numAttrs)
	for i := 0; i < numAttrs; i++ {
		attributes[i] = generateAttribute("attr", i+1)
	}

	// Shuffle attributes to randomize their positions in the tree
	rand.Shuffle(len(attributes), func(i, j int) {
		attributes[i], attributes[j] = attributes[j], attributes[i]
	})

	return buildBalancedPolicyTree(attributes)
}

// Build a balanced policy tree that uses all attributes
func buildBalancedPolicyTree(attributes []string) string {
	if len(attributes) == 0 {
		return ""
	}

	if len(attributes) == 1 {
		return attributes[0]
	}

	// Determine splitting point for balancing
	mid := len(attributes) / 2

	// Build left and right subtrees
	left := buildBalancedPolicyTree(attributes[:mid])
	right := buildBalancedPolicyTree(attributes[mid:])

	// Choose operator (with slightly higher probability for AND to ensure policy is restrictive)
	var op string
	if rand.Float32() < 0.6 {
		op = "and"
	} else {
		op = "or"
	}

	return fmt.Sprintf("(%s %s %s)", left, op, right)
}

// Generate attributes that match the policy
func generateMatchingAttributes(policyString string) []string {
	// Parse the policy string to extract all attributes
	attributes := extractAttributes(policyString)

	// For matching attributes, include all of them
	return attributes
}

// Generate attributes that don't match the policy
func generateNonMatchingAttributes(policyString string, maxAttrs int) []string {
	allAttrs := extractAttributes(policyString)

	// For non-matching, leave out some critical attributes
	if len(allAttrs) == 0 {
		return []string{}
	}

	// Remove at least one critical attribute
	numToRemove := 1 + rand.Intn(len(allAttrs)/2)
	for i := 0; i < numToRemove; i++ {
		idx := rand.Intn(len(allAttrs))
		allAttrs = append(allAttrs[:idx], allAttrs[idx+1:]...)
		if len(allAttrs) == 0 {
			break
		}
	}

	// Add some random attributes that weren't in the policy
	numExtra := rand.Intn(maxAttrs - len(allAttrs) + 1)
	for i := 0; i < numExtra; i++ {
		allAttrs = append(allAttrs, generateAttribute("extra", i+1))
	}

	return allAttrs
}

// Extract all attributes from a policy string
func extractAttributes(policyString string) []string {
	// Remove all parentheses and operators
	policyString = strings.ReplaceAll(policyString, "(", " ")
	policyString = strings.ReplaceAll(policyString, ")", " ")

	words := strings.Fields(policyString)
	attributes := []string{}

	for _, word := range words {
		if word != "and" && word != "or" {
			attributes = append(attributes, word)
		}
	}

	return attributes
}

// Save content to file
func saveToFile(filepath string, content string) error {
	err := os.MkdirAll(filepath[:strings.LastIndex(filepath, "/")], 0755)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, []byte(content), 0644)
}

// Generate test files for a specific size configuration
func generateTest(config TestConfig) error {
	testDir := filepath.Join(config.outputDir, fmt.Sprintf("%d", config.maxAttributes))

	// Create directory if it doesn't exist
	if err := os.MkdirAll(testDir, 0755); err != nil {
		return fmt.Errorf("failed to create test directory: %w", err)
	}

	// Generate policy string
	policyString := generatePolicyString(config.maxAttributes)
	policyPath := filepath.Join(testDir, "access_policy_string")

	// Save policy string to file
	if err := saveToFile(policyPath, policyString); err != nil {
		return fmt.Errorf("failed to save policy string: %w", err)
	}
	fmt.Printf("Generated policy string with %d attributes\n", config.maxAttributes)

	// Run create_policy to generate the access_policy file
	cmd := exec.Command("./bin/create_policy", "--policy_path", policyPath, "--output", filepath.Join(testDir, "access_policy"))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run create_policy: %w", err)
	}
	fmt.Println("Generated access_policy file")

	// Generate matching attributes
	if config.generateMatching {
		matchingAttrs := generateMatchingAttributes(policyString)
		jsonData, err := json.MarshalIndent(matchingAttrs, "", "    ")
		if err != nil {
			return fmt.Errorf("failed to marshal matching attributes to JSON: %w", err)
		}

		matchingPath := filepath.Join(testDir, "attributes_matching")
		if err := saveToFile(matchingPath, string(jsonData)); err != nil {
			return fmt.Errorf("failed to save matching attributes: %w", err)
		}
		fmt.Printf("Generated %d matching attributes as JSON\n", len(matchingAttrs))
	}

	// Generate non-matching attributes
	if config.generateNonMatch {
		nonMatchingAttrs := generateNonMatchingAttributes(policyString, config.maxAttributes)
		jsonData, err := json.MarshalIndent(nonMatchingAttrs, "", "    ")
		if err != nil {
			return fmt.Errorf("failed to marshal matching attributes to JSON: %w", err)
		}
		nonMatchingPath := filepath.Join(testDir, "attributes_non_matching")
		if err := saveToFile(nonMatchingPath, string(jsonData)); err != nil {
			return fmt.Errorf("failed to save non-matching attributes: %w", err)
		}
		fmt.Printf("Generated %d non-matching attributes\n", len(nonMatchingAttrs))
	}

	return nil
}

func main() {
	// Parse command line flags
	outputDir := flag.String("output", "in/tests", "Output directory for test files")
	match := flag.Bool("match", true, "Generate matching attributes")
	nonMatch := flag.Bool("nonmatch", true, "Generate non-matching attributes")
	flag.Parse()

	// Make sure the create_policy tool exists
	if _, err := os.Stat("/bin/create_policy"); os.IsNotExist(err) {
		fmt.Println("Building tools first...")
		cmd := exec.Command("./run.sh", "build")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("Failed to build tools: %v\n", err)
			os.Exit(1)
		}
	}

	// Sizes to generate
	sizes := []int{100, 1000, 10000, 100000, 1000000, 10000000}

	for _, size := range sizes {
		fmt.Printf("\n=== Generating test with %d attributes ===\n", size)
		config := TestConfig{
			outputDir:        *outputDir,
			maxAttributes:    size,
			generateMatching: *match,
			generateNonMatch: *nonMatch,
		}

		if err := generateTest(config); err != nil {
			fmt.Printf("Error generating test for size %d: %v\n", size, err)
		} else {
			fmt.Printf("Successfully generated test for size %d\n", size)
		}
	}

	fmt.Println("Test generation complete!")
}

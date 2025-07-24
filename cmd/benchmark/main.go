package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

type TestInfo struct {
	Sizes    []int             `json:"sizes"`
	FilePath map[string]string `json:"file_path"`
}

type BenchmarkResult struct {
	Size                 int
	KeyGenTime           time.Duration
	VerifyKeyTime        time.Duration
	EncryptTime          time.Duration
	VerifyCiphertextTime time.Duration
	DecryptMatchingTime  time.Duration
	DecryptNonMatchTime  time.Duration
	MatchingSuccess      bool
	NonMatchingSuccess   bool
}

type BenmarchParams struct {
	TestInfoPath string `default:"in/tests/test_info.json"`
}

func main() {
	// Parse command line arguments
	params := ParseArgs()

	testInfoPath := params.TestInfoPath

	// Read test info file
	testInfo, err := ReadTestInfo(testInfoPath)
	if err != nil {
		fmt.Printf("Error reading test info: %v\n", err)
		os.Exit(1)
	}

	// Prepare results slice
	results := make([]BenchmarkResult, 0, len(testInfo.Sizes))

	// Run benchmarks for each size
	testsDir := filepath.Dir(testInfoPath)
	for _, size := range testInfo.Sizes {
		fmt.Printf("=== Running benchmark for size %d ===\n", size)
		result, err := runBenchmark(size, testsDir, testInfo.FilePath)
		if err != nil {
			fmt.Printf("Error benchmarking size %d: %v\n", size, err)
			continue
		}
		results = append(results, result)

		// Save timing information to the size directory
		timingData := fmt.Sprintf(`{
	"keygen_time_ms": %.2f,
	"verify_key_time_ms": %.2f,
	"encrypt_time_ms": %.2f,
	"verify_ciphertext_time_ms": %.2f,
	"decrypt_matching_time_ms": %.2f,
	"decrypt_non_matching_time_ms": %.2f,
	"matching_success": %v,
	"non_matching_success": %v
}`,
			float64(result.KeyGenTime.Microseconds())/1000.0,
			float64(result.VerifyKeyTime.Microseconds())/1000.0,
			float64(result.EncryptTime.Microseconds())/1000.0,
			float64(result.VerifyCiphertextTime.Microseconds())/1000.0,
			float64(result.DecryptMatchingTime.Microseconds())/1000.0,
			float64(result.DecryptNonMatchTime.Microseconds())/1000.0,
			result.MatchingSuccess,
			result.NonMatchingSuccess)

		timingPath := filepath.Join(testsDir, strconv.Itoa(size), "benchmark_results.json")
		if err := os.WriteFile(timingPath, []byte(timingData), 0644); err != nil {
			fmt.Printf("Error writing timing data for size %d: %v\n", size, err)
		}
	}

	// Generate CSV report
	if err := generateCSVReport(results, filepath.Join(testsDir, "benchmark_results.csv")); err != nil {
		fmt.Printf("Error generating CSV report: %v\n", err)
	}

	fmt.Println("Benchmarking complete!")
}

func runBenchmark(size int, testsDir string, filePaths map[string]string) (BenchmarkResult, error) {
	result := BenchmarkResult{Size: size}
	benchmarkFilePath := filepath.Join(testsDir, strconv.Itoa(size), "benchmark_results.json")
	existingResult, err := LoadBenchmarkParamsFromFile(benchmarkFilePath, size)
	if err == nil {
		fmt.Printf("Using existing benchmark results for size %d\n", size)
		return *existingResult, nil
	} else {
		fmt.Printf("No existing benchmark results for size %d, running new benchmark...\n", size)
	}

	sizeDir := filepath.Join(testsDir, strconv.Itoa(size))

	// Check if directory exists
	if _, err := os.Stat(sizeDir); os.IsNotExist(err) {
		return result, fmt.Errorf("test directory for size %d does not exist", size)
	}

	// Read attributes for key generation
	attrMatchingPath := filepath.Join(sizeDir, filePaths["attribute_matching"])
	matchingAttrs, err := readAttributes(attrMatchingPath)
	if err != nil {
		return result, fmt.Errorf("failed to read matching attributes: %w", err)
	}

	attrNonMatchingPath := filepath.Join(sizeDir, filePaths["attribute_non_matching"])
	nonMatchingAttrs, err := readAttributes(attrNonMatchingPath)
	if err != nil {
		return result, fmt.Errorf("failed to read non-matching attributes: %w", err)
	}

	policyPath := filepath.Join(sizeDir, filePaths["access_policy"])

	// Create temporary file for attributes
	tempAttrPath := filepath.Join(sizeDir, "temp_attributes.json")

	// Setup paths
	inputFile := "in/files/input_file.txt"
	secretKeyPath := filepath.Join(sizeDir, "secret_key")
	secretKeyProofPath := filepath.Join(sizeDir, "secret_key_proof")
	ciphertextPath := filepath.Join(sizeDir, "ciphertext")
	ciphertextProofPath := filepath.Join(sizeDir, "ciphertext_proof")
	outputPath := filepath.Join(sizeDir, "decrypted_output")

	// Benchmark KeyGen with matching attributes
	if err := os.WriteFile(tempAttrPath, []byte(matchingAttrs), 0644); err != nil {
		return result, fmt.Errorf("failed to write temporary attributes: %w", err)
	}

	fmt.Println("Running KeyGen...")
	start := time.Now()
	cmd := exec.Command("./bin/key_generator",
		"--attribute-path", tempAttrPath,
		"--private-key-path", secretKeyPath,
		"--private-key-proof-path", secretKeyProofPath,
	)
	err = cmd.Run()
	result.KeyGenTime = time.Since(start)
	if err != nil {
		return result, fmt.Errorf("key generation failed: %w", err)
	}

	// Benchmark VerifyKey
	fmt.Println("Running VerifyKey...")
	start = time.Now()
	cmd = exec.Command("./bin/decryptor",
		"--mode", "verify-key",
		"--private-key-path", secretKeyPath,
		"--private-key-proof-path", secretKeyProofPath,
		"--attribute-path", tempAttrPath,
	)
	err = cmd.Run()
	result.VerifyKeyTime = time.Since(start)
	if err != nil {
		return result, fmt.Errorf("key verification failed: %w", err)
	}

	// Benchmark Encrypt
	fmt.Println("Running Encrypt...")
	start = time.Now()
	cmd = exec.Command("./bin/encryptor",
		"--access-policy-path", policyPath,
		"--ciphertext-path", ciphertextPath,
		"--ciphertext-proof-path", ciphertextProofPath,
	)
	err = cmd.Run()
	result.EncryptTime = time.Since(start)
	if err != nil {
		return result, fmt.Errorf("encryption failed: %w", err)
	}

	// Benchmark VerifyCiphertext
	fmt.Println("Running VerifyCiphertext...")
	start = time.Now()
	cmd = exec.Command("./bin/decryptor",
		"--mode", "verify-ciphertext",
		"--ciphertext-path", ciphertextPath,
		"--ciphertext-proof-path", ciphertextProofPath,
		"--access-policy-path", policyPath,
	)
	err = cmd.Run()
	result.VerifyCiphertextTime = time.Since(start)
	if err != nil {
		return result, fmt.Errorf("ciphertext verification failed: %w", err)
	}

	// Benchmark Decrypt with matching attributes
	fmt.Println("Running Decrypt with matching attributes...")
	start = time.Now()
	cmd = exec.Command("./bin/decryptor",
		"--verbose",
		"--mode", "decrypt",
		"--private-key-path", secretKeyPath,
		"--ciphertext-path", ciphertextPath,
		"--attribute-path", tempAttrPath,
		"--output-path", outputPath,
	)
	err = cmd.Run()
	result.DecryptMatchingTime = time.Since(start)
	result.MatchingSuccess = err == nil

	if !result.MatchingSuccess {
		fmt.Printf("ERROR: Matching attributes failed to decrypt: %v\n", err)
		return result, nil // Continue with non-matching test
	}

	// Verify decryption was successful by comparing with input file
	originalContent, err := os.ReadFile(inputFile)
	if err != nil {
		return result, fmt.Errorf("failed to read original file: %w", err)
	}

	decryptedContent, err := os.ReadFile(outputPath)
	if err != nil {
		return result, fmt.Errorf("failed to read decrypted file: %w", err)
	}

	if string(originalContent) != string(decryptedContent) {
		fmt.Println("WARNING: Decrypted content does not match original")
	}

	// Generate new key pair with non-matching attributes
	if err := os.WriteFile(tempAttrPath, []byte(nonMatchingAttrs), 0644); err != nil {
		return result, fmt.Errorf("failed to write non-matching attributes: %w", err)
	}

	fmt.Println("Running KeyGen with non-matching attributes...")
	nonMatchingSecretKeyPath := filepath.Join(sizeDir, "non_matching_secret_key")
	nonMatchingSecretKeyProofPath := filepath.Join(sizeDir, "non_matching_secret_key_proof")

	cmd = exec.Command("./bin/key_generator",
		"--attribute-path", tempAttrPath,
		"--private-key-path", nonMatchingSecretKeyPath,
		"--private-key-proof-path", nonMatchingSecretKeyProofPath,
	)

	if err := cmd.Run(); err != nil {
		return result, fmt.Errorf("non-matching key generation failed: %w", err)
	}

	// Benchmark Decrypt with non-matching attributes
	fmt.Println("Running Decrypt with non-matching attributes...")
	nonMatchingOutputPath := filepath.Join(sizeDir, "non_matching_output")
	start = time.Now()
	cmd = exec.Command("./bin/decryptor",
		"--mode", "decrypt",
		"--private-key-path", nonMatchingSecretKeyPath,
		"--ciphertext-path", ciphertextPath,
		"--attribute-path", tempAttrPath,
		"--output", nonMatchingOutputPath,
	)
	err = cmd.Run()
	result.DecryptNonMatchTime = time.Since(start)
	result.NonMatchingSuccess = err == nil

	if result.NonMatchingSuccess {
		fmt.Println("ERROR: Non-matching attributes successfully decrypted! This is incorrect behavior.")
		panic("Non-matching attributes should not decrypt successfully")
	} else {
		fmt.Println("Non-matching attributes correctly failed to decrypt.")
	}

	// Clean up temporary files
	if err := os.Remove(tempAttrPath); err != nil {
		fmt.Printf("Warning: failed to remove temporary attributes file: %v\n", err)
	}

	return result, nil
}

func readAttributes(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read attributes file: %w", err)
	}

	// Already in JSON format, just return as string
	return string(data), nil
}

func generateCSVReport(results []BenchmarkResult, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	// Write CSV header
	header := "Size,KeyGenTime(ms),VerifyKeyTime(ms),EncryptTime(ms),VerifyCiphertextTime(ms),DecryptMatchingTime(ms),DecryptNonMatchingTime(ms),MatchingSuccess,NonMatchingSuccess\n"
	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data rows
	for _, result := range results {
		row := fmt.Sprintf("%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%v,%v\n",
			result.Size,
			float64(result.KeyGenTime.Microseconds())/1000.0,
			float64(result.VerifyKeyTime.Microseconds())/1000.0,
			float64(result.EncryptTime.Microseconds())/1000.0,
			float64(result.VerifyCiphertextTime.Microseconds())/1000.0,
			float64(result.DecryptMatchingTime.Microseconds())/1000.0,
			float64(result.DecryptNonMatchTime.Microseconds())/1000.0,
			result.MatchingSuccess,
			result.NonMatchingSuccess)

		if _, err := file.WriteString(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	fmt.Printf("CSV report saved to %s\n", outputPath)
	return nil
}

func ParseArgs() BenmarchParams {
	var params BenmarchParams

	// Define command line flags
	testInfoPath := flag.String("test-info-path", "in/tests/test_info.json", "Path to the test info JSON file")
	help := flag.Bool("help", false, "Show help message")

	// Parse command line arguments
	flag.Parse()

	// Show help if requested
	if *help {
		fmt.Println("Benchmark Tool")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Set parameters
	params.TestInfoPath = *testInfoPath

	return params
}

func ReadTestInfo(path string) (*TestInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read test info file: %w", err)
	}

	var testInfo TestInfo
	if err := json.Unmarshal(data, &testInfo); err != nil {
		return nil, fmt.Errorf("failed to parse test info: %w", err)
	}

	return &testInfo, nil
}

type BenchmarkFileResult struct {
	KeygenTimeMs             float64 `json:"keygen_time_ms"`
	VerifyKeyTimeMs          float64 `json:"verify_key_time_ms"`
	EncryptTimeMs            float64 `json:"encrypt_time_ms"`
	VerifyCiphertextTimeMs   float64 `json:"verify_ciphertext_time_ms"`
	DecryptMatchingTimeMs    float64 `json:"decrypt_matching_time_ms"`
	DecryptNonMatchingTimeMs float64 `json:"decrypt_non_matching_time_ms"`
	MatchingSuccess          bool    `json:"matching_success"`
	NonMatchingSuccess       bool    `json:"non_matching_success"`
}

func LoadBenchmarkParamsFromFile(filename string, size int) (*BenchmarkResult, error) {
	//	timingData := fmt.Sprintf(`{
	//	"keygen_time_ms": %.2f,
	//	"verify_key_time_ms": %.2f,
	//	"encrypt_time_ms": %.2f,
	//	"verify_ciphertext_time_ms": %.2f,
	//	"decrypt_matching_time_ms": %.2f,
	//	"decrypt_non_matching_time_ms": %.2f,
	//	"matching_success": %v,
	//	"non_matching_success": %v
	//}`

	jsonFile, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open benchmark file: %w", err)
	}
	defer jsonFile.Close()

	var result BenchmarkFileResult
	decoder := json.NewDecoder(jsonFile)
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode benchmark file: %w", err)
	}

	return &BenchmarkResult{
		Size:                 size,
		KeyGenTime:           time.Duration(result.KeygenTimeMs * float64(time.Millisecond)),
		VerifyKeyTime:        time.Duration(result.VerifyKeyTimeMs * float64(time.Millisecond)),
		EncryptTime:          time.Duration(result.EncryptTimeMs * float64(time.Millisecond)),
		VerifyCiphertextTime: time.Duration(result.VerifyCiphertextTimeMs * float64(time.Millisecond)),
		DecryptMatchingTime:  time.Duration(result.DecryptMatchingTimeMs * float64(time.Millisecond)),
		DecryptNonMatchTime:  time.Duration(result.DecryptNonMatchingTimeMs * float64(time.Millisecond)),
		MatchingSuccess:      result.MatchingSuccess,
		NonMatchingSuccess:   result.NonMatchingSuccess,
	}, nil
}

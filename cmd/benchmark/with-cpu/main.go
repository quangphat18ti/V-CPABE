package with_cpu

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TestInfo struct {
	Sizes    []int             `json:"sizes"`
	FilePath map[string]string `json:"file_path"`
}

// Enhanced benchmark result with CPU and memory metrics
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

	// CPU and Memory metrics
	KeyGenCPU           CPUMemoryMetrics
	VerifyKeyCPU        CPUMemoryMetrics
	EncryptCPU          CPUMemoryMetrics
	VerifyCiphertextCPU CPUMemoryMetrics
	DecryptMatchingCPU  CPUMemoryMetrics
	DecryptNonMatchCPU  CPUMemoryMetrics
}

type CPUMemoryMetrics struct {
	UserCPUTime   time.Duration `json:"user_cpu_time_ms"`
	SystemCPUTime time.Duration `json:"system_cpu_time_ms"`
	MaxMemoryKB   int64         `json:"max_memory_kb"`
	PeakMemoryKB  int64         `json:"peak_memory_kb"`
	CPUPercent    float64       `json:"cpu_percent"`
}

type ProcessMonitor struct {
	pid         int
	stopChan    chan bool
	done        chan bool
	metrics     CPUMemoryMetrics
	mutex       sync.RWMutex
	lastCPUTime time.Duration
	lastTime    time.Time
	isRunning   bool
}

type BenmarchParams struct {
	TestInfoPath string `default:"in/tests/test_info.json"`
}

func Main() {
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

		// Save enhanced timing and resource information
		timingData := fmt.Sprintf(`{
	"keygen_time_ms": %.2f,
	"verify_key_time_ms": %.2f,
	"encrypt_time_ms": %.2f,
	"verify_ciphertext_time_ms": %.2f,
	"decrypt_matching_time_ms": %.2f,
	"decrypt_non_matching_time_ms": %.2f,
	"matching_success": %v,
	"non_matching_success": %v,
	"keygen_cpu": %s,
	"verify_key_cpu": %s,
	"encrypt_cpu": %s,
	"verify_ciphertext_cpu": %s,
	"decrypt_matching_cpu": %s,
	"decrypt_non_matching_cpu": %s
}`,
			float64(result.KeyGenTime.Microseconds())/1000.0,
			float64(result.VerifyKeyTime.Microseconds())/1000.0,
			float64(result.EncryptTime.Microseconds())/1000.0,
			float64(result.VerifyCiphertextTime.Microseconds())/1000.0,
			float64(result.DecryptMatchingTime.Microseconds())/1000.0,
			float64(result.DecryptNonMatchTime.Microseconds())/1000.0,
			result.MatchingSuccess,
			result.NonMatchingSuccess,
			metricsToJSON(result.KeyGenCPU),
			metricsToJSON(result.VerifyKeyCPU),
			metricsToJSON(result.EncryptCPU),
			metricsToJSON(result.VerifyCiphertextCPU),
			metricsToJSON(result.DecryptMatchingCPU),
			metricsToJSON(result.DecryptNonMatchCPU))

		timingPath := filepath.Join(testsDir, strconv.Itoa(size), "benchmark_results.json")
		if err := os.WriteFile(timingPath, []byte(timingData), 0644); err != nil {
			fmt.Printf("Error writing timing data for size %d: %v\n", size, err)
		}

		// Generate enhanced CSV report
		if err := generateEnhancedCSVReport(results, filepath.Join(testsDir, "benchmark_results.csv")); err != nil {
			fmt.Printf("Error generating CSV report: %v\n", err)
		}
	}

	// Generate enhanced CSV report
	if err := generateEnhancedCSVReport(results, filepath.Join(testsDir, "benchmark_results.csv")); err != nil {
		fmt.Printf("Error generating CSV report: %v\n", err)
	}

	fmt.Println("Benchmarking complete!")
}

func metricsToJSON(metrics CPUMemoryMetrics) string {
	data, _ := json.Marshal(metrics)
	return string(data)
}

// Enhanced benchmark function with CPU and memory monitoring
func runBenchmarkWithMonitoring(cmd *exec.Cmd, operation string) (time.Duration, CPUMemoryMetrics, error) {
	fmt.Printf("Running %s...\n", operation)

	// Start the command
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return 0, CPUMemoryMetrics{}, fmt.Errorf("failed to start command: %w", err)
	}

	// Start monitoring the process
	monitor := NewProcessMonitor(cmd.Process.Pid)
	monitor.Start()

	// Wait for command to complete
	err := cmd.Wait()
	duration := time.Since(start)

	// Stop monitoring and get final metrics
	metrics := monitor.Stop()

	return duration, metrics, err
}

func runBenchmark(size int, testsDir string, filePaths map[string]string) (BenchmarkResult, error) {
	result := BenchmarkResult{Size: size}

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
	tempAttrPath := filepath.Join(sizeDir, "temp_attributes.json")
	inputFile := "in/files/input_file.txt"
	secretKeyPath := filepath.Join(sizeDir, "secret_key")
	secretKeyProofPath := filepath.Join(sizeDir, "secret_key_proof")
	ciphertextPath := filepath.Join(sizeDir, "ciphertext")
	ciphertextProofPath := filepath.Join(sizeDir, "ciphertext_proof")
	outputPath := filepath.Join(sizeDir, "decrypted_output")

	// Benchmark KeyGen with matching attributes and monitoring
	if err := os.WriteFile(tempAttrPath, []byte(matchingAttrs), 0644); err != nil {
		return result, fmt.Errorf("failed to write temporary attributes: %w", err)
	}

	cmd := exec.Command("./bin/key_generator",
		"--attribute-path", tempAttrPath,
		"--private-key-path", secretKeyPath,
		"--private-key-proof-path", secretKeyProofPath,
	)
	result.KeyGenTime, result.KeyGenCPU, err = runBenchmarkWithMonitoring(cmd, "KeyGen")
	if err != nil {
		return result, fmt.Errorf("key generation failed: %w", err)
	}

	// Benchmark VerifyKey
	cmd = exec.Command("./bin/decryptor",
		"--mode", "verify-key",
		"--private-key-path", secretKeyPath,
		"--private-key-proof-path", secretKeyProofPath,
		"--attribute-path", tempAttrPath,
	)
	result.VerifyKeyTime, result.VerifyKeyCPU, err = runBenchmarkWithMonitoring(cmd, "VerifyKey")
	if err != nil {
		return result, fmt.Errorf("key verification failed: %w", err)
	}

	// Benchmark Encrypt
	cmd = exec.Command("./bin/encryptor",
		"--access-policy-path", policyPath,
		"--ciphertext-path", ciphertextPath,
		"--ciphertext-proof-path", ciphertextProofPath,
	)
	result.EncryptTime, result.EncryptCPU, err = runBenchmarkWithMonitoring(cmd, "Encrypt")
	if err != nil {
		return result, fmt.Errorf("encryption failed: %w", err)
	}

	// Benchmark VerifyCiphertext
	cmd = exec.Command("./bin/decryptor",
		"--mode", "verify-ciphertext",
		"--ciphertext-path", ciphertextPath,
		"--ciphertext-proof-path", ciphertextProofPath,
		"--access-policy-path", policyPath,
	)
	result.VerifyCiphertextTime, result.VerifyCiphertextCPU, err = runBenchmarkWithMonitoring(cmd, "VerifyCiphertext")
	if err != nil {
		return result, fmt.Errorf("ciphertext verification failed: %w", err)
	}

	// Benchmark Decrypt with matching attributes
	cmd = exec.Command("./bin/decryptor",
		"--verbose",
		"--mode", "decrypt",
		"--private-key-path", secretKeyPath,
		"--ciphertext-path", ciphertextPath,
		"--attribute-path", tempAttrPath,
		"--output-path", outputPath,
	)
	result.DecryptMatchingTime, result.DecryptMatchingCPU, err = runBenchmarkWithMonitoring(cmd, "Decrypt (matching)")
	result.MatchingSuccess = err == nil

	if !result.MatchingSuccess {
		fmt.Printf("ERROR: Matching attributes failed to decrypt: %v\n", err)
		return result, nil
	}

	// Verify decryption was successful
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
	nonMatchingOutputPath := filepath.Join(sizeDir, "non_matching_output")
	cmd = exec.Command("./bin/decryptor",
		"--mode", "decrypt",
		"--private-key-path", nonMatchingSecretKeyPath,
		"--ciphertext-path", ciphertextPath,
		"--attribute-path", tempAttrPath,
		"--output", nonMatchingOutputPath,
	)
	result.DecryptNonMatchTime, result.DecryptNonMatchCPU, err = runBenchmarkWithMonitoring(cmd, "Decrypt (non-matching)")
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

// Process monitoring functions
func NewProcessMonitor(pid int) *ProcessMonitor {
	return &ProcessMonitor{
		pid:       pid,
		stopChan:  make(chan bool, 1), // Buffered channel
		done:      make(chan bool, 1), // Buffered channel
		lastTime:  time.Now(),
		isRunning: false,
	}
}

func (pm *ProcessMonitor) Start() {
	pm.mutex.Lock()
	if pm.isRunning {
		pm.mutex.Unlock()
		return
	}
	pm.isRunning = true
	pm.mutex.Unlock()

	go pm.monitor()
}

func (pm *ProcessMonitor) Stop() CPUMemoryMetrics {
	pm.mutex.RLock()
	if !pm.isRunning {
		pm.mutex.RUnlock()
		pm.validateAndClampMetrics()
		pm.mutex.RLock()
		defer pm.mutex.RUnlock()
		return pm.metrics
	}
	pm.mutex.RUnlock()

	// Send stop signal (non-blocking)
	select {
	case pm.stopChan <- true:
	default:
	}

	// Wait for monitoring to finish with timeout
	select {
	case <-pm.done:
		// Monitoring finished successfully
	case <-time.After(2 * time.Second):
		// Timeout - monitoring didn't finish
		fmt.Printf("Warning: Process monitor timeout for PID %d\n", pm.pid)
	}

	pm.validateAndClampMetrics()
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.metrics
}

func (pm *ProcessMonitor) monitor() {
	defer func() {
		pm.mutex.Lock()
		pm.isRunning = false
		pm.mutex.Unlock()

		// Signal that monitoring is done
		select {
		case pm.done <- true:
		default:
		}
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	// Initialize baseline
	pm.getCurrentMemoryUsage()
	pm.updateCPUUsage()

	for {
		select {
		case <-pm.stopChan:
			return
		case <-ticker.C:
			// Check if process still exists
			if !pm.processExists() {
				return
			}
			pm.updateMetrics()
		}
	}
}

func (pm *ProcessMonitor) processExists() bool {
	// Quick check if process still exists
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		cmd := exec.Command("kill", "-0", strconv.Itoa(pm.pid))
		return cmd.Run() == nil
	}

	// Fallback for other platforms
	cmd := exec.Command("ps", "-p", strconv.Itoa(pm.pid))
	return cmd.Run() == nil
}

func (pm *ProcessMonitor) updateMetrics() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Get current memory from /proc (Linux) or ps command
	currentMemKB := pm.getCurrentMemoryUsage()
	if currentMemKB > pm.metrics.MaxMemoryKB {
		pm.metrics.MaxMemoryKB = currentMemKB
	}
	if currentMemKB > pm.metrics.PeakMemoryKB {
		pm.metrics.PeakMemoryKB = currentMemKB
	}

	// Get CPU usage via /proc/stat or ps command
	pm.updateCPUUsage()
}

func (pm *ProcessMonitor) getCurrentMemoryUsage() int64 {
	if runtime.GOOS == "linux" {
		// Read from /proc/PID/status for accurate memory
		statusFile := fmt.Sprintf("/proc/%d/status", pm.pid)
		if data, err := os.ReadFile(statusFile); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "VmRSS:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						if mem, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
							return mem // Already in KB
						}
					}
				}
			}
		}
	}

	// Fallback: Use ps command for cross-platform support
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		// macOS ps command
		cmd = exec.Command("ps", "-p", strconv.Itoa(pm.pid), "-o", "rss=")
	} else {
		// Linux and others
		cmd = exec.Command("ps", "-p", strconv.Itoa(pm.pid), "-o", "rss=")
	}

	if output, err := cmd.Output(); err == nil {
		memStr := strings.TrimSpace(string(output))
		if memStr != "" {
			if mem, err := strconv.ParseInt(memStr, 10, 64); err == nil {
				return mem // ps returns KB on most systems
			}
		}
	}

	return 0
}

func (pm *ProcessMonitor) updateCPUUsage() {
	if runtime.GOOS == "linux" {
		// Read CPU stats from /proc/PID/stat
		statFile := fmt.Sprintf("/proc/%d/stat", pm.pid)
		if data, err := os.ReadFile(statFile); err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 17 {
				// fields[13] = utime, fields[14] = stime (in clock ticks)
				if utime, err1 := strconv.ParseInt(fields[13], 10, 64); err1 == nil {
					if stime, err2 := strconv.ParseInt(fields[14], 10, 64); err2 == nil {
						// Convert clock ticks to milliseconds (100 ticks = 1 second typically)
						clockTick := int64(100) // Typical value, can get from sysconf(_SC_CLK_TCK)
						pm.metrics.UserCPUTime = time.Duration(utime*1000/clockTick) * time.Millisecond
						pm.metrics.SystemCPUTime = time.Duration(stime*1000/clockTick) * time.Millisecond

						// Calculate CPU percentage since last measurement
						now := time.Now()
						if !pm.lastTime.IsZero() {
							totalCPUTime := pm.metrics.UserCPUTime + pm.metrics.SystemCPUTime
							cpuDelta := totalCPUTime - pm.lastCPUTime
							timeDelta := now.Sub(pm.lastTime)

							if timeDelta > 0 {
								// Limit CPU percentage to reasonable values (0-100% per core)
								cpuPercent := float64(cpuDelta) / float64(timeDelta) * 100.0
								if cpuPercent <= float64(runtime.NumCPU()*100) {
									pm.metrics.CPUPercent = cpuPercent
								}
							}
							pm.lastCPUTime = totalCPUTime
						}
						pm.lastTime = now
						return
					}
				}
			}
		}
	}

	// Fallback: Use ps command for CPU
	cmd := exec.Command("ps", "-p", strconv.Itoa(pm.pid), "-o", "pcpu=")
	if output, err := cmd.Output(); err == nil {
		if cpu, err := strconv.ParseFloat(strings.TrimSpace(string(output)), 64); err == nil {
			pm.metrics.CPUPercent = cpu
		}
	}
}

// Remove the old updateLinuxMemoryStats function since it's replaced
// Add validation function for reasonable metrics
func (pm *ProcessMonitor) validateAndClampMetrics() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Clamp memory to reasonable values (max 32GB = 32 * 1024 * 1024 KB)
	maxReasonableMemKB := int64(32 * 1024 * 1024)
	if pm.metrics.MaxMemoryKB > maxReasonableMemKB {
		fmt.Printf("Warning: Clamping unreasonable memory value %d KB to %d KB\n",
			pm.metrics.MaxMemoryKB, maxReasonableMemKB)
		pm.metrics.MaxMemoryKB = maxReasonableMemKB
	}

	if pm.metrics.PeakMemoryKB > maxReasonableMemKB {
		pm.metrics.PeakMemoryKB = maxReasonableMemKB
	}

	// Clamp CPU percentage to reasonable values (0-100% per core)
	maxCPU := float64(runtime.NumCPU() * 100)
	if pm.metrics.CPUPercent > maxCPU {
		fmt.Printf("Warning: Clamping unreasonable CPU value %.2f%% to %.2f%%\n",
			pm.metrics.CPUPercent, maxCPU)
		pm.metrics.CPUPercent = maxCPU
	}

	if pm.metrics.CPUPercent < 0 {
		pm.metrics.CPUPercent = 0
	}
}

func generateEnhancedCSVReport(results []BenchmarkResult, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	// Write enhanced CSV header with CPU and memory metrics
	header := "Size,KeyGenTime(ms),VerifyKeyTime(ms),EncryptTime(ms),VerifyCiphertextTime(ms),DecryptMatchingTime(ms),DecryptNonMatchingTime(ms)," +
		"KeyGenMaxMem(KB),VerifyKeyMaxMem(KB),EncryptMaxMem(KB),VerifyCiphertextMaxMem(KB),DecryptMatchingMaxMem(KB),DecryptNonMatchingMaxMem(KB)," +
		"KeyGenCPU(%),VerifyKeyCPU(%),EncryptCPU(%),VerifyCiphertextCPU(%),DecryptMatchingCPU(%),DecryptNonMatchingCPU(%)," +
		"MatchingSuccess,NonMatchingSuccess\n"

	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data rows with enhanced metrics
	for _, result := range results {
		row := fmt.Sprintf("%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d,%d,%d,%d,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%v,%v\n",
			result.Size,
			float64(result.KeyGenTime.Microseconds())/1000.0,
			float64(result.VerifyKeyTime.Microseconds())/1000.0,
			float64(result.EncryptTime.Microseconds())/1000.0,
			float64(result.VerifyCiphertextTime.Microseconds())/1000.0,
			float64(result.DecryptMatchingTime.Microseconds())/1000.0,
			float64(result.DecryptNonMatchTime.Microseconds())/1000.0,
			result.KeyGenCPU.MaxMemoryKB,
			result.VerifyKeyCPU.MaxMemoryKB,
			result.EncryptCPU.MaxMemoryKB,
			result.VerifyCiphertextCPU.MaxMemoryKB,
			result.DecryptMatchingCPU.MaxMemoryKB,
			result.DecryptNonMatchCPU.MaxMemoryKB,
			result.KeyGenCPU.CPUPercent,
			result.VerifyKeyCPU.CPUPercent,
			result.EncryptCPU.CPUPercent,
			result.VerifyCiphertextCPU.CPUPercent,
			result.DecryptMatchingCPU.CPUPercent,
			result.DecryptNonMatchCPU.CPUPercent,
			result.MatchingSuccess,
			result.NonMatchingSuccess)

		if _, err := file.WriteString(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	fmt.Printf("Enhanced CSV report saved to %s\n", outputPath)
	return nil
}

// Existing functions remain the same
func readAttributes(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read attributes file: %w", err)
	}
	return string(data), nil
}

func ParseArgs() BenmarchParams {
	var params BenmarchParams

	testInfoPath := flag.String("test-info-path", "in/tests/test_info.json", "Path to the test info JSON file")
	help := flag.Bool("help", false, "Show help message")

	flag.Parse()

	if *help {
		fmt.Println("Enhanced Benchmark Tool with CPU and Memory Monitoring")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

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

//go:build windows
// +build windows

// Stage 4: Multi-Wiper Deployment (T1485)
// Simulates simultaneous deployment of three Agrius wiper variants:
// - MultiLayer Wiper: Overwrites test files with random data
// - PartialWasher: Selectively corrupts test file headers
// - BFG Agonizer: Aggressive overwrite with multiple passes
//
// SAFE: Only operates on test files created in c:\F0\wiper_test\
// NEVER touches real data, boot sectors, or system files

package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	TEST_UUID      = "7d39b861-644d-4f8b-bb19-4faae527a130"
	TECHNIQUE_ID   = "T1485"
	TECHNIQUE_NAME = "Data Destruction"
	STAGE_ID       = 4
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	wiperTestDir = "c:\\F0\\wiper_test"
	testFileSize = 4096 // 4KB test files
	numTestFiles = 20   // Create 20 test files to simulate data targets
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	fmt.Printf("[STAGE %s] Starting %s\n", TECHNIQUE_ID, TECHNIQUE_NAME)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogMessage("INFO", TECHNIQUE_ID, "Simulating Agrius multi-wiper deployment (MultiLayer + PartialWasher + BFG Agonizer)")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)
		LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		os.Exit(determineExitCode(err))
	}

	fmt.Printf("[STAGE %s] %s executed successfully\n", TECHNIQUE_ID, TECHNIQUE_NAME)
	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Multi-wiper deployment simulation completed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Phase 1: Create test file targets (simulating banking data files)
	fmt.Printf("[STAGE %s] Phase 1: Creating test file targets in %s\n", TECHNIQUE_ID, wiperTestDir)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Creating %d test files in %s", numTestFiles, wiperTestDir))

	if err := createTestTargets(); err != nil {
		return fmt.Errorf("failed to create test targets: %v", err)
	}

	// Phase 2: Deploy three wipers simultaneously (concurrent execution)
	fmt.Printf("[STAGE %s] Phase 2: Deploying three wiper variants simultaneously\n", TECHNIQUE_ID)
	LogMessage("WARNING", TECHNIQUE_ID, "Launching simultaneous multi-wiper deployment")

	var wg sync.WaitGroup
	wiperResults := make(chan wiperResult, 3)

	// Launch all three wipers concurrently (simulates real Agrius behavior)
	wg.Add(3)

	go func() {
		defer wg.Done()
		wiperResults <- runMultiLayerWiper()
	}()

	go func() {
		defer wg.Done()
		wiperResults <- runPartialWasherWiper()
	}()

	go func() {
		defer wg.Done()
		wiperResults <- runBFGAgonizerWiper()
	}()

	wg.Wait()
	close(wiperResults)

	// Evaluate wiper results
	totalWiped := 0
	totalBlocked := 0
	for result := range wiperResults {
		fmt.Printf("[STAGE %s] Wiper %s: wiped=%d, blocked=%d\n", TECHNIQUE_ID, result.name, result.filesWiped, result.filesBlocked)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Wiper %s: wiped=%d, blocked=%d, error=%v",
			result.name, result.filesWiped, result.filesBlocked, result.err))
		totalWiped += result.filesWiped
		totalBlocked += result.filesBlocked
	}

	// Phase 3: Boot sector awareness simulation (LOG ONLY - never modify actual boot sectors)
	fmt.Printf("[STAGE %s] Phase 3: Boot sector awareness check (LOG ONLY)\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Boot sector awareness: Agrius BFG Agonizer targets MBR/VBR in real attacks")
	LogMessage("INFO", TECHNIQUE_ID, "SAFETY: Boot sector modification SIMULATED ONLY (logged, not executed)")
	LogMessage("INFO", TECHNIQUE_ID, "Real IOC: MBR overwrite with 0x00 bytes, VBR corruption via raw disk access")

	// Write a simulation marker file instead of touching boot sectors
	bootSimPath := filepath.Join(wiperTestDir, "BOOT_SECTOR_SIM_MARKER.txt")
	bootSimContent := fmt.Sprintf("F0RT1KA SIMULATION\r\nAgrius BFG Agonizer boot sector wipe simulation\r\nTimestamp: %s\r\nReal attack would overwrite MBR at physical offset 0x0 with null bytes\r\nReal attack would corrupt VBR at partition start sectors\r\nThis file is a safe simulation marker - NO actual boot sector was modified\r\n",
		time.Now().UTC().Format(time.RFC3339))
	os.WriteFile(bootSimPath, []byte(bootSimContent), 0644)

	// Summary
	fmt.Printf("[STAGE %s] Multi-wiper summary: %d files wiped, %d blocked\n", TECHNIQUE_ID, totalWiped, totalBlocked)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Multi-wiper summary: total_wiped=%d, total_blocked=%d", totalWiped, totalBlocked))

	// If all operations were blocked, EDR is protecting
	if totalWiped == 0 && totalBlocked > 0 {
		return fmt.Errorf("all wiper operations blocked by EDR (%d blocked)", totalBlocked)
	}

	return nil
}

type wiperResult struct {
	name         string
	filesWiped   int
	filesBlocked int
	err          error
}

// createTestTargets creates test files simulating banking data
func createTestTargets() error {
	if err := os.MkdirAll(wiperTestDir, 0755); err != nil {
		return err
	}

	// Create subdirectories simulating banking infrastructure layout
	subdirs := []string{"transactions", "customer_data", "audit_logs"}
	for _, subdir := range subdirs {
		os.MkdirAll(filepath.Join(wiperTestDir, subdir), 0755)
	}

	extensions := []string{".db", ".xlsx", ".pdf", ".docx", ".csv", ".bak", ".log"}
	fileIdx := 0

	for _, subdir := range subdirs {
		for i := 0; i < numTestFiles/len(subdirs); i++ {
			ext := extensions[fileIdx%len(extensions)]
			filename := fmt.Sprintf("test_data_%03d%s", fileIdx, ext)
			filePath := filepath.Join(wiperTestDir, subdir, filename)

			content := make([]byte, testFileSize)
			rand.Read(content)

			if err := os.WriteFile(filePath, content, 0644); err != nil {
				return fmt.Errorf("failed to create test file %s: %v", filename, err)
			}
			fileIdx++
		}
	}

	// Create remaining files in root wiper_test dir
	for fileIdx < numTestFiles {
		ext := extensions[fileIdx%len(extensions)]
		filename := fmt.Sprintf("test_data_%03d%s", fileIdx, ext)
		filePath := filepath.Join(wiperTestDir, filename)

		content := make([]byte, testFileSize)
		rand.Read(content)
		os.WriteFile(filePath, content, 0644)
		fileIdx++
	}

	fmt.Printf("[STAGE %s] Created %d test files across %d directories\n", TECHNIQUE_ID, numTestFiles, len(subdirs)+1)
	return nil
}

// runMultiLayerWiper simulates the MultiLayer wiper - overwrites files with random data
func runMultiLayerWiper() wiperResult {
	result := wiperResult{name: "MultiLayer"}

	fmt.Printf("[STAGE %s] [MultiLayer] Starting random data overwrite wiper\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "[MultiLayer] Starting random data overwrite simulation")

	err := filepath.Walk(filepath.Join(wiperTestDir, "transactions"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Overwrite with random data (simulating MultiLayer wiper behavior)
		randomData := make([]byte, info.Size())
		rand.Read(randomData)

		if writeErr := os.WriteFile(path, randomData, 0644); writeErr != nil {
			result.filesBlocked++
			return nil
		}
		result.filesWiped++
		return nil
	})

	result.err = err
	return result
}

// runPartialWasherWiper simulates PartialWasher - corrupts file headers
func runPartialWasherWiper() wiperResult {
	result := wiperResult{name: "PartialWasher"}

	fmt.Printf("[STAGE %s] [PartialWasher] Starting file header corruption wiper\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "[PartialWasher] Starting file header corruption simulation")

	err := filepath.Walk(filepath.Join(wiperTestDir, "customer_data"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Read existing file
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			result.filesBlocked++
			return nil
		}

		// Corrupt first 512 bytes (header corruption - PartialWasher behavior)
		corruptSize := 512
		if len(data) < corruptSize {
			corruptSize = len(data)
		}

		corruptData := make([]byte, corruptSize)
		rand.Read(corruptData)
		copy(data[:corruptSize], corruptData)

		if writeErr := os.WriteFile(path, data, 0644); writeErr != nil {
			result.filesBlocked++
			return nil
		}
		result.filesWiped++
		return nil
	})

	result.err = err
	return result
}

// runBFGAgonizerWiper simulates BFG Agonizer - aggressive multi-pass overwrite
func runBFGAgonizerWiper() wiperResult {
	result := wiperResult{name: "BFG Agonizer"}

	fmt.Printf("[STAGE %s] [BFG Agonizer] Starting multi-pass aggressive wiper\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "[BFG Agonizer] Starting multi-pass overwrite simulation")

	err := filepath.Walk(filepath.Join(wiperTestDir, "audit_logs"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Three-pass overwrite (BFG Agonizer pattern)
		passes := []byte{0x00, 0xFF, 0xAA} // null, ones, alternating
		for _, pattern := range passes {
			overwriteData := make([]byte, info.Size())
			for i := range overwriteData {
				overwriteData[i] = pattern
			}
			if writeErr := os.WriteFile(path, overwriteData, 0644); writeErr != nil {
				result.filesBlocked++
				return nil
			}
		}

		// Final pass: delete the file (destruction)
		if removeErr := os.Remove(path); removeErr != nil {
			result.filesBlocked++
			return nil
		}
		result.filesWiped++
		return nil
	})

	result.err = err
	return result
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "blocked") || strings.Contains(errStr, "denied") ||
		strings.Contains(errStr, "prevented") || strings.Contains(errStr, "quarantined") {
		return StageBlocked
	}
	return StageBlocked
}

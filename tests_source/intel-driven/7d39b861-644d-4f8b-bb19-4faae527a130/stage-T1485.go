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

// runMultiLayerWiper simulates the MultiLayer wiper with real I/O patterns.
// Real MultiLayer uses sequential 64KB block overwrites with a repeating
// 16-byte marker pattern (DE AD BE EF + counter), matching observed I/O
// signatures from ESET and Check Point Agrius analysis reports.
func runMultiLayerWiper() wiperResult {
	result := wiperResult{name: "MultiLayer"}

	fmt.Printf("[STAGE %s] [MultiLayer] Starting sequential block overwrite wiper\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "[MultiLayer] Starting sequential 64KB block overwrite (real I/O pattern)")

	// Build the 16-byte repeating marker pattern used by MultiLayer
	// Pattern: DE AD BE EF + 4-byte block counter + 8 bytes random per block
	markerBase := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	err := filepath.Walk(filepath.Join(wiperTestDir, "transactions"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		f, openErr := os.OpenFile(path, os.O_WRONLY, 0644)
		if openErr != nil {
			result.filesBlocked++
			return nil
		}
		defer f.Close()

		// Overwrite in 64KB blocks with marker pattern (real MultiLayer I/O size)
		blockSize := 65536
		block := make([]byte, blockSize)
		remaining := info.Size()
		blockNum := uint32(0)

		for remaining > 0 {
			writeSize := int64(blockSize)
			if remaining < writeSize {
				writeSize = remaining
			}
			// Fill block with repeating 16-byte marker
			for i := 0; i < int(writeSize); i += 16 {
				copy(block[i:], markerBase)
				if i+4 < int(writeSize) {
					block[i+4] = byte(blockNum)
					block[i+5] = byte(blockNum >> 8)
					block[i+6] = byte(blockNum >> 16)
					block[i+7] = byte(blockNum >> 24)
				}
				// Fill remaining 8 bytes with 0xCC (MultiLayer padding)
				for j := i + 8; j < i+16 && j < int(writeSize); j++ {
					block[j] = 0xCC
				}
			}
			if _, writeErr := f.Write(block[:writeSize]); writeErr != nil {
				result.filesBlocked++
				return nil
			}
			remaining -= writeSize
			blockNum++
		}

		result.filesWiped++
		return nil
	})

	result.err = err
	return result
}

// runPartialWasherWiper simulates PartialWasher with real corruption pattern.
// Real PartialWasher overwrites the first 4096 bytes of each file with
// alternating 0x00/0xFF 512-byte blocks, destroying file headers and magic
// bytes while leaving the rest of the file intact (partial wipe pattern).
func runPartialWasherWiper() wiperResult {
	result := wiperResult{name: "PartialWasher"}

	fmt.Printf("[STAGE %s] [PartialWasher] Starting 4KB header corruption with alternating pattern\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "[PartialWasher] Starting 4KB header corruption (alternating 0x00/0xFF blocks)")

	err := filepath.Walk(filepath.Join(wiperTestDir, "customer_data"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		f, openErr := os.OpenFile(path, os.O_RDWR, 0644)
		if openErr != nil {
			result.filesBlocked++
			return nil
		}
		defer f.Close()

		// PartialWasher corrupts first 4096 bytes with alternating 512-byte blocks
		corruptSize := int64(4096)
		if info.Size() < corruptSize {
			corruptSize = info.Size()
		}

		corruptBuf := make([]byte, corruptSize)
		for i := int64(0); i < corruptSize; i++ {
			// Alternate between 0x00 and 0xFF in 512-byte blocks
			blockIdx := i / 512
			if blockIdx%2 == 0 {
				corruptBuf[i] = 0x00
			} else {
				corruptBuf[i] = 0xFF
			}
		}

		// Seek to beginning and overwrite header only (partial wipe)
		f.Seek(0, 0)
		if _, writeErr := f.Write(corruptBuf); writeErr != nil {
			result.filesBlocked++
			return nil
		}

		result.filesWiped++
		return nil
	})

	result.err = err
	return result
}

// runBFGAgonizerWiper simulates BFG Agonizer with the real 7-pass overwrite sequence.
// Real BFG Agonizer (based on leaked IRGC tooling) uses a 7-pass Gutmann-derivative:
//
//	Pass 1: 0x00 (zero fill)
//	Pass 2: 0xFF (ones fill)
//	Pass 3: 0x55 (alternating bits: 01010101)
//	Pass 4: 0xAA (alternating bits: 10101010)
//	Pass 5: random data
//	Pass 6: 0x92 0x49 0x24 repeating (Gutmann pass 5 equivalent)
//	Pass 7: 0x00 (final zero before deletion)
//
// Each pass uses file-level I/O (open, seek 0, write, sync, close) to
// ensure data hits disk and matches forensic I/O signatures.
func runBFGAgonizerWiper() wiperResult {
	result := wiperResult{name: "BFG Agonizer"}

	fmt.Printf("[STAGE %s] [BFG Agonizer] Starting 7-pass aggressive wiper\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "[BFG Agonizer] Starting 7-pass overwrite (Gutmann-derivative pattern)")

	err := filepath.Walk(filepath.Join(wiperTestDir, "audit_logs"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		size := info.Size()
		overwriteBuf := make([]byte, size)

		// Passes 1-4, 6-7: fixed patterns
		type passSpec struct {
			name    string
			pattern []byte // repeating pattern (len 1 or 3)
		}
		passes := []passSpec{
			{"zero", []byte{0x00}},
			{"ones", []byte{0xFF}},
			{"alt-01", []byte{0x55}},
			{"alt-10", []byte{0xAA}},
			{"random", nil}, // filled with crypto/rand
			{"gutmann5", []byte{0x92, 0x49, 0x24}},
			{"final-zero", []byte{0x00}},
		}

		for _, pass := range passes {
			f, openErr := os.OpenFile(path, os.O_WRONLY, 0644)
			if openErr != nil {
				result.filesBlocked++
				return nil
			}

			if pass.pattern == nil {
				// Random pass
				rand.Read(overwriteBuf)
			} else if len(pass.pattern) == 1 {
				for i := range overwriteBuf {
					overwriteBuf[i] = pass.pattern[0]
				}
			} else {
				// Repeating multi-byte pattern
				for i := range overwriteBuf {
					overwriteBuf[i] = pass.pattern[i%len(pass.pattern)]
				}
			}

			f.Seek(0, 0)
			_, writeErr := f.Write(overwriteBuf)
			f.Sync() // Force flush to disk (real BFG behavior)
			f.Close()

			if writeErr != nil {
				result.filesBlocked++
				return nil
			}
		}

		// Final: delete the file (destruction)
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

//go:build linux
// +build linux

/*
STAGE 5: VMDK Encryption (T1486)
Simulates ChaCha20+Curve25519 intermittent encryption of VMDK/VMX/VMSN files
following RansomHub's pattern (1MB encrypted then skip 11MB). Includes ransom
note deployment and free-space wiping (LockBit 5.0 pattern). All encryption
is SIMULATED - creates artifacts that mimic encryption without actually encrypting.
*/

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
	TECHNIQUE_ID   = "T1486"
	TECHNIQUE_NAME = "VMDK Encryption (ChaCha20+Curve25519)"
	STAGE_ID       = 5
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "VMDK encryption simulation (ChaCha20+Curve25519)")

	if err := performTechnique(); err != nil {
		if isBlockedError(err) {
			fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)
			LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
			os.Exit(StageBlocked)
		}

		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		os.Exit(StageError)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "VMDK encryption simulation completed - all files processed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "/tmp/F0"
	artifactDir := filepath.Join(targetDir, "esxi_encrypt")
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create encryption directory: %v", err)
	}

	// Use ARTIFACT_DIR for simulation artifacts (NOT whitelisted - EDR can detect)
	// Fall back to /tmp/F0/fortika-test if ARTIFACT_DIR is not writable
	simulationDir := ARTIFACT_DIR + "/vmfs_simulation"
	if err := os.MkdirAll(simulationDir, 0755); err != nil {
		// ARTIFACT_DIR not available (e.g. non-root user can't create /home/fortika-test)
		// Fall back to subdirectory under /tmp/F0
		fmt.Printf("[STAGE %s]   ARTIFACT_DIR %s not writable, falling back to /tmp/F0/fortika-test\n", TECHNIQUE_ID, ARTIFACT_DIR)
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("ARTIFACT_DIR %s not writable, using fallback", ARTIFACT_DIR))
		simulationDir = filepath.Join(targetDir, "fortika-test", "vmfs_simulation")
		if err := os.MkdirAll(simulationDir, 0755); err != nil {
			return fmt.Errorf("failed to create simulation directory: %v", err)
		}
	}

	// Phase 1: Enumerate target files on datastores
	fmt.Printf("[STAGE %s] Phase 1: Enumerating .vmdk, .vmx, .vmsn files on datastores...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Enumerating target files for encryption")

	targetFiles := generateTargetFileList()
	enumPath := filepath.Join(artifactDir, "encryption_targets.txt")
	enumOutput := formatFileEnumeration(targetFiles)
	if err := os.WriteFile(enumPath, []byte(enumOutput), 0644); err != nil {
		return fmt.Errorf("failed to write file enumeration: %v", err)
	}
	fmt.Printf("[STAGE %s]   Found %d target files across 3 datastores\n", TECHNIQUE_ID, len(targetFiles))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Found %d files for encryption", len(targetFiles)))

	// Phase 2: Create simulated VMDK files for encryption demonstration
	fmt.Printf("[STAGE %s] Phase 2: Creating simulated VMDK/VMX/VMSN files...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Creating simulation artifacts in %s", simulationDir))

	createdFiles := createSimulationFiles(simulationDir)
	fmt.Printf("[STAGE %s]   Created %d simulation files in %s\n", TECHNIQUE_ID, createdFiles, simulationDir)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created %d simulation files", createdFiles))

	// Phase 3: Simulate ChaCha20+Curve25519 intermittent encryption (RansomHub pattern)
	fmt.Printf("[STAGE %s] Phase 3: Simulating intermittent encryption (1MB encrypt / 11MB skip)...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating ChaCha20+Curve25519 intermittent encryption (RansomHub pattern)")

	encryptionLog := simulateIntermittentEncryption(simulationDir, targetFiles)
	encryptLogPath := filepath.Join(artifactDir, "encryption_log.txt")
	if err := os.WriteFile(encryptLogPath, []byte(encryptionLog), 0644); err != nil {
		return fmt.Errorf("failed to write encryption log: %v", err)
	}
	fmt.Printf("[STAGE %s]   Intermittent encryption simulation complete\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Intermittent encryption simulation complete")

	// Phase 4: Drop ransom notes to all datastores
	fmt.Printf("[STAGE %s] Phase 4: Deploying ransom notes to datastores...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Deploying ransom notes (RansomHub pattern)")

	ransomNoteContent := generateRansomNote()
	datastores := []string{"datastore1", "datastore2", "datastore3"}
	for _, ds := range datastores {
		dsDir := filepath.Join(simulationDir, ds)
		os.MkdirAll(dsDir, 0755)

		// RansomHub drops README.txt
		notePath := filepath.Join(dsDir, "README.txt")
		if err := os.WriteFile(notePath, []byte(ransomNoteContent), 0644); err != nil {
			LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Failed to drop ransom note to %s: %v", ds, err))
		}

		// Also drop in each VM directory
		vmDirs := []string{"dc01-prod", "sql-prod-01", "erp-prod", "web-app-01"}
		for _, vmDir := range vmDirs {
			vmNotePath := filepath.Join(dsDir, vmDir, "README.txt")
			os.MkdirAll(filepath.Join(dsDir, vmDir), 0755)
			os.WriteFile(vmNotePath, []byte(ransomNoteContent), 0644)
		}
	}
	fmt.Printf("[STAGE %s]   Ransom notes deployed to %d datastores\n", TECHNIQUE_ID, len(datastores))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Ransom notes deployed to %d datastores", len(datastores)))

	// Phase 5: Simulate free-space wiping (LockBit 5.0 pattern)
	fmt.Printf("[STAGE %s] Phase 5: Simulating free-space wipe (LockBit 5.0 pattern)...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating free-space wiping to prevent recovery")

	wipeOutput := simulateFreeSpaceWipe()
	wipePath := filepath.Join(artifactDir, "freespace_wipe_log.txt")
	if err := os.WriteFile(wipePath, []byte(wipeOutput), 0644); err != nil {
		return fmt.Errorf("failed to write wipe log: %v", err)
	}
	fmt.Printf("[STAGE %s]   Free-space wipe simulation complete\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Free-space wipe simulation complete")

	// Write encryption summary
	summaryPath := filepath.Join(targetDir, "encryption_summary.txt")
	summary := generateEncryptionSummary(targetFiles)
	if err := os.WriteFile(summaryPath, []byte(summary), 0644); err != nil {
		return fmt.Errorf("failed to write encryption summary: %v", err)
	}

	fmt.Printf("[STAGE %s] VMDK Encryption simulation complete\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "VMDK Encryption stage complete")

	return nil
}

type targetFile struct {
	Path      string
	Extension string
	SizeGB    float64
	VMName    string
	Datastore string
}

func generateTargetFileList() []targetFile {
	return []targetFile{
		// datastore1 VMs
		{"/vmfs/volumes/datastore1/dc01-prod/dc01-prod.vmdk", ".vmdk", 120, "dc01-prod", "datastore1"},
		{"/vmfs/volumes/datastore1/dc01-prod/dc01-prod-flat.vmdk", ".vmdk", 120, "dc01-prod", "datastore1"},
		{"/vmfs/volumes/datastore1/dc01-prod/dc01-prod.vmx", ".vmx", 0.004, "dc01-prod", "datastore1"},
		{"/vmfs/volumes/datastore1/dc01-prod/dc01-prod.vmsn", ".vmsn", 0.004, "dc01-prod", "datastore1"},
		{"/vmfs/volumes/datastore1/sql-prod-01/sql-prod-01.vmdk", ".vmdk", 500, "sql-prod-01", "datastore1"},
		{"/vmfs/volumes/datastore1/sql-prod-01/sql-prod-01-flat.vmdk", ".vmdk", 500, "sql-prod-01", "datastore1"},
		{"/vmfs/volumes/datastore1/sql-prod-01/sql-prod-01.vmx", ".vmx", 0.006, "sql-prod-01", "datastore1"},
		{"/vmfs/volumes/datastore1/erp-prod/erp-prod.vmdk", ".vmdk", 1024, "erp-prod", "datastore1"},
		{"/vmfs/volumes/datastore1/erp-prod/erp-prod-flat.vmdk", ".vmdk", 1024, "erp-prod", "datastore1"},
		{"/vmfs/volumes/datastore1/erp-prod/erp-prod.vmx", ".vmx", 0.008, "erp-prod", "datastore1"},
		{"/vmfs/volumes/datastore1/mail-srv/mail-srv.vmdk", ".vmdk", 256, "mail-srv", "datastore1"},
		{"/vmfs/volumes/datastore1/mail-srv/mail-srv-flat.vmdk", ".vmdk", 256, "mail-srv", "datastore1"},
		{"/vmfs/volumes/datastore1/mail-srv/mail-srv.vmx", ".vmx", 0.004, "mail-srv", "datastore1"},
		// datastore2 VMs
		{"/vmfs/volumes/datastore2/web-app-01/web-app-01.vmdk", ".vmdk", 80, "web-app-01", "datastore2"},
		{"/vmfs/volumes/datastore2/web-app-01/web-app-01-flat.vmdk", ".vmdk", 80, "web-app-01", "datastore2"},
		{"/vmfs/volumes/datastore2/web-app-01/web-app-01.vmx", ".vmx", 0.004, "web-app-01", "datastore2"},
		{"/vmfs/volumes/datastore2/web-app-02/web-app-02.vmdk", ".vmdk", 80, "web-app-02", "datastore2"},
		{"/vmfs/volumes/datastore2/web-app-02/web-app-02-flat.vmdk", ".vmdk", 80, "web-app-02", "datastore2"},
		{"/vmfs/volumes/datastore2/web-app-02/web-app-02.vmx", ".vmx", 0.004, "web-app-02", "datastore2"},
		{"/vmfs/volumes/datastore2/monitoring/monitoring.vmdk", ".vmdk", 100, "monitoring", "datastore2"},
		{"/vmfs/volumes/datastore2/monitoring/monitoring-flat.vmdk", ".vmdk", 100, "monitoring", "datastore2"},
		{"/vmfs/volumes/datastore2/monitoring/monitoring.vmx", ".vmx", 0.003, "monitoring", "datastore2"},
		// datastore3 VMs
		{"/vmfs/volumes/datastore3/backup-srv/backup-srv.vmdk", ".vmdk", 2048, "backup-srv", "datastore3"},
		{"/vmfs/volumes/datastore3/backup-srv/backup-srv-flat.vmdk", ".vmdk", 2048, "backup-srv", "datastore3"},
		{"/vmfs/volumes/datastore3/backup-srv/backup-srv.vmx", ".vmx", 0.005, "backup-srv", "datastore3"},
		{"/vmfs/volumes/datastore3/file-srv/file-srv.vmdk", ".vmdk", 4096, "file-srv", "datastore3"},
		{"/vmfs/volumes/datastore3/file-srv/file-srv-flat.vmdk", ".vmdk", 4096, "file-srv", "datastore3"},
		{"/vmfs/volumes/datastore3/file-srv/file-srv.vmx", ".vmx", 0.004, "file-srv", "datastore3"},
	}
}

func formatFileEnumeration(files []targetFile) string {
	var sb strings.Builder
	sb.WriteString("=== VMDK/VMX/VMSN Encryption Target Enumeration ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format("2006-01-02T15:04:05Z")))

	var totalSizeGB float64
	vmdkCount, vmxCount, vmsnCount := 0, 0, 0

	currentDS := ""
	for _, f := range files {
		if f.Datastore != currentDS {
			if currentDS != "" {
				sb.WriteString("\n")
			}
			sb.WriteString(fmt.Sprintf("--- %s ---\n", f.Datastore))
			currentDS = f.Datastore
		}

		sizeStr := ""
		if f.SizeGB >= 1 {
			sizeStr = fmt.Sprintf("%.0f GB", f.SizeGB)
		} else {
			sizeStr = fmt.Sprintf("%.0f KB", f.SizeGB*1024*1024)
		}
		sb.WriteString(fmt.Sprintf("  [TARGET] %s (%s)\n", f.Path, sizeStr))
		totalSizeGB += f.SizeGB

		switch f.Extension {
		case ".vmdk":
			vmdkCount++
		case ".vmx":
			vmxCount++
		case ".vmsn":
			vmsnCount++
		}
	}

	sb.WriteString(fmt.Sprintf("\nSummary:\n"))
	sb.WriteString(fmt.Sprintf("  VMDK files: %d\n", vmdkCount))
	sb.WriteString(fmt.Sprintf("  VMX files:  %d\n", vmxCount))
	sb.WriteString(fmt.Sprintf("  VMSN files: %d\n", vmsnCount))
	sb.WriteString(fmt.Sprintf("  Total size: %.1f TB\n", totalSizeGB/1024.0))
	return sb.String()
}

func createSimulationFiles(simulationDir string) int {
	count := 0
	// Create small simulation files that mimic VMDK structure (tiny files for safety)
	simVMs := []struct {
		Name      string
		Datastore string
	}{
		{"dc01-prod", "datastore1"},
		{"sql-prod-01", "datastore1"},
		{"web-app-01", "datastore2"},
		{"erp-prod", "datastore1"},
	}

	for _, vm := range simVMs {
		vmDir := filepath.Join(simulationDir, vm.Datastore, vm.Name)
		os.MkdirAll(vmDir, 0755)

		// Create small .vmdk simulation file (4KB each - NOT actual disk images)
		vmdkContent := generateSimulatedVMDKHeader(vm.Name)
		vmdkPath := filepath.Join(vmDir, vm.Name+".vmdk")
		os.WriteFile(vmdkPath, []byte(vmdkContent), 0644)
		count++

		// Create .vmx configuration file
		vmxContent := generateSimulatedVMXFile(vm.Name)
		vmxPath := filepath.Join(vmDir, vm.Name+".vmx")
		os.WriteFile(vmxPath, []byte(vmxContent), 0644)
		count++

		// Create .vmsn snapshot descriptor
		vmsnContent := fmt.Sprintf("# VMware Snapshot Descriptor (simulated)\nversion = 1\nnumSnapshots = 0\ncurrent = -1\n")
		vmsnPath := filepath.Join(vmDir, vm.Name+".vmsn")
		os.WriteFile(vmsnPath, []byte(vmsnContent), 0644)
		count++

		// Create .nvram file
		nvramContent := "NVRAM simulation data - not a real NVRAM file"
		nvramPath := filepath.Join(vmDir, vm.Name+".nvram")
		os.WriteFile(nvramPath, []byte(nvramContent), 0644)
		count++
	}

	return count
}

func generateSimulatedVMDKHeader(vmName string) string {
	return fmt.Sprintf(`# Disk DescriptorFile (SIMULATED - NOT REAL VMDK)
version=1
CID=fffffffe
parentCID=ffffffff
createType="vmfs"
# Extent description
RW 2097152 VMFS "%s-flat.vmdk"
# The Disk Data Base
ddb.virtualHWVersion = "20"
ddb.geometry.cylinders = "130"
ddb.geometry.heads = "16"
ddb.geometry.sectors = "63"
ddb.adapterType = "lsilogic"
ddb.thinProvisioned = "1"
ddb.uuid = "%s"
`, vmName, generateFakeUUID())
}

func generateSimulatedVMXFile(vmName string) string {
	return fmt.Sprintf(`.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "20"
displayName = "%s"
guestOS = "windows2019srv_64Guest"
memSize = "8192"
numvcpus = "4"
scsi0.virtualDev = "pvscsi"
scsi0:0.fileName = "%s.vmdk"
scsi0:0.present = "TRUE"
ethernet0.virtualDev = "vmxnet3"
ethernet0.networkName = "VM Network"
ethernet0.present = "TRUE"
`, vmName, vmName)
}

func simulateIntermittentEncryption(simulationDir string, targetFiles []targetFile) string {
	var sb strings.Builder
	sb.WriteString("=== Intermittent Encryption Simulation ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02T15:04:05Z")))
	sb.WriteString("Algorithm: ChaCha20-Poly1305 + Curve25519 (RansomHub)\n")
	sb.WriteString("Pattern: Encrypt 1MB, skip 11MB (intermittent - faster than full encryption)\n")
	sb.WriteString("Extension: .ransomhub\n\n")

	// Generate a simulated Curve25519 public key
	pubKey := generateFakePublicKey()
	sb.WriteString(fmt.Sprintf("Encryption Public Key: %s\n", pubKey))
	sb.WriteString("Key Exchange: Curve25519 ECDH\n\n")

	encryptedCount := 0
	var totalProcessed float64

	for _, f := range targetFiles {
		sb.WriteString(fmt.Sprintf("[ENCRYPT] %s\n", f.Path))
		sb.WriteString(fmt.Sprintf("  File size: %.1f GB | VM: %s\n", f.SizeGB, f.VMName))

		if f.SizeGB < 0.01 {
			// Small files: encrypt entirely
			sb.WriteString("  Mode: Full encryption (file < 10MB)\n")
			sb.WriteString(fmt.Sprintf("  [SIMULATED] Encrypted and renamed to %s.ransomhub\n\n", filepath.Base(f.Path)))
		} else {
			// Large files: intermittent encryption
			encryptedMB := int(f.SizeGB * 1024 / 12) // 1MB per 12MB chunk
			skippedMB := int(f.SizeGB*1024) - encryptedMB
			sb.WriteString(fmt.Sprintf("  Mode: Intermittent (1MB encrypt / 11MB skip)\n"))
			sb.WriteString(fmt.Sprintf("  Encrypted: %d MB | Skipped: %d MB | Total: %.0f MB\n", encryptedMB, skippedMB, f.SizeGB*1024))
			sb.WriteString(fmt.Sprintf("  Encryption speed: ~400 MB/s (ChaCha20 is fast)\n"))
			sb.WriteString(fmt.Sprintf("  [SIMULATED] Encrypted and renamed to %s.ransomhub\n\n", filepath.Base(f.Path)))
		}
		encryptedCount++
		totalProcessed += f.SizeGB
	}

	// Actually rename the simulation files to demonstrate the extension change
	renameSimulationFiles(simulationDir)

	sb.WriteString(fmt.Sprintf("=== Encryption Summary ===\n"))
	sb.WriteString(fmt.Sprintf("Files processed: %d\n", encryptedCount))
	sb.WriteString(fmt.Sprintf("Total data processed: %.1f TB\n", totalProcessed/1024.0))
	sb.WriteString(fmt.Sprintf("Actual encrypted data: ~%.1f GB (intermittent pattern)\n", totalProcessed/12.0))
	sb.WriteString(fmt.Sprintf("Time estimate: ~%.0f seconds (ChaCha20 @ 400 MB/s)\n", totalProcessed*1024/12.0/400.0))
	return sb.String()
}

func renameSimulationFiles(simulationDir string) {
	// Walk the simulation directory and rename files to .ransomhub extension
	filepath.Walk(simulationDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext == ".vmdk" || ext == ".vmx" || ext == ".vmsn" || ext == ".nvram" {
			newPath := path + ".ransomhub"
			os.Rename(path, newPath)
		}
		return nil
	})
}

func generateRansomNote() string {
	return `===================================================
                  RANSOMHUB
===================================================

Your network has been breached and all data was encrypted.

Personal data, financial reports, and important documents are ready to disclose.

To decrypt all the data and not allow the leakage of stolen data,
you must ensure that you will pay the ransom.

We are only interested in money and do not want to damage your reputation.

===================================================
WARNING! DO NOT:
  - Modify files or file names
  - Contact law enforcement or the FBI
  - Contact data recovery companies
  - Use antivirus or decryption tools

All of these actions will PERMANENTLY DAMAGE your data.
===================================================

CONTACT US:
  TOR Browser: http://ransomxxx[SIMULATED].onion
  Chat ID: [SIMULATED_CHAT_ID]

Deadline: 72 HOURS

If no contact is made within the deadline, your data
will be published on our blog for public access.

===================================================
[THIS IS A SIMULATED RANSOM NOTE FOR F0RT1KA TESTING]
[NO ACTUAL ENCRYPTION HAS OCCURRED]
===================================================
`
}

func simulateFreeSpaceWipe() string {
	var sb strings.Builder
	sb.WriteString("=== Free-Space Wipe Simulation (LockBit 5.0 Pattern) ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format("2006-01-02T15:04:05Z")))

	sb.WriteString("[*] Purpose: Overwrite free space to prevent forensic recovery\n")
	sb.WriteString("[*] Method: dd if=/dev/zero of=/vmfs/volumes/$ds/.fswipe bs=1M\n\n")

	datastores := []struct {
		Name   string
		FreeGB int
	}{
		{"datastore1", 2048},
		{"datastore2", 1024},
		{"datastore3", 4096},
	}

	for _, ds := range datastores {
		sb.WriteString(fmt.Sprintf("[WIPE] %s - %d GB free space\n", ds.Name, ds.FreeGB))
		sb.WriteString(fmt.Sprintf("  Command: dd if=/dev/zero of=/vmfs/volumes/%s/.fswipe bs=1M\n", ds.Name))
		sb.WriteString(fmt.Sprintf("  [SIMULATED] Writing zeros to fill %d GB free space\n", ds.FreeGB))
		sb.WriteString(fmt.Sprintf("  [SIMULATED] Free-space wipe complete, removing wipe file\n"))
		sb.WriteString(fmt.Sprintf("  [SIMULATED] rm /vmfs/volumes/%s/.fswipe\n\n", ds.Name))
	}

	sb.WriteString("[+] Free-space wipe complete on all datastores\n")
	sb.WriteString("[+] Forensic recovery of deleted/original files significantly impaired\n")
	return sb.String()
}

func generateEncryptionSummary(targetFiles []targetFile) string {
	var sb strings.Builder
	sb.WriteString("=== VMDK Encryption Summary ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format("2006-01-02T15:04:05Z")))

	sb.WriteString("Ransomware Variant: RansomHub (ChaCha20+Curve25519)\n")
	sb.WriteString("Encryption Mode: Intermittent (1MB encrypt / 11MB skip)\n")
	sb.WriteString("File Extension: .ransomhub\n\n")

	var totalSizeGB float64
	for _, f := range targetFiles {
		totalSizeGB += f.SizeGB
	}

	sb.WriteString(fmt.Sprintf("Files Encrypted: %d\n", len(targetFiles)))
	sb.WriteString(fmt.Sprintf("Total Virtual Disk Size: %.1f TB\n", totalSizeGB/1024.0))
	sb.WriteString(fmt.Sprintf("Actually Encrypted: ~%.1f GB (8.3%% of total - intermittent)\n", totalSizeGB/12.0))
	sb.WriteString(fmt.Sprintf("Ransom Notes Deployed: 15\n"))
	sb.WriteString(fmt.Sprintf("Free-Space Wiped: 3 datastores (7.2 TB)\n\n"))

	sb.WriteString("Impact:\n")
	sb.WriteString("  - ALL VMs unbootable (VMX/VMDK corrupted by encryption)\n")
	sb.WriteString("  - Recovery snapshots destroyed (Stage 3)\n")
	sb.WriteString("  - Free space wiped (prevents forensic recovery)\n")
	sb.WriteString("  - Data exfiltrated (Stage 4) for double extortion\n")
	sb.WriteString("  - Ransom demand: Typically $100K-$5M (sector-dependent)\n")

	return sb.String()
}

func generateFakeUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func generateFakePublicKey() string {
	data := make([]byte, 32)
	rand.Read(data)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func isBlockedError(err error) bool {
	errStr := strings.ToLower(err.Error())
	// Only match EDR/AV-specific indicators, NOT standard OS errors.
	// "permission denied" and "operation not permitted" are standard POSIX errors
	// from filesystem operations — not EDR blocks. On Linux, EDR blocks manifest
	// as process kills (SIGKILL), file quarantine (file disappears), or security
	// policy enforcement — never as simple EACCES/EPERM on mkdir/write.
	blockedPatterns := []string{
		"quarantined", "blocked by security", "blocked by endpoint",
		"malware detected", "threat detected", "security policy",
	}
	for _, pattern := range blockedPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}

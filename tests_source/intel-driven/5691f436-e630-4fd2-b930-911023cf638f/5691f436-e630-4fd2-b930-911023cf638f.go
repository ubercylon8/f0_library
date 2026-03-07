//go:build windows
// +build windows

/*
ID: 5691f436-e630-4fd2-b930-911023cf638f
NAME: APT34 Exchange Server Weaponization with Email-Based C2
TECHNIQUES: T1505.003, T1071.003, T1556.002, T1048.003
TACTICS: persistence, command-and-control, credential-access, exfiltration
SEVERITY: critical
TARGET: windows-endpoint
COMPLEXITY: high
THREAT_ACTOR: APT34
SUBCATEGORY: apt
TAGS: exchange-server, email-c2, password-filter-dll, iis-backdoor, credential-theft, apt34, oilrig, iranian-apt, stealhook, powerexchange
UNIT: response
CREATED: 2026-03-07
AUTHOR: sectest-builder
*/

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	_ "embed"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "5691f436-e630-4fd2-b930-911023cf638f"
	TEST_NAME = "APT34 Exchange Server Weaponization with Email-Based C2"
)

// Embed signed stage binaries (signed BEFORE embedding during build)
//go:embed 5691f436-e630-4fd2-b930-911023cf638f-T1505.003.exe
var stage1Binary []byte

//go:embed 5691f436-e630-4fd2-b930-911023cf638f-T1071.003.exe
var stage2Binary []byte

//go:embed 5691f436-e630-4fd2-b930-911023cf638f-T1556.002.exe
var stage3Binary []byte

//go:embed 5691f436-e630-4fd2-b930-911023cf638f-T1048.003.exe
var stage4Binary []byte

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
	Endpoint.Say("Threat Actor: APT34 / OilRig / Helix Kitten / Hazel Sandstorm")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Multi-stage architecture for technique-level detection")
	Endpoint.Say("")

	// Initialize logger with Schema v2.0 metadata
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "initial_access",
		Severity:   "critical",
		Techniques: []string{"T1505.003", "T1071.003", "T1556.002", "T1048.003"},
		Tactics:    []string{"persistence", "command-and-control", "credential-access", "exfiltration"},
		Score:      8.7,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.7,
			TechnicalSophistication: 2.8,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.7,
			LoggingObservability:    0.5,
		},
		Tags: []string{"multi-stage", "apt34", "oilrig", "exchange-server", "email-c2", "password-filter-dll", "iis-backdoor"},
	}

	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         600000,
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

	test()
}

func test() {
	// Define attack killchain matching APT34 Exchange weaponization TTP
	killchain := []KillchainStage{
		{
			ID:          1,
			Name:        "IIS Backdoor Deployment (CacheHttp.dll)",
			Technique:   "T1505.003",
			BinaryName:  fmt.Sprintf("%s-T1505.003.exe", TEST_UUID),
			BinaryData:  stage1Binary,
			Description: "Simulate deployment of CacheHttp.dll passive IIS backdoor module",
		},
		{
			ID:          2,
			Name:        "Email-Based C2 Channel (PowerExchange)",
			Technique:   "T1071.003",
			BinaryName:  fmt.Sprintf("%s-T1071.003.exe", TEST_UUID),
			BinaryData:  stage2Binary,
			Description: "Simulate PowerExchange email-based C2 with @@ subject markers",
		},
		{
			ID:          3,
			Name:        "Password Filter DLL Registration",
			Technique:   "T1556.002",
			BinaryName:  fmt.Sprintf("%s-T1556.002.exe", TEST_UUID),
			BinaryData:  stage3Binary,
			Description: "Register password filter DLL in LSA for cleartext credential interception",
		},
		{
			ID:          4,
			Name:        "STEALHOOK Data Exfiltration via Email",
			Technique:   "T1048.003",
			BinaryName:  fmt.Sprintf("%s-T1048.003.exe", TEST_UUID),
			BinaryData:  stage4Binary,
			Description: "Exfiltrate stolen data as email attachments via Exchange transport",
		},
	}

	// Phase 0: Extract all stage binaries
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries...", len(killchain))

	for _, stage := range killchain {
		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s", stage.BinaryName))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Extraction failed: %v", err))
			Endpoint.Say("")
			Endpoint.Say("FATAL: Failed to extract stage binary: %s", stage.BinaryName)
			time.Sleep(5 * time.Second)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
		Endpoint.Say("  [+] Extracted: %s (%d bytes)", stage.BinaryName, len(stage.BinaryData))
	}

	LogPhaseEnd(0, "success", fmt.Sprintf("Extracted %d stage binaries", len(killchain)))
	Endpoint.Say("    All stage binaries extracted successfully")
	Endpoint.Say("")

	// Initialize per-stage results for bundle fan-out
	stageResults := make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{
			Technique: stage.Technique,
			Name:      stage.Name,
			Severity:  "critical",
			Tactics:   []string{"persistence", "command-and-control", "credential-access", "exfiltration"},
			ExitCode:  0,
			Status:    "skipped",
		}
	}

	// Execute killchain sequentially
	Endpoint.Say("[*] Executing %d-stage APT34 attack killchain...", len(killchain))
	Endpoint.Say("")

	for idx, stage := range killchain {
		LogStageStart(stage.ID, stage.Technique, fmt.Sprintf("%s (%s)", stage.Name, stage.Technique))

		Endpoint.Say("=================================================================")
		Endpoint.Say("STAGE %d/%d: %s", stage.ID, len(killchain), stage.Name)
		Endpoint.Say("Technique: %s", stage.Technique)
		Endpoint.Say("Description: %s", stage.Description)
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		exitCode := executeStage(stage)

		if exitCode == 126 || exitCode == 105 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("EDR blocked %s (exit code: %d)", stage.Technique, exitCode)
			LogStageEnd(stage.ID, stage.Technique, "blocked", fmt.Sprintf("EDR blocked %s", stage.Technique))

			Endpoint.Say("")
			Endpoint.Say("=================================================================")
			Endpoint.Say("RESULT: PROTECTED")
			Endpoint.Say("=================================================================")
			Endpoint.Say("")
			Endpoint.Say("EDR successfully blocked the attack at stage %d:", stage.ID)
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
			Endpoint.Say("=================================================================")

			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("EDR blocked at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
			time.Sleep(5 * time.Second)
			Endpoint.Stop(Endpoint.ExecutionPrevented)

		} else if exitCode != 0 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit code %d", exitCode)
			LogStageEnd(stage.ID, stage.Technique, "error", fmt.Sprintf("Stage error: exit code %d", exitCode))

			Endpoint.Say("")
			Endpoint.Say("ERROR: Stage %d encountered an error (exit code %d)", stage.ID, exitCode)
			Endpoint.Say("  Technique: %s", stage.Technique)

			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %d (%s) failed with exit code %d", stage.ID, stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
			time.Sleep(5 * time.Second)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed successfully", stage.Technique)
		LogStageEnd(stage.ID, stage.Technique, "success", fmt.Sprintf("%s completed successfully", stage.Technique))
		Endpoint.Say("    Stage %d completed successfully", stage.ID)
		Endpoint.Say("")
	}

	// All stages succeeded = vulnerable
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: Complete APT34 attack chain executed without prevention")
	Endpoint.Say("")
	Endpoint.Say("All %d techniques executed successfully:", len(killchain))
	for _, stage := range killchain {
		Endpoint.Say("  - %s: %s", stage.Technique, stage.Name)
	}
	Endpoint.Say("")
	Endpoint.Say("The system allowed:")
	Endpoint.Say("  1. IIS backdoor module deployment (CacheHttp.dll)")
	Endpoint.Say("  2. Email-based C2 channel establishment (PowerExchange)")
	Endpoint.Say("  3. Password filter DLL registration for credential interception")
	Endpoint.Say("  4. Data exfiltration via email attachments (STEALHOOK)")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED:")
	Endpoint.Say("  - Review IIS module registrations")
	Endpoint.Say("  - Audit LSA Notification Packages registry keys")
	Endpoint.Say("  - Monitor Exchange transport for abnormal email patterns")
	Endpoint.Say("  - Implement application whitelisting for DLL loading")
	Endpoint.Say("=================================================================")

	SaveLog(Endpoint.Unprotected, "Complete APT34 killchain succeeded - all techniques executed")
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
	time.Sleep(5 * time.Second)
	Endpoint.Stop(Endpoint.Unprotected)
}

func extractStage(stage KillchainStage) error {
	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)

	stagePath := filepath.Join(targetDir, stage.BinaryName)
	if err := os.WriteFile(stagePath, stage.BinaryData, 0755); err != nil {
		return fmt.Errorf("failed to write %s: %v", stage.BinaryName, err)
	}

	LogFileDropped(stage.BinaryName, stagePath, int64(len(stage.BinaryData)), false)
	return nil
}

func executeStage(stage KillchainStage) int {
	stagePath := filepath.Join("c:\\F0", stage.BinaryName)

	// 5-minute timeout per stage
	timeout := 5 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, stagePath)
	cmd.Dir = "c:\\F0"

	// Capture stdout/stderr to both console and file
	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)
	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

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

	// Save raw output to file
	outputFilePath := filepath.Join("c:\\F0", fmt.Sprintf("%s_output.txt", stage.Technique))
	if writeErr := os.WriteFile(outputFilePath, outputBuffer.Bytes(), 0644); writeErr != nil {
		LogMessage("WARNING", "Output Capture", fmt.Sprintf("Failed to save output: %v", writeErr))
	} else {
		LogMessage("INFO", "Output Capture", fmt.Sprintf("Raw output saved to: %s (%d bytes)", outputFilePath, outputBuffer.Len()))
	}

	if ctx.Err() == context.DeadlineExceeded {
		Endpoint.Say("  Stage execution timeout (5 minutes exceeded)")
		LogMessage("ERROR", stage.Technique, "Stage timeout after 5 minutes")
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

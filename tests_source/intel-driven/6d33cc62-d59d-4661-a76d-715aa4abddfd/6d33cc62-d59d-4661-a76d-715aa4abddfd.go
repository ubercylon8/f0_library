// PII Exfiltration to External Inference Services — Multi-Stage Orchestrator
// F0RT1KA Security Testing Framework
//
// This orchestrator drives a 3-stage "shadow AI" data-governance killchain:
//   Stage 1 (T1552.001, T1119) — shadow-AI staging & API-key discovery
//   Stage 2 (T1005)            — synthetic canary PII collection
//   Stage 3 (T1567)            — exfiltration to real AI inference vendor hosts
//
// The adversary here is typically a well-meaning insider or an app integration,
// not malware. The test validates whether the org's DLP / CASB / egress-proxy
// controls detect or block PII heading to real AI vendor hosts. See
// docs/superpowers/specs/2026-07-07-pii-exfil-inference-services-design.md.
//
// Cross-platform: Windows + Linux. Platform-specific embed/name logic lives in
// orchestrator_embed_windows.go / orchestrator_embed_linux.go; LOG_DIR and
// ARTIFACT_DIR come from the per-platform test_logger_<os>.go files.

/*
ID: 6d33cc62-d59d-4661-a76d-715aa4abddfd
NAME: PII Exfiltration to External Inference Services
TECHNIQUES: T1552.001, T1119, T1005, T1567
TACTICS: credential-access, collection, exfiltration
SEVERITY: high
TARGET: windows-endpoint, linux-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: data-exfiltration
TAGS: shadow-ai, dlp, casb, pii, data-governance, exfiltration, canary
SOURCE_URL: N/A
UNIT: response
CREATED: 2026-07-07
AUTHOR: sectest-builder
*/

package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const (
	TEST_UUID = "6d33cc62-d59d-4661-a76d-715aa4abddfd"
	TEST_NAME = "PII Exfiltration to External Inference Services"
)

// Embedded gzip-compressed signed stage binaries. The //go:embed directives and
// the binary-name/extension helpers live in the per-platform orchestrator_embed_*.go
// files so the orchestrator builds cleanly for both Windows and Linux.
//   - stage1Compressed / stage2Compressed / stage3Compressed
//   - stageBinaryName(technique string) string
// are all provided by the platform embed file selected at build time.

// ==============================================================================
// STAGE DEFINITION
// ==============================================================================

// KillchainStage represents one technique-stage in the attack killchain.
// NOTE: deliberately NOT named "Stage" — that name is owned by test_logger.go.
type KillchainStage struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
}

// ==============================================================================
// MAIN
// ==============================================================================

func main() {
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "data_exfiltration",
		Severity:      "high",
		Techniques:    []string{"T1552.001", "T1119", "T1005", "T1567"},
		Tactics:       []string{"credential-access", "collection", "exfiltration"},
		Score:         7.8, // authoritative score per README.md / info.md (v2.1 rubric): Realism 5.2 + Structure 2.6
		RubricVersion: "v2.1",
		ScoreBreakdown: &ScoreBreakdown{
			// Legacy v1-dimension breakdown (retained for ES fields); the binding
			// v2.1 tiered breakdown lives in <uuid>_info.md. Sums to 7.8.
			RealWorldAccuracy:       2.4,
			TechnicalSophistication: 2.4,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.6,
			LoggingObservability:    0.4,
		},
		Tags: []string{"multi-stage", "shadow-ai", "dlp", "casb", "pii", "exfiltration", "canary"},
	}

	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         300000,
			MultiStageEnabled: true,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}()

	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Multi-Stage Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Purpose: validate DLP/CASB/egress coverage of PII heading to AI services")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	test()
}

// ==============================================================================
// TEST IMPLEMENTATION
// ==============================================================================

func test() {
	killchain := []KillchainStage{
		{
			ID:          1,
			Name:        "Shadow-AI Staging & Key Discovery",
			Technique:   "T1552.001",
			BinaryName:  stageBinaryName("T1552.001"),
			BinaryData:  stage1Compressed,
			Description: "Drop an ai-assistant tool artifact and scan env/config paths for AI-service API keys (also T1119 Automated Collection)",
		},
		{
			ID:          2,
			Name:        "Synthetic Canary PII Collection",
			Technique:   "T1005",
			BinaryName:  stageBinaryName("T1005"),
			BinaryData:  stage2Compressed,
			Description: "Generate format/checksum-valid synthetic canary PII (SSN, Luhn PAN, emails) and collect into an egress payload",
		},
		{
			ID:          3,
			Name:        "Exfiltration to Inference Services",
			Technique:   "T1567",
			BinaryName:  stageBinaryName("T1567"),
			BinaryData:  stage3Compressed,
			Description: "POST the canary PII over real TLS to OpenAI, Anthropic, Gemini and Copilot hosts (unauthenticated); classify leak vs. org-control block",
		},
	}

	// Phase 0: extract all stage binaries
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries to %s ...", len(killchain), LOG_DIR)

	for i, stage := range killchain {
		Endpoint.Say("    [%d/%d] Extracting %s (%s)", i+1, len(killchain), stage.BinaryName, stage.Technique)
		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s: %v", stage.BinaryName, err))
			Endpoint.Say("")
			Endpoint.Say("FATAL: Failed to extract stage binary: %s", stage.BinaryName)
			Endpoint.Say("    Error: %v", err)
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage extraction failed: %v", err))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}

	LogPhaseEnd(0, "success", fmt.Sprintf("Successfully extracted %d stage binaries", len(killchain)))
	Endpoint.Say("    All stage binaries extracted successfully")
	Endpoint.Say("")

	// Per-stage results for bundle fan-out
	stageSeverity := "high"
	stageTactics := []string{"credential-access", "collection", "exfiltration"}
	stageResults := make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{
			Technique: stage.Technique,
			Name:      stage.Name,
			Severity:  stageSeverity,
			Tactics:   stageTactics,
			ExitCode:  0,
			Status:    "skipped",
		}
	}

	Endpoint.Say("[*] Executing %d-stage shadow-AI exfiltration killchain...", len(killchain))
	Endpoint.Say("")

	for idx, stage := range killchain {
		LogPhaseStart(stage.ID, fmt.Sprintf("%s (%s)", stage.Name, stage.Technique))

		Endpoint.Say("=================================================================")
		Endpoint.Say("Stage %d/%d: %s", stage.ID, len(killchain), stage.Name)
		Endpoint.Say("Technique: %s", stage.Technique)
		Endpoint.Say("Description: %s", stage.Description)
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		exitCode := executeStage(stage)

		// Exit-code semantics (see stage sources + spec §4/§5):
		//   0   → stage's technique executed (for stage 3: PII LEAKED to a vendor)
		//   126 → org control intervened (positive block evidence) — PROTECTED
		//   999 → prerequisite/ambiguous error — inconclusive
		if exitCode == 126 || exitCode == 105 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("Org control intervened at %s (exit code: %d)", stage.Technique, exitCode)
			LogPhaseEnd(stage.ID, "blocked", fmt.Sprintf("Org control intervened at %s (exit code: %d)", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("=================================================================")
			Endpoint.Say("FINAL EVALUATION: Stage %d Intercepted", stage.ID)
			Endpoint.Say("=================================================================")
			Endpoint.Say("")
			Endpoint.Say("RESULT: PROTECTED")
			Endpoint.Say("")
			Endpoint.Say("An organizational control intervened at stage %d:", stage.ID)
			Endpoint.Say("  - Technique: %s", stage.Technique)
			Endpoint.Say("  - Stage: %s", stage.Name)
			Endpoint.Say("  - Exit Code: %d", exitCode)
			Endpoint.Say("")
			Endpoint.Say("Killchain Interrupted:")
			Endpoint.Say("  - Completed Stages: %d/%d", stage.ID-1, len(killchain))
			Endpoint.Say("  - Intercepted Stage: %d (%s)", stage.ID, stage.Technique)
			Endpoint.Say("  - Remaining Stages: %d (not executed)", len(killchain)-stage.ID)
			Endpoint.Say("")
			Endpoint.Say("Data-Governance Status: PII EGRESS CONTROLLED")
			Endpoint.Say("=================================================================")
			Endpoint.Say("")

			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Org control intervened at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)
			Endpoint.Stop(Endpoint.ExecutionPrevented)

		} else if exitCode != 0 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit code %d", exitCode)
			LogPhaseEnd(stage.ID, "error", fmt.Sprintf("Stage %s failed with exit code %d", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("ERROR: Stage %d could not complete (exit code %d)", stage.ID, exitCode)
			Endpoint.Say("    Technique: %s", stage.Technique)
			Endpoint.Say("")
			Endpoint.Say("This is inconclusive — NOT a protection verdict. Likely causes:")
			Endpoint.Say("  - ARTIFACT_DIR (%s) not provisioned/writable", ARTIFACT_DIR)
			Endpoint.Say("  - No network egress available at all")
			Endpoint.Say("  - An ambiguous response that is not affirmative block evidence")
			Endpoint.Say("")

			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %d (%s) failed with exit code %d", stage.ID, stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s executed", stage.Technique)
		LogPhaseEnd(stage.ID, "success", fmt.Sprintf("Stage %s executed", stage.Technique))
		Endpoint.Say("    Stage %d executed", stage.ID)
		Endpoint.Say("")
	}

	// All stages executed without an org control intervening → PII reached a vendor.
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: All Stages Completed")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("RESULT: UNPROTECTED (PII LEAKED)")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: Synthetic canary PII crossed the org boundary and reached")
	Endpoint.Say("at least one external AI inference vendor. No DLP/CASB/egress control fired.")
	Endpoint.Say("")
	Endpoint.Say("Killchain Summary:")
	for _, stage := range killchain {
		Endpoint.Say("  - Stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique)
	}
	Endpoint.Say("")
	Endpoint.Say("Data-Governance Impact: HIGH")
	Endpoint.Say("  - AI-service API keys discoverable on host")
	Endpoint.Say("  - Sensitive-record collection unimpeded")
	Endpoint.Say("  - PII egress to shadow-AI endpoints uncontrolled")
	Endpoint.Say("")
	Endpoint.Say("RECOMMENDED ACTION: enforce DLP/CASB inspection of AI-vendor egress")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d stages completed - canary PII reached an external inference service", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)
	Endpoint.Stop(Endpoint.Unprotected)
}

// ==============================================================================
// HELPERS
// ==============================================================================

// extractStage decompresses and writes a gzip-compressed stage binary to LOG_DIR.
func extractStage(stage KillchainStage) error {
	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", LOG_DIR, err)
	}

	binaryData, err := decompressGzip(stage.BinaryData)
	if err != nil {
		return fmt.Errorf("failed to decompress %s: %v", stage.BinaryName, err)
	}

	stagePath := filepath.Join(LOG_DIR, stage.BinaryName)
	if err := os.WriteFile(stagePath, binaryData, 0755); err != nil {
		return fmt.Errorf("failed to write %s: %v", stage.BinaryName, err)
	}

	LogFileDropped(stage.BinaryName, stagePath, int64(len(binaryData)), false)
	return nil
}

// decompressGzip decompresses gzip-compressed data in memory.
func decompressGzip(compressed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data: %v", err)
	}
	return decompressed, nil
}

// executeStage runs a stage binary and returns its exit code. Stage stdout/stderr
// is captured to both the console and LOG_DIR/<binary>_output.txt via io.MultiWriter
// (CLAUDE.md mandatory stdout/stderr capture pattern).
func executeStage(stage KillchainStage) int {
	stagePath := filepath.Join(LOG_DIR, stage.BinaryName)
	cmd := exec.Command(stagePath)

	outPath := filepath.Join(LOG_DIR, stage.BinaryName+"_output.txt")
	if outFile, ferr := os.Create(outPath); ferr == nil {
		defer outFile.Close()
		cmd.Stdout = io.MultiWriter(os.Stdout, outFile)
		cmd.Stderr = io.MultiWriter(os.Stderr, outFile)
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, exitCode, exitErr.Error())
			return exitCode
		}
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, err.Error())
		return 999
	}

	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}

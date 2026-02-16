//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// ==============================================================================
// VALIDATOR DEFINITIONS
// ==============================================================================

// ValidatorDef describes an embedded validator binary and its expected controls
type ValidatorDef struct {
	Name        string   // Short name (e.g., "defender")
	DisplayName string   // Human-readable name (e.g., "Microsoft Defender Configuration")
	Binary      []byte   // Embedded signed binary (populated via //go:embed)
	ControlIDs  []string // Expected control IDs for skip-marking on quarantine
}

// ==============================================================================
// VALIDATOR OUTPUT TYPES (mirrored from validator_output.go for orchestrator build)
// ==============================================================================

// ValidatorOutput is the JSON structure each validator binary writes to c:\F0\vr_<name>.json
type ValidatorOutput struct {
	Validator   string        `json:"validator"`
	Checks      []CheckOutput `json:"checks"`
	PassedCount int           `json:"passed_count"`
	FailedCount int           `json:"failed_count"`
	TotalChecks int           `json:"total_checks"`
	IsCompliant bool          `json:"is_compliant"`
}

// CheckOutput is a single check result in the validator output JSON
type CheckOutput struct {
	ControlID   string   `json:"control_id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Passed      bool     `json:"passed"`
	Expected    string   `json:"expected"`
	Actual      string   `json:"actual"`
	Details     string   `json:"details"`
	Severity    string   `json:"severity"`
	Techniques  []string `json:"techniques"`
	Tactics     []string `json:"tactics"`
}

// IsAdmin checks if the current process has administrator privileges
func IsAdmin() bool {
	_, err := exec.Command("net", "session").Output()
	return err == nil
}

// ==============================================================================
// BUNDLE RESULTS PROTOCOL (moved from check_utils.go)
// ==============================================================================

// ControlResult represents a single control's result for bundle_results.json
type ControlResult struct {
	ControlID    string   `json:"control_id"`
	ControlName  string   `json:"control_name"`
	Validator    string   `json:"validator"`
	ExitCode     int      `json:"exit_code"`
	Compliant    bool     `json:"compliant"`
	Severity     string   `json:"severity"`
	Category     string   `json:"category"`
	Subcategory  string   `json:"subcategory"`
	Techniques   []string `json:"techniques"`
	Tactics      []string `json:"tactics"`
	Expected     string   `json:"expected"`
	Actual       string   `json:"actual"`
	Details      string   `json:"details"`
	Skipped      bool     `json:"skipped"`
	ErrorMessage string   `json:"error_message"`
}

// BundleResults represents the complete bundle output written to bundle_results.json
type BundleResults struct {
	SchemaVersion     string          `json:"schema_version"`
	BundleID          string          `json:"bundle_id"`
	BundleName        string          `json:"bundle_name"`
	BundleCategory    string          `json:"bundle_category"`
	BundleSubcategory string          `json:"bundle_subcategory"`
	ExecutionID       string          `json:"execution_id"`
	StartedAt         string          `json:"started_at"`
	CompletedAt       string          `json:"completed_at"`
	OverallExitCode   int             `json:"overall_exit_code"`
	TotalControls     int             `json:"total_controls"`
	PassedControls    int             `json:"passed_controls"`
	FailedControls    int             `json:"failed_controls"`
	SkippedControls   int             `json:"skipped_controls"`
	Controls          []ControlResult `json:"controls"`
}

// WriteBundleResults writes bundle_results.json to c:\F0
func WriteBundleResults(results *BundleResults) error {
	results.CompletedAt = time.Now().UTC().Format(time.RFC3339)

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal bundle results: %v", err)
	}

	outputPath := filepath.Join(`c:\F0`, "bundle_results.json")
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write bundle results to %s: %v", outputPath, err)
	}

	return nil
}

// ==============================================================================
// VALIDATOR EXTRACT / QUARANTINE CHECK / EXECUTE
// ==============================================================================

// ExtractValidator writes an embedded validator binary to c:\F0\validator-<name>.exe
func ExtractValidator(name string, binary []byte) (string, error) {
	exePath := filepath.Join(`c:\F0`, fmt.Sprintf("validator-%s.exe", name))
	if err := os.WriteFile(exePath, binary, 0755); err != nil {
		return "", fmt.Errorf("failed to extract validator %s: %v", name, err)
	}
	return exePath, nil
}

// IsQuarantined checks if a file still exists after extraction (EDR may have removed it)
func IsQuarantined(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}

// ExecuteValidator runs a validator binary as a subprocess and returns its exit code
func ExecuteValidator(exePath string) (exitCode int, err error) {
	cmd := exec.Command(exePath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	err = cmd.Run()
	if err != nil {
		// Extract exit code from exec.ExitError
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 999, fmt.Errorf("failed to execute validator %s: %v", exePath, err)
	}
	return 0, nil
}

// ReadValidatorOutput reads and parses a validator's output JSON from c:\F0\vr_<name>.json
func ReadValidatorOutput(name string) (*ValidatorOutput, error) {
	outputPath := filepath.Join(`c:\F0`, fmt.Sprintf("vr_%s.json", name))
	data, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read validator output %s: %v", outputPath, err)
	}

	var output ValidatorOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse validator output %s: %v", outputPath, err)
	}

	return &output, nil
}

// MakeSkippedControls creates ControlResult entries for all controls of a quarantined validator
func MakeSkippedControls(vd ValidatorDef, category, subcategory, reason string) []ControlResult {
	controls := make([]ControlResult, len(vd.ControlIDs))
	for i, id := range vd.ControlIDs {
		controls[i] = ControlResult{
			ControlID:    id,
			ControlName:  fmt.Sprintf("%s (skipped)", vd.DisplayName),
			Validator:    vd.DisplayName,
			ExitCode:     0,
			Compliant:    false,
			Severity:     "medium",
			Category:     category,
			Subcategory:  subcategory,
			Skipped:      true,
			ErrorMessage: reason,
		}
	}
	return controls
}

// ConvertOutputToControls converts ValidatorOutput checks into ControlResult entries
func ConvertOutputToControls(validatorName, category, subcategory string, output *ValidatorOutput) []ControlResult {
	results := make([]ControlResult, 0, len(output.Checks))
	for _, check := range output.Checks {
		exitCode := 126 // compliant
		if !check.Passed {
			exitCode = 101 // non-compliant
		}

		results = append(results, ControlResult{
			ControlID:   check.ControlID,
			ControlName: check.Name,
			Validator:   validatorName,
			ExitCode:    exitCode,
			Compliant:   check.Passed,
			Severity:    check.Severity,
			Category:    category,
			Subcategory: subcategory,
			Techniques:  check.Techniques,
			Tactics:     check.Tactics,
			Expected:    check.Expected,
			Actual:      check.Actual,
			Details:     check.Details,
			Skipped:     false,
		})
	}
	return results
}

// CleanupValidator removes the extracted validator binary and its output JSON
func CleanupValidator(name string) {
	exePath := filepath.Join(`c:\F0`, fmt.Sprintf("validator-%s.exe", name))
	outputPath := filepath.Join(`c:\F0`, fmt.Sprintf("vr_%s.json", name))
	os.Remove(exePath)
	os.Remove(outputPath)
}

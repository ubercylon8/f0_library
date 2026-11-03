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

	cyberhygiene "f0_library/tests_source/cyber-hygiene/shared"
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
	ControlID      string                     `json:"control_id"`
	Name           string                     `json:"name"`
	Category       string                     `json:"category"`
	Description    string                     `json:"description"`
	Passed         bool                       `json:"passed"`
	Status         cyberhygiene.ControlStatus `json:"status"`
	Expected       string                     `json:"expected"`
	Actual         string                     `json:"actual"`
	Details        string                     `json:"details"`
	Severity       string                     `json:"severity"`
	Techniques     []string                   `json:"techniques"`
	Tactics        []string                   `json:"tactics"`
	Applicability  string                     `json:"applicability,omitempty"`
	EvidenceSource string                     `json:"evidence_source,omitempty"`
	ObservedAt     string                     `json:"observed_at,omitempty"`
	Remediation    string                     `json:"remediation,omitempty"`
	Evidence       map[string]interface{}     `json:"evidence,omitempty"`
}

// IsAdmin checks if the current process has administrator privileges
func IsAdmin() bool {
	_, err := exec.Command("net", "session").Output()
	return err == nil
}

// ==============================================================================
// BUNDLE RESULTS PROTOCOL (moved from check_utils.go)
// ==============================================================================

type ControlResult = cyberhygiene.ControlResult
type BundleResults = cyberhygiene.BundleResults

// WriteBundleResults writes bundle_results.json to c:\F0
func WriteBundleResults(results *BundleResults) error {
	cyberhygiene.FinalizeBundleResults(results)

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
			ControlID:      id,
			ControlName:    fmt.Sprintf("%s (skipped)", vd.DisplayName),
			Validator:      vd.DisplayName,
			Status:         cyberhygiene.StatusSkipped,
			Severity:       "medium",
			Category:       category,
			Subcategory:    subcategory,
			Skipped:        true,
			ErrorMessage:   reason,
			EvidenceSource: "orchestrator",
		}
	}
	return controls
}

// ConvertOutputToControls converts ValidatorOutput checks into ControlResult entries
func ConvertOutputToControls(validatorName, category, subcategory string, output *ValidatorOutput) []ControlResult {
	results := make([]ControlResult, 0, len(output.Checks))
	for _, check := range output.Checks {
		results = append(results, ControlResult{
			ControlID:      check.ControlID,
			ControlName:    check.Name,
			Validator:      validatorName,
			Compliant:      check.Passed,
			Status:         check.Status,
			Severity:       check.Severity,
			Category:       category,
			Subcategory:    subcategory,
			Techniques:     check.Techniques,
			Tactics:        check.Tactics,
			Expected:       check.Expected,
			Actual:         check.Actual,
			Details:        check.Details,
			Description:    check.Description,
			Applicability:  check.Applicability,
			EvidenceSource: check.EvidenceSource,
			ObservedAt:     check.ObservedAt,
			Remediation:    check.Remediation,
			Evidence:       check.Evidence,
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

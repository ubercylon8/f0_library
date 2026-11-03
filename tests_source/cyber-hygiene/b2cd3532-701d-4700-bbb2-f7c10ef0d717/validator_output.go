//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	cyberhygiene "f0_library/tests_source/cyber-hygiene/shared"
)

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

// WriteValidatorOutput writes the validator's results to c:\F0\vr_<name>.json
func WriteValidatorOutput(name string, result ValidatorResult) error {
	output := ValidatorOutput{
		Validator:   name,
		PassedCount: result.PassedCount,
		FailedCount: result.FailedCount,
		TotalChecks: result.TotalChecks,
		IsCompliant: result.IsCompliant,
	}

	output.Checks = make([]CheckOutput, len(result.Checks))
	for i, c := range result.Checks {
		output.Checks[i] = CheckOutput{
			ControlID:      c.ControlID,
			Name:           c.Name,
			Category:       c.Category,
			Description:    c.Description,
			Passed:         c.Passed,
			Status:         c.Status,
			Expected:       c.Expected,
			Actual:         c.Actual,
			Details:        c.Details,
			Severity:       c.Severity,
			Techniques:     c.Techniques,
			Tactics:        c.Tactics,
			Applicability:  c.Applicability,
			EvidenceSource: c.EvidenceSource,
			ObservedAt:     c.ObservedAt,
			Remediation:    c.Remediation,
			Evidence:       c.Evidence,
		}
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal validator output: %v", err)
	}

	outputPath := filepath.Join(`c:\F0`, fmt.Sprintf("vr_%s.json", name))
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write validator output to %s: %v", outputPath, err)
	}

	return nil
}

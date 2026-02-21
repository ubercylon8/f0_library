//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
			ControlID:   c.ControlID,
			Name:        c.Name,
			Category:    c.Category,
			Description: c.Description,
			Passed:      c.Passed,
			Expected:    c.Expected,
			Actual:      c.Actual,
			Details:     c.Details,
			Severity:    c.Severity,
			Techniques:  c.Techniques,
			Tactics:     c.Tactics,
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

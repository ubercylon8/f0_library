//go:build darwin
// +build darwin

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ValidatorOutputLocal is the JSON structure each validator binary writes to /tmp/F0/vr_<name>.json
// Named differently to avoid conflict with orchestrator_utils.go ValidatorOutput during validator builds
type ValidatorOutputLocal struct {
	Validator   string             `json:"validator"`
	Checks      []CheckOutputLocal `json:"checks"`
	PassedCount int                `json:"passed_count"`
	FailedCount int                `json:"failed_count"`
	TotalChecks int                `json:"total_checks"`
	IsCompliant bool               `json:"is_compliant"`
}

// CheckOutputLocal is a single check result in the validator output JSON
type CheckOutputLocal struct {
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

// WriteValidatorOutput writes the validator's results to /tmp/F0/vr_<name>.json
func WriteValidatorOutput(name string, result ValidatorResult) error {
	output := ValidatorOutputLocal{
		Validator:   name,
		PassedCount: result.PassedCount,
		FailedCount: result.FailedCount,
		TotalChecks: result.TotalChecks,
		IsCompliant: result.IsCompliant,
	}

	output.Checks = make([]CheckOutputLocal, len(result.Checks))
	for i, c := range result.Checks {
		output.Checks[i] = CheckOutputLocal{
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

	outputPath := filepath.Join("/tmp/F0", fmt.Sprintf("vr_%s.json", name))
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write validator output to %s: %v", outputPath, err)
	}

	return nil
}

//go:build windows
// +build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

// CheckResult represents the result of a single configuration check
type CheckResult struct {
	ControlID   string // Stable control ID e.g. "ITGC-AM-003"
	Name        string
	Category    string
	Description string
	Passed      bool
	Expected    string
	Actual      string
	Details     string
	Severity    string   // critical, high, medium, low, informational
	Techniques  []string // MITRE ATT&CK technique IDs
	Tactics     []string // MITRE ATT&CK tactic names (kebab-case)

	// ISACA ITGC auditor workpaper cross-references (omitempty for non-ITGC checks).
	CisaDomain     string                 // CISA 2024 ECO domain
	CobitObjective string                 // COBIT 2019 management objective
	CisV8Mapping   string                 // CIS Controls v8 mapping
	ManualResidual string                 // Auditor manual residual procedure
	Evidence       map[string]interface{} // Control-specific structured evidence
}

// ValidatorResult represents the result of a complete validator (group of checks)
type ValidatorResult struct {
	Name        string
	Checks      []CheckResult
	PassedCount int
	FailedCount int
	TotalChecks int
	IsCompliant bool
}

// RunPowerShell executes a PowerShell command and returns the output
func RunPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("PowerShell error: %v, stderr: %s", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}

// ParseGraphJSON parses JSON output from PowerShell into a slice of maps.
// Handles both single objects and arrays.
func ParseGraphJSON(jsonStr string) ([]map[string]interface{}, error) {
	jsonStr = strings.TrimSpace(jsonStr)
	if jsonStr == "" || jsonStr == "null" {
		return nil, nil
	}

	// Try parsing as array first
	var arr []map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &arr); err == nil {
		return arr, nil
	}

	// Try parsing as single object
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &obj); err == nil {
		return []map[string]interface{}{obj}, nil
	}

	return nil, fmt.Errorf("failed to parse JSON: %.200s", jsonStr)
}

// ParseGraphJSONSingle parses JSON output into a single map.
func ParseGraphJSONSingle(jsonStr string) (map[string]interface{}, error) {
	jsonStr = strings.TrimSpace(jsonStr)
	if jsonStr == "" || jsonStr == "null" {
		return nil, nil
	}

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	return obj, nil
}

// GetNestedString safely extracts a nested string value from a map using dot notation.
func GetNestedString(data map[string]interface{}, path string) string {
	parts := strings.Split(path, ".")
	current := interface{}(data)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return ""
		}
	}

	if s, ok := current.(string); ok {
		return s
	}
	if current != nil {
		return fmt.Sprintf("%v", current)
	}
	return ""
}

// GetNestedBool safely extracts a nested boolean value from a map.
func GetNestedBool(data map[string]interface{}, path string) (bool, bool) {
	parts := strings.Split(path, ".")
	current := interface{}(data)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return false, false
		}
	}

	if b, ok := current.(bool); ok {
		return b, true
	}
	return false, false
}

// GetNestedSlice safely extracts a nested slice from a map.
func GetNestedSlice(data map[string]interface{}, path string) []interface{} {
	parts := strings.Split(path, ".")
	current := interface{}(data)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return nil
		}
	}

	if s, ok := current.([]interface{}); ok {
		return s
	}
	return nil
}

// SliceContainsString checks if a []interface{} contains a specific string.
func SliceContainsString(slice []interface{}, target string) bool {
	for _, item := range slice {
		if s, ok := item.(string); ok && strings.EqualFold(s, target) {
			return true
		}
	}
	return false
}

// AggregateValidatorResults calculates pass/fail counts for a validator
func AggregateValidatorResults(checks []CheckResult) (passed, failed int) {
	for _, check := range checks {
		if check.Passed {
			passed++
		} else {
			failed++
		}
	}
	return passed, failed
}

// FormatCheckResult formats a check result for display
func FormatCheckResult(result CheckResult) string {
	status := "[PASS]"
	if !result.Passed {
		status = "[FAIL]"
	}

	if result.Details != "" {
		return fmt.Sprintf("       \u251c\u2500 %s %s: %s", status, result.Name, result.Details)
	}
	return fmt.Sprintf("       \u251c\u2500 %s %s", status, result.Name)
}

// FormatLastCheckResult formats the last check result with end connector
func FormatLastCheckResult(result CheckResult) string {
	status := "[PASS]"
	if !result.Passed {
		status = "[FAIL]"
	}

	if result.Details != "" {
		return fmt.Sprintf("       \u2514\u2500 %s %s: %s", status, result.Name, result.Details)
	}
	return fmt.Sprintf("       \u2514\u2500 %s %s", status, result.Name)
}

// BoolToEnabledDisabled converts boolean to "Enabled"/"Disabled" string
func BoolToEnabledDisabled(b bool) string {
	if b {
		return "Enabled"
	}
	return "Disabled"
}

// BoolToYesNo converts boolean to "Yes"/"No" string
func BoolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// CheckRegistryDWORD reads a DWORD value from the Windows registry and compares it to expected.
// Returns (actualValue, exists, error).
func CheckRegistryDWORD(keyPath, valueName string) (uint32, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return 0, false, fmt.Errorf("failed to open registry key %s: %v", keyPath, err)
	}
	defer k.Close()

	val, _, err := k.GetIntegerValue(valueName)
	if err != nil {
		return 0, false, nil // Value does not exist
	}

	return uint32(val), true, nil
}

// ==============================================================================
// BUNDLE RESULTS PROTOCOL
// ==============================================================================
//
// BundleResults and ControlResult structs are defined in test_logger.go.
// This file provides the functions that operate on those types.
// ==============================================================================

// CollectControlResults converts a validator's CheckResults into flat ControlResult slice
func CollectControlResults(validatorName, category, subcategory string, checks []CheckResult) []ControlResult {
	results := make([]ControlResult, 0, len(checks))
	for _, check := range checks {
		exitCode := 126 // compliant
		if !check.Passed {
			exitCode = 101 // non-compliant
		}

		results = append(results, ControlResult{
			ControlID:      check.ControlID,
			ControlName:    check.Name,
			Validator:      validatorName,
			ExitCode:       exitCode,
			Compliant:      check.Passed,
			Severity:       check.Severity,
			Category:       category,
			Subcategory:    subcategory,
			Techniques:     check.Techniques,
			Tactics:        check.Tactics,
			Expected:       check.Expected,
			Actual:         check.Actual,
			Details:        check.Details,
			Skipped:        false,
			CisaDomain:     check.CisaDomain,
			CobitObjective: check.CobitObjective,
			CisV8Mapping:   check.CisV8Mapping,
			ManualResidual: check.ManualResidual,
			Evidence:       check.Evidence,
		})
	}
	return results
}

// CollectSkippedControlResults creates skipped ControlResult entries for checks that could not run
func CollectSkippedControlResults(validatorName, category, subcategory, reason string, checks []CheckResult) []ControlResult {
	results := make([]ControlResult, 0, len(checks))
	for _, check := range checks {
		results = append(results, ControlResult{
			ControlID:    check.ControlID,
			ControlName:  check.Name,
			Validator:    validatorName,
			ExitCode:     0,
			Compliant:    false,
			Severity:     check.Severity,
			Category:     category,
			Subcategory:  subcategory,
			Techniques:   check.Techniques,
			Tactics:      check.Tactics,
			Expected:     check.Expected,
			Actual:       "Skipped",
			Details:      reason,
			Skipped:      true,
			ErrorMessage: reason,
		})
	}
	return results
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

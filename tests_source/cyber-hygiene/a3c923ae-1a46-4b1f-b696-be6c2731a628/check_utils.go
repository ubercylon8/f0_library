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
	ControlID   string   // Stable control ID e.g. "CH-DEF-001"
	Name        string
	Category    string
	Description string
	Passed      bool
	Expected    string
	Actual      string
	Details     string
	Severity    string   // critical, high, medium, low
	Techniques  []string // MITRE ATT&CK technique IDs
	Tactics     []string // MITRE ATT&CK tactic names (kebab-case)
}

// ValidatorResult represents the result of a complete validator (group of checks)
type ValidatorResult struct {
	Name         string
	Checks       []CheckResult
	PassedCount  int
	FailedCount  int
	TotalChecks  int
	IsCompliant  bool
}

// CheckRegistryDWORD checks if a DWORD registry value matches expected value
func CheckRegistryDWORD(rootKey registry.Key, path, valueName string, expected uint64) (bool, uint64, error) {
	key, err := registry.OpenKey(rootKey, path, registry.QUERY_VALUE)
	if err != nil {
		return false, 0, fmt.Errorf("failed to open registry key: %v", err)
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue(valueName)
	if err != nil {
		return false, 0, fmt.Errorf("failed to read value: %v", err)
	}

	return val == expected, val, nil
}

// CheckRegistryDWORDMinimum checks if a DWORD registry value is at least the expected value
func CheckRegistryDWORDMinimum(rootKey registry.Key, path, valueName string, minimum uint64) (bool, uint64, error) {
	key, err := registry.OpenKey(rootKey, path, registry.QUERY_VALUE)
	if err != nil {
		return false, 0, fmt.Errorf("failed to open registry key: %v", err)
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue(valueName)
	if err != nil {
		return false, 0, fmt.Errorf("failed to read value: %v", err)
	}

	return val >= minimum, val, nil
}

// CheckRegistryDWORDMaximum checks if a DWORD registry value is at most the expected value
func CheckRegistryDWORDMaximum(rootKey registry.Key, path, valueName string, maximum uint64) (bool, uint64, error) {
	key, err := registry.OpenKey(rootKey, path, registry.QUERY_VALUE)
	if err != nil {
		return false, 0, fmt.Errorf("failed to open registry key: %v", err)
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue(valueName)
	if err != nil {
		return false, 0, fmt.Errorf("failed to read value: %v", err)
	}

	return val <= maximum, val, nil
}

// CheckRegistryString checks if a string registry value matches expected value
func CheckRegistryString(rootKey registry.Key, path, valueName, expected string) (bool, string, error) {
	key, err := registry.OpenKey(rootKey, path, registry.QUERY_VALUE)
	if err != nil {
		return false, "", fmt.Errorf("failed to open registry key: %v", err)
	}
	defer key.Close()

	val, _, err := key.GetStringValue(valueName)
	if err != nil {
		return false, "", fmt.Errorf("failed to read value: %v", err)
	}

	return strings.EqualFold(val, expected), val, nil
}

// CheckRegistryExists checks if a registry key or value exists
func CheckRegistryExists(rootKey registry.Key, path, valueName string) (bool, error) {
	key, err := registry.OpenKey(rootKey, path, registry.QUERY_VALUE)
	if err != nil {
		return false, nil // Key doesn't exist
	}
	defer key.Close()

	if valueName == "" {
		return true, nil // Key exists
	}

	_, _, err = key.GetValue(valueName, nil)
	if err != nil {
		return false, nil // Value doesn't exist
	}

	return true, nil
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

// RunCommand executes a command and returns the output
func RunCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("command error: %v, stderr: %s", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}

// ParseKeyValueOutput parses output in "Key: Value" format
func ParseKeyValueOutput(output string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, ":"); idx != -1 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			result[key] = value
		}
	}

	return result
}

// CheckServiceStatus checks if a Windows service exists and its start type
func CheckServiceStatus(serviceName string) (exists bool, running bool, startType uint32, err error) {
	script := fmt.Sprintf(`
		$svc = Get-Service -Name '%s' -ErrorAction SilentlyContinue
		if ($svc) {
			$startup = (Get-WmiObject -Class Win32_Service -Filter "Name='%s'").StartMode
			Write-Output "EXISTS:TRUE"
			Write-Output "RUNNING:$($svc.Status -eq 'Running')"
			Write-Output "STARTTYPE:$startup"
		} else {
			Write-Output "EXISTS:FALSE"
		}
	`, serviceName, serviceName)

	output, err := RunPowerShell(script)
	if err != nil {
		return false, false, 0, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "EXISTS:") {
			exists = strings.Contains(line, "TRUE")
		} else if strings.HasPrefix(line, "RUNNING:") {
			running = strings.Contains(line, "True")
		} else if strings.HasPrefix(line, "STARTTYPE:") {
			startTypeStr := strings.TrimPrefix(line, "STARTTYPE:")
			switch strings.TrimSpace(startTypeStr) {
			case "Disabled":
				startType = 4
			case "Manual":
				startType = 3
			case "Auto":
				startType = 2
			case "Boot":
				startType = 0
			case "System":
				startType = 1
			}
		}
	}

	return exists, running, startType, nil
}

// IsAdmin checks if the current process has administrator privileges
func IsAdmin() bool {
	_, err := exec.Command("net", "session").Output()
	return err == nil
}

// FormatCheckResult formats a check result for display
func FormatCheckResult(result CheckResult) string {
	status := "[PASS]"
	if !result.Passed {
		status = "[FAIL]"
	}

	if result.Details != "" {
		return fmt.Sprintf("       ├─ %s %s: %s", status, result.Name, result.Details)
	}
	return fmt.Sprintf("       ├─ %s %s", status, result.Name)
}

// FormatLastCheckResult formats the last check result with end connector
func FormatLastCheckResult(result CheckResult) string {
	status := "[PASS]"
	if !result.Passed {
		status = "[FAIL]"
	}

	if result.Details != "" {
		return fmt.Sprintf("       └─ %s %s: %s", status, result.Name, result.Details)
	}
	return fmt.Sprintf("       └─ %s %s", status, result.Name)
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
	SchemaVersion    string          `json:"schema_version"`
	BundleID         string          `json:"bundle_id"`
	BundleName       string          `json:"bundle_name"`
	BundleCategory   string          `json:"bundle_category"`
	BundleSubcategory string         `json:"bundle_subcategory"`
	ExecutionID      string          `json:"execution_id"`
	StartedAt        string          `json:"started_at"`
	CompletedAt      string          `json:"completed_at"`
	OverallExitCode  int             `json:"overall_exit_code"`
	TotalControls    int             `json:"total_controls"`
	PassedControls   int             `json:"passed_controls"`
	FailedControls   int             `json:"failed_controls"`
	Controls         []ControlResult `json:"controls"`
}

// CollectControlResults converts a validator's CheckResults into flat ControlResult slice
func CollectControlResults(validatorName, category, subcategory string, checks []CheckResult) []ControlResult {
	results := make([]ControlResult, 0, len(checks))
	for _, check := range checks {
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

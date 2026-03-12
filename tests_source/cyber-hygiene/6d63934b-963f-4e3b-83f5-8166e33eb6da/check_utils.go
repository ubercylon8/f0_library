//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// CheckResult represents the result of a single configuration check
type CheckResult struct {
	ControlID   string   // Stable control ID e.g. "CH-CM1-001"
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
	Name        string
	Checks      []CheckResult
	PassedCount int
	FailedCount int
	TotalChecks int
	IsCompliant bool
}

// RunBash executes a bash command and returns stdout
func RunBash(script string) (string, error) {
	cmd := exec.Command("/bin/bash", "-c", script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("bash error: %v, stderr: %s", err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

// RunCommand executes a command and returns stdout (allows non-zero exit)
func RunCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return strings.TrimSpace(stdout.String()), fmt.Errorf("command error: %v, stderr: %s", err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

// RunCommandCombined executes a command and returns combined stdout+stderr
func RunCommandCombined(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// ReadDefaultsDomain reads a macOS defaults domain key value
// e.g., ReadDefaultsDomain("/Library/Preferences/com.apple.alf", "globalstate")
func ReadDefaultsDomain(domain, key string) (string, error) {
	cmd := exec.Command("defaults", "read", domain, key)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("defaults read error for %s %s: %v, stderr: %s", domain, key, err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

// ReadDefaultsByHost reads user-level defaults by currentHost domain
func ReadDefaultsByHost(domain, key string) (string, error) {
	cmd := exec.Command("defaults", "-currentHost", "read", domain, key)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("defaults -currentHost read error for %s %s: %v", domain, key, err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// CheckSystemSetup checks a systemsetup setting
func CheckSystemSetup(flag string) (string, error) {
	cmd := exec.Command("systemsetup", flag)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("systemsetup error for %s: %v, stderr: %s", flag, err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

// FileExists checks if a file or directory exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsRunningAsRoot checks if the current process is running as root
func IsRunningAsRoot() bool {
	return os.Getuid() == 0
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

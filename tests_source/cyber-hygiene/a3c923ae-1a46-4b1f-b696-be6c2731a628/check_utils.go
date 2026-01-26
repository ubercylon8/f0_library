//go:build windows
// +build windows

package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// CheckResult represents the result of a single configuration check
type CheckResult struct {
	Name        string
	Category    string
	Description string
	Passed      bool
	Expected    string
	Actual      string
	Details     string
	Severity    string // critical, high, medium, low
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

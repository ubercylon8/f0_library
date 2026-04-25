//go:build windows
// +build windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// CheckResult represents the result of a single configuration check
type CheckResult struct {
	ControlID   string // Stable control ID e.g. "CH-IEP-001"
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

// CheckRegistrySubkeys enumerates subkey names under a registry path
func CheckRegistrySubkeys(rootKey registry.Key, path string) ([]string, error) {
	key, err := registry.OpenKey(rootKey, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("failed to open registry key: %v", err)
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate subkeys: %v", err)
	}

	return names, nil
}

// CheckDirectoryExists checks if a directory exists and optionally if it is non-empty
func CheckDirectoryExists(path string) (exists bool, nonEmpty bool) {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false, false
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return true, false
	}

	return true, len(entries) > 0
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

// NOTE: BundleResults, ControlResult, CollectControlResults, WriteBundleResults
// have been moved to orchestrator_utils.go for the multi-binary architecture.
// Validator binaries use validator_output.go instead.

// ==============================================================================
// DSREGCMD HELPERS
// ==============================================================================

// DsregcmdSection represents a parsed section from dsregcmd /status output
type DsregcmdSection struct {
	Name   string
	Values map[string]string
}

// DsregcmdOutput holds the full parsed dsregcmd /status output
type DsregcmdOutput struct {
	Sections  []DsregcmdSection
	RawOutput string
}

var (
	dsregcmdCache *DsregcmdOutput
	dsregcmdOnce  sync.Once
	dsregcmdErr   error
)

// RunDsregcmd executes dsregcmd /status once and caches the parsed output
func RunDsregcmd() (*DsregcmdOutput, error) {
	dsregcmdOnce.Do(func() {
		output, err := RunCommand("dsregcmd", "/status")
		if err != nil {
			dsregcmdErr = fmt.Errorf("failed to run dsregcmd /status: %v", err)
			return
		}

		dsregcmdCache = parseDsregcmdOutput(output)
	})

	return dsregcmdCache, dsregcmdErr
}

// parseDsregcmdOutput parses the dsregcmd /status output into sections
// Sections are delimited by lines containing +------
func parseDsregcmdOutput(output string) *DsregcmdOutput {
	result := &DsregcmdOutput{
		RawOutput: output,
		Sections:  []DsregcmdSection{},
	}

	lines := strings.Split(output, "\n")
	var currentSection *DsregcmdSection

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		// Detect section delimiter: +------...------+
		if strings.HasPrefix(line, "+") && strings.Contains(line, "---") {
			// Next non-empty line is the section header
			if i+1 < len(lines) {
				headerLine := strings.TrimSpace(lines[i+1])
				// Skip the closing delimiter line
				if i+2 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+2]), "+") {
					i += 2
				}

				// Strip leading/trailing | characters
				headerLine = strings.Trim(headerLine, "|")
				headerLine = strings.TrimSpace(headerLine)

				if headerLine != "" {
					if currentSection != nil {
						result.Sections = append(result.Sections, *currentSection)
					}
					currentSection = &DsregcmdSection{
						Name:   headerLine,
						Values: make(map[string]string),
					}
				}
			}
			continue
		}

		// Parse key : value lines within current section
		if currentSection != nil && strings.Contains(line, " : ") {
			parts := strings.SplitN(line, " : ", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				currentSection.Values[key] = value
			}
		}
	}

	// Don't forget the last section
	if currentSection != nil {
		result.Sections = append(result.Sections, *currentSection)
	}

	return result
}

// GetDsregcmdValue retrieves a value from a specific dsregcmd section
// Returns the value and whether it was found
func GetDsregcmdValue(sectionName, key string) (string, bool) {
	dsreg, err := RunDsregcmd()
	if err != nil || dsreg == nil {
		return "", false
	}

	for _, section := range dsreg.Sections {
		if strings.Contains(strings.ToLower(section.Name), strings.ToLower(sectionName)) {
			if val, ok := section.Values[key]; ok {
				return val, true
			}
		}
	}

	return "", false
}

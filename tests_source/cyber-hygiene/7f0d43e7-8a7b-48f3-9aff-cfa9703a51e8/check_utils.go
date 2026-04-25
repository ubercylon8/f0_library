//go:build linux
// +build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// CheckResult represents the result of a single configuration check
type CheckResult struct {
	ControlID   string // Stable control ID e.g. "CH-CL1-001"
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
	cmd := exec.Command("bash", "-c", script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("bash error: %v, stderr: %s", err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

// RunBashIgnoreError executes a bash command and returns stdout, ignoring exit code errors
func RunBashIgnoreError(script string) string {
	cmd := exec.Command("bash", "-c", script)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &bytes.Buffer{}
	_ = cmd.Run()
	return strings.TrimSpace(stdout.String())
}

// CheckSysctl checks a sysctl value
func CheckSysctl(key string) (string, error) {
	output, err := RunBash(fmt.Sprintf("sysctl -n %s 2>/dev/null", key))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

// CheckServiceActive checks if a systemd service is active
func CheckServiceActive(service string) bool {
	out := RunBashIgnoreError(fmt.Sprintf("systemctl is-active %s 2>/dev/null", service))
	return strings.TrimSpace(out) == "active"
}

// CheckServiceEnabled checks if a systemd service is enabled
func CheckServiceEnabled(service string) bool {
	out := RunBashIgnoreError(fmt.Sprintf("systemctl is-enabled %s 2>/dev/null", service))
	return strings.TrimSpace(out) == "enabled"
}

// CheckSSHConfig reads an SSH config value from /etc/ssh/sshd_config
// Returns the value of the first matching non-commented line
func CheckSSHConfig(key string) (string, error) {
	// Parse sshd_config, ignoring comments and leading whitespace
	script := fmt.Sprintf(`grep -iE "^\s*%s\s" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}'`, key)
	return RunBash(script)
}

// CheckModuleBlacklisted checks if a kernel module is blacklisted via modprobe.d
func CheckModuleBlacklisted(module string) bool {
	out := RunBashIgnoreError(fmt.Sprintf(
		`grep -r -l "blacklist %s\|install %s /bin/true\|install %s /bin/false" /etc/modprobe.d/ 2>/dev/null | head -1`,
		module, module, module))
	return strings.TrimSpace(out) != ""
}

// CheckModuleLoaded checks if a kernel module is currently loaded
func CheckModuleLoaded(module string) bool {
	out := RunBashIgnoreError(fmt.Sprintf("lsmod | grep -w %s 2>/dev/null", module))
	return strings.TrimSpace(out) != ""
}

// DetectDistro returns "debian", "rhel", or "unknown"
func DetectDistro() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	content := strings.ToLower(string(data))
	if strings.Contains(content, "debian") || strings.Contains(content, "ubuntu") {
		return "debian"
	}
	if strings.Contains(content, "rhel") || strings.Contains(content, "centos") ||
		strings.Contains(content, "rocky") || strings.Contains(content, "alma") ||
		strings.Contains(content, "fedora") {
		return "rhel"
	}
	return "unknown"
}

// CheckFilePermissions checks if a file has at most the given permissions
func CheckFilePermissions(path string, maxPerm os.FileMode) (bool, os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, 0, err
	}
	perm := info.Mode().Perm()
	// Check that the file has no MORE permissions than maxPerm
	// i.e., no bit set in perm that is not set in maxPerm
	return (perm & ^maxPerm) == 0, perm, nil
}

// CheckMountOption checks if a mount point has a specific option
func CheckMountOption(mountPoint, option string) bool {
	out := RunBashIgnoreError(fmt.Sprintf(
		`grep -E "^[^ ]+ %s " /proc/mounts 2>/dev/null | head -1`,
		mountPoint))
	if out == "" {
		return false
	}
	// Options are the 4th field in /proc/mounts
	fields := strings.Fields(out)
	if len(fields) < 4 {
		return false
	}
	options := strings.Split(fields[3], ",")
	for _, opt := range options {
		if opt == option {
			return true
		}
	}
	return false
}

// CheckMountPointExists checks if a mount point is separately mounted
func CheckMountPointExists(mountPoint string) bool {
	out := RunBashIgnoreError(fmt.Sprintf(
		`grep -E "^[^ ]+ %s " /proc/mounts 2>/dev/null | head -1`,
		mountPoint))
	return strings.TrimSpace(out) != ""
}

// ParseIntSafe safely parses a string to int, returning 0 on error
func ParseIntSafe(s string) int {
	val, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return val
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

// IsAdmin checks if running as root
func IsAdmin() bool {
	return os.Getuid() == 0
}

// BoolToYesNo converts boolean to "Yes"/"No" string
func BoolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// truncateLongOutput limits output to maxLines and adds ellipsis
func truncateLongOutput(output string, maxLines int) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) <= maxLines {
		return output
	}
	return strings.Join(lines[:maxLines], "\n") + "\n..."
}

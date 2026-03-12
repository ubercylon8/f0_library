//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// RunAccessCtlChecks performs CIS Linux L1 access control checks
func RunAccessCtlChecks() ValidatorResult {
	checks := []CheckResult{
		checkSudoNoPassword(),
		checkSudoLogging(),
		checkPasswordHashing(),
		checkPasswordMinLength(),
		checkRootAccountLocked(),
		checkInactiveUserLockout(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Access Control",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkSudoNoPassword verifies no NOPASSWD entries in sudoers
// CIS 5.3.4 - Ensure users must provide a password for privilege escalation
func checkSudoNoPassword() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-025",
		Name:        "No sudo NOPASSWD",
		Category:    "accessctl",
		Description: "Verify no NOPASSWD entries exist in /etc/sudoers or /etc/sudoers.d/",
		Severity:    "high",
		Expected:    "No NOPASSWD entries in sudoers configuration",
		Techniques:  []string{"T1548.003"},
		Tactics:     []string{"privilege-escalation"},
	}

	// Check main sudoers and sudoers.d directory
	nopasswdEntries := RunBashIgnoreError(
		`grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | grep -v "#.*NOPASSWD"`)

	if strings.TrimSpace(nopasswdEntries) == "" {
		result.Passed = true
		result.Actual = "No NOPASSWD entries found"
		result.Details = "All sudo commands require password authentication"
	} else {
		lineCount := len(strings.Split(strings.TrimSpace(nopasswdEntries), "\n"))
		result.Passed = false
		result.Actual = fmt.Sprintf("%d NOPASSWD entries found", lineCount)
		result.Details = fmt.Sprintf("NOPASSWD entries allow passwordless privilege escalation:\n%s",
			truncateLongOutput(nopasswdEntries, 3))
	}

	return result
}

// checkSudoLogging verifies sudo logging is configured
// CIS 5.3.5 - Ensure sudo log file exists
func checkSudoLogging() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-026",
		Name:        "sudo Logging Enabled",
		Category:    "accessctl",
		Description: "Verify sudo logging is configured via Defaults logfile or log_output",
		Severity:    "medium",
		Expected:    "Defaults logfile or log_output configured in sudoers",
		Techniques:  []string{"T1548.003"},
		Tactics:     []string{"privilege-escalation"},
	}

	// Check for log directives
	logfile := RunBashIgnoreError(
		`grep -r "Defaults.*logfile" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#"`)
	logOutput := RunBashIgnoreError(
		`grep -r "Defaults.*log_output" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#"`)
	logInput := RunBashIgnoreError(
		`grep -r "Defaults.*log_input" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#"`)

	features := []string{}
	if strings.TrimSpace(logfile) != "" {
		features = append(features, "logfile")
	}
	if strings.TrimSpace(logOutput) != "" {
		features = append(features, "log_output")
	}
	if strings.TrimSpace(logInput) != "" {
		features = append(features, "log_input")
	}

	// Also check if journald captures sudo
	journaldSudo := RunBashIgnoreError("journalctl _COMM=sudo --no-pager -n 1 2>/dev/null")
	if strings.TrimSpace(journaldSudo) != "" {
		features = append(features, "journald")
	}

	if len(features) > 0 {
		result.Passed = true
		result.Actual = fmt.Sprintf("Logging via: %s", strings.Join(features, ", "))
		result.Details = "sudo activity is being logged"
	} else {
		result.Passed = false
		result.Actual = "No explicit sudo logging configured"
		result.Details = "No logfile, log_output, or log_input directives found in sudoers"
	}

	return result
}

// checkPasswordHashing verifies strong password hashing algorithm
// CIS 5.4.4 - Ensure password hashing algorithm is SHA-512 or yescrypt
func checkPasswordHashing() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-027",
		Name:        "Strong Password Hashing",
		Category:    "accessctl",
		Description: "Verify SHA-512 or yescrypt password hashing is configured",
		Severity:    "high",
		Expected:    "ENCRYPT_METHOD SHA512 or yescrypt",
		Techniques:  []string{"T1003.008"},
		Tactics:     []string{"credential-access"},
	}

	// Check /etc/login.defs for ENCRYPT_METHOD
	encryptMethod := RunBashIgnoreError(
		`grep -E "^\s*ENCRYPT_METHOD\s+" /etc/login.defs 2>/dev/null | awk '{print $2}'`)

	// Check PAM configuration
	pamHash := RunBashIgnoreError(
		`grep -E "pam_unix.so.*sha512|pam_unix.so.*yescrypt" /etc/pam.d/common-password /etc/pam.d/system-auth 2>/dev/null | head -1`)

	strongHash := false
	detectedMethod := ""

	if encryptMethod != "" {
		method := strings.ToUpper(strings.TrimSpace(encryptMethod))
		if method == "SHA512" || method == "YESCRYPT" {
			strongHash = true
			detectedMethod = method
		} else {
			detectedMethod = method
		}
	}

	if !strongHash && pamHash != "" {
		if strings.Contains(pamHash, "sha512") {
			strongHash = true
			detectedMethod = "SHA512 (via PAM)"
		} else if strings.Contains(pamHash, "yescrypt") {
			strongHash = true
			detectedMethod = "yescrypt (via PAM)"
		}
	}

	if strongHash {
		result.Passed = true
		result.Actual = detectedMethod
		result.Details = fmt.Sprintf("Password hashing uses %s", detectedMethod)
	} else if detectedMethod != "" {
		result.Passed = false
		result.Actual = detectedMethod
		result.Details = fmt.Sprintf("Weak hashing algorithm '%s' — use SHA512 or yescrypt", detectedMethod)
	} else {
		result.Passed = false
		result.Actual = "Unable to determine hashing algorithm"
		result.Details = "Could not find ENCRYPT_METHOD in login.defs or sha512/yescrypt in PAM"
	}

	return result
}

// checkPasswordMinLength verifies minimum password length
// CIS 5.4.1 - Ensure password creation requirements are configured
func checkPasswordMinLength() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-028",
		Name:        "Password Minimum Length >= 14",
		Category:    "accessctl",
		Description: "Verify password minimum length is at least 14 characters",
		Severity:    "high",
		Expected:    "minlen >= 14 in pwquality.conf or PAM",
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	// Check /etc/security/pwquality.conf
	minlenConf := RunBashIgnoreError(
		`grep -E "^\s*minlen\s*=" /etc/security/pwquality.conf 2>/dev/null | head -1`)

	// Check PAM for pam_pwquality.so minlen
	minlenPam := RunBashIgnoreError(
		`grep -E "pam_pwquality.so.*minlen=" /etc/pam.d/common-password /etc/pam.d/system-auth 2>/dev/null | head -1`)

	// Also check login.defs PASS_MIN_LEN
	passMinLen := RunBashIgnoreError(
		`grep -E "^\s*PASS_MIN_LEN\s+" /etc/login.defs 2>/dev/null | awk '{print $2}'`)

	minLength := 0
	source := ""

	if minlenConf != "" {
		parts := strings.SplitN(minlenConf, "=", 2)
		if len(parts) == 2 {
			val, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err == nil {
				minLength = val
				source = "pwquality.conf"
			}
		}
	}

	if minLength == 0 && minlenPam != "" {
		// Extract minlen=N from PAM line
		for _, part := range strings.Fields(minlenPam) {
			if strings.HasPrefix(part, "minlen=") {
				val, err := strconv.Atoi(strings.TrimPrefix(part, "minlen="))
				if err == nil {
					minLength = val
					source = "PAM pam_pwquality.so"
				}
			}
		}
	}

	if minLength == 0 && passMinLen != "" {
		val, err := strconv.Atoi(strings.TrimSpace(passMinLen))
		if err == nil {
			minLength = val
			source = "login.defs PASS_MIN_LEN"
		}
	}

	if minLength >= 14 {
		result.Passed = true
		result.Actual = fmt.Sprintf("minlen = %d (%s)", minLength, source)
		result.Details = fmt.Sprintf("Password minimum length is %d (compliant with CIS >= 14)", minLength)
	} else if minLength > 0 {
		result.Passed = false
		result.Actual = fmt.Sprintf("minlen = %d (%s)", minLength, source)
		result.Details = fmt.Sprintf("Password minimum length is %d — CIS requires at least 14", minLength)
	} else {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Password minimum length is not configured in pwquality.conf, PAM, or login.defs"
	}

	return result
}

// checkRootAccountLocked verifies root account is locked for direct login
// CIS 5.4.3 - Ensure default group for the root account is GID 0
func checkRootAccountLocked() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-029",
		Name:        "Root Account Locked",
		Category:    "accessctl",
		Description: "Verify root account is locked for direct login (use sudo instead)",
		Severity:    "high",
		Expected:    "Root password locked (passwd -S root shows 'L' or 'LK')",
		Techniques:  []string{"T1078.003"},
		Tactics:     []string{"privilege-escalation"},
	}

	// Check if root password is locked
	passwdStatus := RunBashIgnoreError("passwd -S root 2>/dev/null")
	if passwdStatus == "" {
		result.Passed = false
		result.Actual = "Unable to check root password status"
		result.Details = "passwd -S root failed — insufficient privileges or passwd not available"
		return result
	}

	fields := strings.Fields(passwdStatus)
	if len(fields) < 2 {
		result.Passed = false
		result.Actual = passwdStatus
		result.Details = "Could not parse passwd status output"
		return result
	}

	status := fields[1]
	if status == "L" || status == "LK" {
		result.Passed = true
		result.Actual = fmt.Sprintf("Root password status: %s (locked)", status)
		result.Details = "Root account is locked — direct login is prevented"
	} else if status == "P" || status == "PS" {
		result.Passed = false
		result.Actual = fmt.Sprintf("Root password status: %s (has password)", status)
		result.Details = "Root account has a password set — direct login is possible. Lock with 'passwd -l root'"
	} else if status == "NP" {
		result.Passed = false
		result.Actual = fmt.Sprintf("Root password status: %s (no password)", status)
		result.Details = "Root account has no password — extremely insecure"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("Root password status: %s", status)
		result.Details = "Unexpected root password status"
	}

	return result
}

// checkInactiveUserLockout verifies inactive user lockout is configured
// CIS 5.4.1.4 - Ensure inactive password lock is 30 days or less
func checkInactiveUserLockout() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-030",
		Name:        "Inactive User Lockout <= 30 days",
		Category:    "accessctl",
		Description: "Verify inactive user accounts are locked within 30 days",
		Severity:    "medium",
		Expected:    "INACTIVE <= 30 in useradd defaults",
		Techniques:  []string{"T1078.003"},
		Tactics:     []string{"privilege-escalation"},
	}

	// Check useradd defaults
	inactiveDefault := RunBashIgnoreError("useradd -D 2>/dev/null | grep INACTIVE")
	// Also check /etc/default/useradd directly
	if inactiveDefault == "" {
		data, err := os.ReadFile("/etc/default/useradd")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "INACTIVE=") {
					inactiveDefault = line
					break
				}
			}
		}
	}

	if inactiveDefault == "" {
		result.Passed = false
		result.Actual = "INACTIVE not configured"
		result.Details = "No inactive account lockout is configured in useradd defaults"
		return result
	}

	// Parse INACTIVE value
	var inactiveVal int
	parts := strings.SplitN(inactiveDefault, "=", 2)
	if len(parts) == 2 {
		val, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err == nil {
			inactiveVal = val
		}
	}

	if inactiveVal == -1 || inactiveVal == 0 {
		result.Passed = false
		result.Actual = fmt.Sprintf("INACTIVE = %d (disabled)", inactiveVal)
		result.Details = "Inactive password lock is disabled — stale accounts remain active indefinitely"
	} else if inactiveVal > 0 && inactiveVal <= 30 {
		result.Passed = true
		result.Actual = fmt.Sprintf("INACTIVE = %d days", inactiveVal)
		result.Details = fmt.Sprintf("Inactive accounts are locked after %d days (compliant with CIS <= 30)", inactiveVal)
	} else if inactiveVal > 30 {
		result.Passed = false
		result.Actual = fmt.Sprintf("INACTIVE = %d days", inactiveVal)
		result.Details = fmt.Sprintf("Inactive lockout is %d days — CIS recommends 30 or fewer", inactiveVal)
	} else {
		result.Passed = false
		result.Actual = inactiveDefault
		result.Details = "Could not parse INACTIVE value"
	}

	return result
}

// NOTE: truncateLongOutput is defined in check_utils.go (shared by all validators)

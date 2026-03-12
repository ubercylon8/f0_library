//go:build linux
// +build linux

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// RunSSHConfigChecks performs CIS Linux L1 SSH configuration checks
func RunSSHConfigChecks() ValidatorResult {
	checks := []CheckResult{
		checkSSHProtocol2(),
		checkSSHRootLoginDisabled(),
		checkSSHMaxAuthTries(),
		checkSSHNoEmptyPasswords(),
		checkSSHAllowUsersGroups(),
		checkSSHKeyAuth(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "SSH Configuration",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkSSHProtocol2 verifies SSH uses Protocol 2 only
// CIS 5.2.4 - Ensure SSH Protocol is set to 2
func checkSSHProtocol2() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-019",
		Name:        "SSH Protocol 2 Only",
		Category:    "sshconfig",
		Description: "Verify SSH is configured to use Protocol 2 only (Protocol 1 has known vulnerabilities)",
		Severity:    "critical",
		Expected:    "Protocol 2 (default in modern OpenSSH, or explicitly set)",
		Techniques:  []string{"T1021.004"},
		Tactics:     []string{"lateral-movement"},
	}

	val, err := CheckSSHConfig("Protocol")
	if err != nil || val == "" {
		// Modern OpenSSH (7.4+) defaults to Protocol 2 and removed Protocol 1 support
		// Check OpenSSH version
		sshVersion := RunBashIgnoreError("ssh -V 2>&1")
		result.Passed = true
		result.Actual = "Not set (default Protocol 2)"
		result.Details = fmt.Sprintf("Protocol not explicitly set — default is 2 in modern OpenSSH (%s)",
			strings.TrimSpace(sshVersion))
		return result
	}

	if val == "2" {
		result.Passed = true
		result.Actual = "Protocol 2"
		result.Details = "SSH explicitly configured for Protocol 2"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("Protocol %s", val)
		result.Details = "SSH Protocol 1 is insecure and should be disabled"
	}

	return result
}

// checkSSHRootLoginDisabled verifies root login via SSH is disabled
// CIS 5.2.10 - Ensure SSH root login is disabled
func checkSSHRootLoginDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-020",
		Name:        "Root Login Disabled",
		Category:    "sshconfig",
		Description: "Verify PermitRootLogin is set to 'no' to prevent direct root access via SSH",
		Severity:    "critical",
		Expected:    "PermitRootLogin = no",
		Techniques:  []string{"T1021.004"},
		Tactics:     []string{"lateral-movement"},
	}

	val, err := CheckSSHConfig("PermitRootLogin")
	if err != nil || val == "" {
		// Default is prohibit-password in modern OpenSSH (partial protection)
		result.Passed = false
		result.Actual = "Not set (default: prohibit-password)"
		result.Details = "PermitRootLogin not explicitly set — default allows root login with keys"
		return result
	}

	valLower := strings.ToLower(val)
	if valLower == "no" {
		result.Passed = true
		result.Actual = fmt.Sprintf("PermitRootLogin = %s", val)
		result.Details = "Root login via SSH is completely disabled"
	} else if valLower == "prohibit-password" || valLower == "without-password" {
		result.Passed = false
		result.Actual = fmt.Sprintf("PermitRootLogin = %s", val)
		result.Details = "Root login with password is disabled, but key-based root login is still allowed"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("PermitRootLogin = %s", val)
		result.Details = "Root login via SSH is enabled — set to 'no'"
	}

	return result
}

// checkSSHMaxAuthTries verifies MaxAuthTries is 4 or less
// CIS 5.2.7 - Ensure SSH MaxAuthTries is set to 4 or less
func checkSSHMaxAuthTries() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-021",
		Name:        "MaxAuthTries <= 4",
		Category:    "sshconfig",
		Description: "Verify SSH MaxAuthTries is set to 4 or less to limit brute force attempts",
		Severity:    "medium",
		Expected:    "MaxAuthTries <= 4",
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	val, err := CheckSSHConfig("MaxAuthTries")
	if err != nil || val == "" {
		// Default is 6 in OpenSSH
		result.Passed = false
		result.Actual = "Not set (default: 6)"
		result.Details = "MaxAuthTries not configured — default of 6 exceeds CIS recommendation of 4"
		return result
	}

	tries, parseErr := strconv.Atoi(val)
	if parseErr != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("MaxAuthTries = %s (invalid)", val)
		result.Details = "Could not parse MaxAuthTries value"
		return result
	}

	if tries <= 4 {
		result.Passed = true
		result.Actual = fmt.Sprintf("MaxAuthTries = %d", tries)
		result.Details = fmt.Sprintf("MaxAuthTries is %d (compliant with CIS <= 4)", tries)
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("MaxAuthTries = %d", tries)
		result.Details = fmt.Sprintf("MaxAuthTries is %d — should be 4 or less", tries)
	}

	return result
}

// checkSSHNoEmptyPasswords verifies empty passwords are not permitted
// CIS 5.2.11 - Ensure SSH PermitEmptyPasswords is disabled
func checkSSHNoEmptyPasswords() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-022",
		Name:        "No Empty Passwords",
		Category:    "sshconfig",
		Description: "Verify PermitEmptyPasswords is set to 'no' to prevent authentication with empty passwords",
		Severity:    "critical",
		Expected:    "PermitEmptyPasswords = no",
		Techniques:  []string{"T1021.004"},
		Tactics:     []string{"lateral-movement"},
	}

	val, err := CheckSSHConfig("PermitEmptyPasswords")
	if err != nil || val == "" {
		// Default is "no" in OpenSSH
		result.Passed = true
		result.Actual = "Not set (default: no)"
		result.Details = "PermitEmptyPasswords defaults to 'no' in OpenSSH"
		return result
	}

	if strings.ToLower(val) == "no" {
		result.Passed = true
		result.Actual = fmt.Sprintf("PermitEmptyPasswords = %s", val)
		result.Details = "Empty passwords are explicitly prohibited"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("PermitEmptyPasswords = %s", val)
		result.Details = "Empty passwords are permitted — accounts without passwords can authenticate"
	}

	return result
}

// checkSSHAllowUsersGroups verifies AllowUsers or AllowGroups is configured
// CIS 5.2.17 - Ensure SSH access is limited
func checkSSHAllowUsersGroups() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-023",
		Name:        "SSH Access Limited",
		Category:    "sshconfig",
		Description: "Verify AllowUsers, AllowGroups, DenyUsers, or DenyGroups is configured to restrict SSH access",
		Severity:    "high",
		Expected:    "At least one of AllowUsers, AllowGroups, DenyUsers, or DenyGroups is configured",
		Techniques:  []string{"T1021.004"},
		Tactics:     []string{"lateral-movement"},
	}

	allowUsers, _ := CheckSSHConfig("AllowUsers")
	allowGroups, _ := CheckSSHConfig("AllowGroups")
	denyUsers, _ := CheckSSHConfig("DenyUsers")
	denyGroups, _ := CheckSSHConfig("DenyGroups")

	configured := []string{}
	if allowUsers != "" {
		configured = append(configured, fmt.Sprintf("AllowUsers=%s", allowUsers))
	}
	if allowGroups != "" {
		configured = append(configured, fmt.Sprintf("AllowGroups=%s", allowGroups))
	}
	if denyUsers != "" {
		configured = append(configured, fmt.Sprintf("DenyUsers=%s", denyUsers))
	}
	if denyGroups != "" {
		configured = append(configured, fmt.Sprintf("DenyGroups=%s", denyGroups))
	}

	if len(configured) > 0 {
		result.Passed = true
		result.Actual = strings.Join(configured, ", ")
		result.Details = "SSH access is restricted by user/group directives"
	} else {
		result.Passed = false
		result.Actual = "No AllowUsers/AllowGroups/DenyUsers/DenyGroups configured"
		result.Details = "SSH access is not restricted — all valid accounts can connect"
	}

	return result
}

// checkSSHKeyAuth verifies key-based authentication is preferred
// CIS 5.2.5 - Ensure SSH PasswordAuthentication is disabled
func checkSSHKeyAuth() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-024",
		Name:        "Key-Based Authentication",
		Category:    "sshconfig",
		Description: "Verify key-based authentication is enforced (PasswordAuthentication disabled)",
		Severity:    "high",
		Expected:    "PubkeyAuthentication = yes AND PasswordAuthentication = no",
		Techniques:  []string{"T1021.004", "T1110"},
		Tactics:     []string{"lateral-movement", "credential-access"},
	}

	pubkeyAuth, _ := CheckSSHConfig("PubkeyAuthentication")
	passwordAuth, _ := CheckSSHConfig("PasswordAuthentication")

	// PubkeyAuthentication defaults to "yes"
	pubkeyEnabled := true
	if pubkeyAuth != "" && strings.ToLower(pubkeyAuth) == "no" {
		pubkeyEnabled = false
	}

	// PasswordAuthentication defaults to "yes"
	passwordDisabled := false
	if passwordAuth != "" && strings.ToLower(passwordAuth) == "no" {
		passwordDisabled = true
	}

	result.Actual = fmt.Sprintf("PubkeyAuthentication=%s, PasswordAuthentication=%s",
		func() string {
			if pubkeyAuth == "" {
				return "yes (default)"
			}
			return pubkeyAuth
		}(),
		func() string {
			if passwordAuth == "" {
				return "yes (default)"
			}
			return passwordAuth
		}())

	if pubkeyEnabled && passwordDisabled {
		result.Passed = true
		result.Details = "Key-based authentication only — password authentication is disabled"
	} else if pubkeyEnabled && !passwordDisabled {
		result.Passed = false
		result.Details = "Public key authentication is enabled but password authentication is also allowed"
	} else {
		result.Passed = false
		result.Details = "Public key authentication should be enabled and password authentication disabled"
	}

	return result
}

//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"strings"
)

// RunAuditLogChecks performs Audit & Logging checks (3 controls)
func RunAuditLogChecks() ValidatorResult {
	checks := []CheckResult{
		checkBSMAuditEnabled(),
		checkInstallLogRetained(),
		checkFirewallLogging(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Audit & Logging",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// CH-CM1-009: BSM audit (auditd) enabled
func checkBSMAuditEnabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-009",
		Name:        "BSM Audit (auditd) Running",
		Category:    "audit-logging",
		Description: "Verify that the Basic Security Module audit daemon is running (CIS 3.5)",
		Expected:    "auditd is loaded and running",
		Severity:    "high",
		Techniques:  []string{"T1562.001", "T1070.002"},
		Tactics:     []string{"defense-evasion"},
	}

	// Check if auditd is loaded via launchctl
	output, err := RunBash("launchctl list 2>/dev/null | grep -i 'com.apple.auditd'")
	if err != nil || output == "" {
		// Try alternative: check if auditd process is running
		procOutput, procErr := RunBash("ps aux | grep -v grep | grep auditd")
		if procErr != nil || procOutput == "" {
			result.Passed = false
			result.Actual = "auditd is not running"
			result.Details = "BSM audit daemon (auditd) is not loaded or running"
			return result
		}
		result.Passed = true
		result.Actual = fmt.Sprintf("auditd process found: %s", strings.TrimSpace(procOutput))
		result.Details = "BSM audit daemon is running (detected via process list)"
		return result
	}

	result.Actual = fmt.Sprintf("launchctl: %s", strings.TrimSpace(output))
	result.Passed = true
	result.Details = "BSM audit daemon (auditd) is loaded and running"
	return result
}

// CH-CM1-010: Install.log retained
func checkInstallLogRetained() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-010",
		Name:        "Install Log File Retained",
		Category:    "audit-logging",
		Description: "Verify that /var/log/install.log exists and is being retained (CIS 3.4)",
		Expected:    "/var/log/install.log exists",
		Severity:    "medium",
		Techniques:  []string{"T1070.002"},
		Tactics:     []string{"defense-evasion"},
	}

	if FileExists("/var/log/install.log") {
		// Get file details
		output, _ := RunBash("ls -lh /var/log/install.log | awk '{print $5, $6, $7, $8}'")
		result.Passed = true
		result.Actual = fmt.Sprintf("/var/log/install.log exists (%s)", strings.TrimSpace(output))
		result.Details = "Install log file is present and being retained"
	} else {
		result.Passed = false
		result.Actual = "/var/log/install.log does not exist"
		result.Details = "Install log file is missing - software installation events are not being logged"
	}
	return result
}

// CH-CM1-011: Firewall logging enabled
func checkFirewallLogging() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-011",
		Name:        "Firewall Logging Enabled",
		Category:    "audit-logging",
		Description: "Verify that the Application Firewall logging is enabled (CIS 3.3)",
		Expected:    "Logging mode enabled",
		Severity:    "high",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	output, err := RunCommandCombined("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getloggingmode")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("socketfilterfw error: %v", err)
		result.Details = "Could not determine firewall logging status"
		return result
	}

	result.Actual = output
	result.Passed = strings.Contains(strings.ToLower(output), "enabled")
	if result.Passed {
		result.Details = "Firewall logging is enabled - connection attempts are being recorded"
	} else {
		result.Details = "Firewall logging is disabled - connection attempts are not being logged"
	}
	return result
}

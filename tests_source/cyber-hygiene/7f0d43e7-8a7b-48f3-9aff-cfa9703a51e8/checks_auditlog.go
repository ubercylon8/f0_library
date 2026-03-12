//go:build linux
// +build linux

package main

import (
	"fmt"
	"strings"
)

// RunAuditLogChecks performs CIS Linux L1 audit and logging checks
func RunAuditLogChecks() ValidatorResult {
	checks := []CheckResult{
		checkAuditdRunning(),
		checkLogRetention(),
		checkIdentityFileAudit(),
		checkPermissionChangeAudit(),
		checkPrivilegedCommandAudit(),
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

// checkAuditdRunning verifies auditd service is active
// CIS 4.1.1.1 - Ensure auditd is installed
func checkAuditdRunning() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-014",
		Name:        "auditd Service Running",
		Category:    "auditlog",
		Description: "Verify the auditd service is running for comprehensive system auditing",
		Severity:    "critical",
		Expected:    "auditd service is active and enabled",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	active := CheckServiceActive("auditd")
	enabled := CheckServiceEnabled("auditd")

	if active && enabled {
		result.Passed = true
		result.Actual = "Active and enabled"
		result.Details = "auditd is running and will start on boot"
	} else if active && !enabled {
		result.Passed = false
		result.Actual = "Active but not enabled at boot"
		result.Details = "auditd is running but will not start automatically on reboot"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("Active: %s, Enabled: %s", BoolToYesNo(active), BoolToYesNo(enabled))
		result.Details = "auditd is not running — system activity is not being audited"
	}

	return result
}

// checkLogRetention verifies log retention is configured
// CIS 4.1.2.2 - Ensure audit logs are not automatically deleted
func checkLogRetention() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-015",
		Name:        "Log Retention Configured",
		Category:    "auditlog",
		Description: "Verify audit logs are configured for retention (max_log_file_action = keep_logs)",
		Severity:    "medium",
		Expected:    "max_log_file_action = keep_logs",
		Techniques:  []string{"T1070.002"},
		Tactics:     []string{"defense-evasion"},
	}

	output := RunBashIgnoreError(`grep -E "^\s*max_log_file_action\s*=" /etc/audit/auditd.conf 2>/dev/null`)
	if output == "" {
		result.Passed = false
		result.Actual = "auditd.conf not found or max_log_file_action not set"
		result.Details = "Could not read /etc/audit/auditd.conf"
		return result
	}

	// Extract value
	parts := strings.SplitN(output, "=", 2)
	if len(parts) < 2 {
		result.Passed = false
		result.Actual = output
		result.Details = "Could not parse max_log_file_action value"
		return result
	}

	value := strings.TrimSpace(parts[1])
	if strings.EqualFold(value, "keep_logs") {
		result.Passed = true
		result.Actual = fmt.Sprintf("max_log_file_action = %s", value)
		result.Details = "Audit logs are retained (not automatically deleted)"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("max_log_file_action = %s", value)
		result.Details = fmt.Sprintf("Audit logs use action '%s' — should be 'keep_logs' to prevent data loss", value)
	}

	return result
}

// checkIdentityFileAudit verifies audit watches on identity files
// CIS 4.1.4 - Ensure events that modify user/group information are collected
func checkIdentityFileAudit() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-016",
		Name:        "Identity File Change Audit",
		Category:    "auditlog",
		Description: "Verify audit rules monitor changes to /etc/passwd, /etc/group, /etc/shadow",
		Severity:    "high",
		Expected:    "Audit watches configured for /etc/passwd, /etc/group, /etc/shadow",
		Techniques:  []string{"T1136.001", "T1098"},
		Tactics:     []string{"persistence", "privilege-escalation"},
	}

	// Check for audit watches on identity files
	auditRules := RunBashIgnoreError("auditctl -l 2>/dev/null")

	watchedFiles := []string{"/etc/passwd", "/etc/group", "/etc/shadow"}
	foundFiles := []string{}
	missingFiles := []string{}

	for _, file := range watchedFiles {
		if strings.Contains(auditRules, file) {
			foundFiles = append(foundFiles, file)
		} else {
			missingFiles = append(missingFiles, file)
		}
	}

	if len(missingFiles) == 0 {
		result.Passed = true
		result.Actual = fmt.Sprintf("Watching: %s", strings.Join(foundFiles, ", "))
		result.Details = "All identity files are monitored by auditd"
	} else if len(foundFiles) > 0 {
		result.Passed = false
		result.Actual = fmt.Sprintf("Watching: %s | Missing: %s", strings.Join(foundFiles, ", "), strings.Join(missingFiles, ", "))
		result.Details = fmt.Sprintf("Missing audit watches for: %s", strings.Join(missingFiles, ", "))
	} else {
		result.Passed = false
		result.Actual = "No identity file audit watches found"
		result.Details = "No audit rules found for /etc/passwd, /etc/group, or /etc/shadow"
	}

	return result
}

// checkPermissionChangeAudit verifies audit rules for permission changes
// CIS 4.1.6 - Ensure events that modify the system's Mandatory Access Controls are collected
func checkPermissionChangeAudit() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-017",
		Name:        "Permission Change Audit",
		Category:    "auditlog",
		Description: "Verify audit rules capture chmod, chown, and fchmod syscalls",
		Severity:    "medium",
		Expected:    "Audit rules configured for chmod, chown, fchmod syscalls",
		Techniques:  []string{"T1222.002"},
		Tactics:     []string{"defense-evasion"},
	}

	auditRules := RunBashIgnoreError("auditctl -l 2>/dev/null")

	syscalls := []string{"chmod", "chown", "fchmod", "fchown"}
	foundSyscalls := []string{}
	missingSyscalls := []string{}

	for _, sc := range syscalls {
		if strings.Contains(auditRules, sc) {
			foundSyscalls = append(foundSyscalls, sc)
		} else {
			missingSyscalls = append(missingSyscalls, sc)
		}
	}

	if len(missingSyscalls) == 0 {
		result.Passed = true
		result.Actual = fmt.Sprintf("Auditing: %s", strings.Join(foundSyscalls, ", "))
		result.Details = "Permission change syscalls are being audited"
	} else if len(foundSyscalls) > 0 {
		result.Passed = false
		result.Actual = fmt.Sprintf("Auditing: %s | Missing: %s", strings.Join(foundSyscalls, ", "), strings.Join(missingSyscalls, ", "))
		result.Details = fmt.Sprintf("Missing audit rules for: %s", strings.Join(missingSyscalls, ", "))
	} else {
		result.Passed = false
		result.Actual = "No permission change audit rules found"
		result.Details = "No audit rules for chmod, chown, fchmod, or fchown syscalls"
	}

	return result
}

// checkPrivilegedCommandAudit verifies privileged commands are audited
// CIS 4.1.11 - Ensure privileged commands are collected
func checkPrivilegedCommandAudit() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-018",
		Name:        "Privileged Command Audit",
		Category:    "auditlog",
		Description: "Verify audit rules are configured for privileged (SUID/SGID) commands",
		Severity:    "high",
		Expected:    "Audit rules for SUID/SGID binaries or execve syscall",
		Techniques:  []string{"T1548.001"},
		Tactics:     []string{"privilege-escalation"},
	}

	auditRules := RunBashIgnoreError("auditctl -l 2>/dev/null")

	// Check for execve monitoring or specific privileged commands
	hasExecve := strings.Contains(auditRules, "execve")
	hasSudo := strings.Contains(auditRules, "/usr/bin/sudo") || strings.Contains(auditRules, "sudo")
	hasSu := strings.Contains(auditRules, "/usr/bin/su") || strings.Contains(auditRules, "/bin/su")
	hasPasswd := strings.Contains(auditRules, "/usr/bin/passwd")

	indicators := []string{}
	if hasExecve {
		indicators = append(indicators, "execve")
	}
	if hasSudo {
		indicators = append(indicators, "sudo")
	}
	if hasSu {
		indicators = append(indicators, "su")
	}
	if hasPasswd {
		indicators = append(indicators, "passwd")
	}

	if len(indicators) >= 2 || hasExecve {
		result.Passed = true
		result.Actual = fmt.Sprintf("Auditing: %s", strings.Join(indicators, ", "))
		result.Details = "Privileged command execution is being audited"
	} else if len(indicators) == 1 {
		result.Passed = false
		result.Actual = fmt.Sprintf("Partial: %s", strings.Join(indicators, ", "))
		result.Details = "Only partial privileged command auditing detected — add more rules"
	} else {
		result.Passed = false
		result.Actual = "No privileged command audit rules found"
		result.Details = "No audit rules for SUID/SGID binaries or execve syscall"
	}

	return result
}

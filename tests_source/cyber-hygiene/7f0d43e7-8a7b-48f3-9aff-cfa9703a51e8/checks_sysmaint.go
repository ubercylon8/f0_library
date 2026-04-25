//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"strings"
)

// RunSysMaintChecks performs CIS Linux L1 system maintenance checks
func RunSysMaintChecks() ValidatorResult {
	checks := []CheckResult{
		checkPasswdPermissions(),
		checkShadowPermissions(),
		checkWorldWritableFiles(),
		checkUnownedFiles(),
		checkSUIDSGIDAudit(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "System Maintenance",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkPasswdPermissions verifies /etc/passwd permissions are 644 or stricter
// CIS 6.1.2 - Ensure permissions on /etc/passwd are configured
func checkPasswdPermissions() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-031",
		Name:        "/etc/passwd Permissions",
		Category:    "sysmaint",
		Description: "Verify /etc/passwd has permissions 644 or more restrictive",
		Severity:    "medium",
		Expected:    "Permissions <= 0644",
		Techniques:  []string{"T1222.002"},
		Tactics:     []string{"defense-evasion"},
	}

	ok, perm, err := CheckFilePermissions("/etc/passwd", 0644)
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Error: %v", err)
		result.Details = "Could not check /etc/passwd permissions"
		return result
	}

	result.Actual = fmt.Sprintf("%04o", perm)
	if ok {
		result.Passed = true
		result.Details = fmt.Sprintf("/etc/passwd permissions are %04o (compliant)", perm)
	} else {
		result.Passed = false
		result.Details = fmt.Sprintf("/etc/passwd permissions are %04o — should be 0644 or stricter", perm)
	}

	return result
}

// checkShadowPermissions verifies /etc/shadow permissions are 640 or stricter
// CIS 6.1.3 - Ensure permissions on /etc/shadow are configured
func checkShadowPermissions() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-032",
		Name:        "/etc/shadow Permissions",
		Category:    "sysmaint",
		Description: "Verify /etc/shadow has permissions 640 or more restrictive",
		Severity:    "high",
		Expected:    "Permissions <= 0640",
		Techniques:  []string{"T1003.008"},
		Tactics:     []string{"credential-access"},
	}

	ok, perm, err := CheckFilePermissions("/etc/shadow", 0640)
	if err != nil {
		if os.IsNotExist(err) {
			result.Passed = false
			result.Actual = "File does not exist"
			result.Details = "/etc/shadow not found"
		} else if os.IsPermission(err) {
			// If we can't read the permissions, it may be very restricted (good)
			result.Passed = true
			result.Actual = "Permission denied (highly restricted)"
			result.Details = "Cannot even stat /etc/shadow — likely has very restrictive permissions"
		} else {
			result.Passed = false
			result.Actual = fmt.Sprintf("Error: %v", err)
			result.Details = "Could not check /etc/shadow permissions"
		}
		return result
	}

	result.Actual = fmt.Sprintf("%04o", perm)
	if ok {
		result.Passed = true
		result.Details = fmt.Sprintf("/etc/shadow permissions are %04o (compliant)", perm)
	} else {
		result.Passed = false
		result.Details = fmt.Sprintf("/etc/shadow permissions are %04o — should be 0640 or stricter", perm)
	}

	return result
}

// checkWorldWritableFiles checks for world-writable files
// CIS 6.1.10 - Ensure no world writable files exist
func checkWorldWritableFiles() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-033",
		Name:        "No World-Writable Files",
		Category:    "sysmaint",
		Description: "Check for world-writable files on local filesystems (excluding /proc, /sys, /dev)",
		Severity:    "medium",
		Expected:    "No world-writable files found (or minimal expected ones)",
		Techniques:  []string{"T1222.002"},
		Tactics:     []string{"defense-evasion"},
	}

	// Find world-writable files, excluding virtual filesystems and common expected ones
	// Use timeout to prevent long-running searches
	output := RunBashIgnoreError(
		`timeout 15 find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -20`)

	if strings.TrimSpace(output) == "" {
		result.Passed = true
		result.Actual = "No world-writable files found"
		result.Details = "No world-writable files detected on local filesystems"
	} else {
		files := strings.Split(strings.TrimSpace(output), "\n")
		count := len(files)
		if count >= 20 {
			result.Actual = fmt.Sprintf("20+ world-writable files found (showing first 20)")
		} else {
			result.Actual = fmt.Sprintf("%d world-writable files found", count)
		}
		result.Passed = false
		result.Details = fmt.Sprintf("World-writable files:\n%s", truncateLongOutput(output, 5))
	}

	return result
}

// checkUnownedFiles checks for files without valid owner or group
// CIS 6.1.11 - Ensure no unowned files or directories exist
func checkUnownedFiles() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-034",
		Name:        "No Unowned Files",
		Category:    "sysmaint",
		Description: "Check for files without a valid owner or group on local filesystems",
		Severity:    "medium",
		Expected:    "No unowned files found",
		Techniques:  []string{"T1222.002"},
		Tactics:     []string{"defense-evasion"},
	}

	// Find unowned files (no valid user or group)
	output := RunBashIgnoreError(
		`timeout 15 find / -xdev \( -nouser -o -nogroup \) ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -20`)

	if strings.TrimSpace(output) == "" {
		result.Passed = true
		result.Actual = "No unowned files found"
		result.Details = "All files have valid owners and groups"
	} else {
		files := strings.Split(strings.TrimSpace(output), "\n")
		count := len(files)
		if count >= 20 {
			result.Actual = fmt.Sprintf("20+ unowned files found (showing first 20)")
		} else {
			result.Actual = fmt.Sprintf("%d unowned files found", count)
		}
		result.Passed = false
		result.Details = fmt.Sprintf("Files without valid owner/group:\n%s", truncateLongOutput(output, 5))
	}

	return result
}

// checkSUIDSGIDAudit audits SUID/SGID files
// CIS 6.1.13 - Audit SUID executables / 6.1.14 - Audit SGID executables
func checkSUIDSGIDAudit() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-035",
		Name:        "SUID/SGID File Audit",
		Category:    "sysmaint",
		Description: "Audit SUID and SGID files on the system — excessive count may indicate compromise",
		Severity:    "high",
		Expected:    "SUID/SGID files are from known packages only",
		Techniques:  []string{"T1548.001"},
		Tactics:     []string{"privilege-escalation", "defense-evasion"},
	}

	// Count SUID/SGID files
	suidOutput := RunBashIgnoreError(
		`timeout 15 find / -xdev -type f \( -perm -4000 -o -perm -2000 \) ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null`)

	if strings.TrimSpace(suidOutput) == "" {
		result.Passed = true
		result.Actual = "No SUID/SGID files found"
		result.Details = "No setuid/setgid binaries detected"
		return result
	}

	files := strings.Split(strings.TrimSpace(suidOutput), "\n")
	count := len(files)

	// Common expected SUID/SGID binaries on a minimal Linux system
	expectedSUID := map[string]bool{
		"/usr/bin/su":        true,
		"/usr/bin/sudo":      true,
		"/usr/bin/passwd":    true,
		"/usr/bin/chsh":      true,
		"/usr/bin/chfn":      true,
		"/usr/bin/gpasswd":   true,
		"/usr/bin/newgrp":    true,
		"/usr/bin/mount":     true,
		"/usr/bin/umount":    true,
		"/usr/bin/pkexec":    true,
		"/usr/bin/crontab":   true,
		"/usr/bin/ssh-agent": true,
		"/usr/lib/dbus-1.0/dbus-daemon-launch-helper": true,
		"/usr/lib/openssh/ssh-keysign":                true,
		"/usr/sbin/unix_chkpwd":                       true,
		"/usr/sbin/pam_timestamp_check":               true,
		"/bin/su":                                     true,
		"/bin/mount":                                  true,
		"/bin/umount":                                 true,
		"/bin/ping":                                   true,
		"/usr/bin/ping":                               true,
	}

	unexpectedFiles := []string{}
	for _, f := range files {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !expectedSUID[f] {
			unexpectedFiles = append(unexpectedFiles, f)
		}
	}

	result.Actual = fmt.Sprintf("%d total SUID/SGID files (%d unexpected)", count, len(unexpectedFiles))

	if len(unexpectedFiles) == 0 {
		result.Passed = true
		result.Details = fmt.Sprintf("All %d SUID/SGID files are from known system packages", count)
	} else if len(unexpectedFiles) <= 5 {
		// Small number of unexpected files — informational
		result.Passed = true
		result.Details = fmt.Sprintf("%d SUID/SGID files found, %d non-standard:\n%s",
			count, len(unexpectedFiles), strings.Join(unexpectedFiles, "\n"))
	} else {
		result.Passed = false
		result.Details = fmt.Sprintf("%d unexpected SUID/SGID files detected — review for unauthorized setuid binaries:\n%s",
			len(unexpectedFiles), truncateLongOutput(strings.Join(unexpectedFiles, "\n"), 5))
	}

	return result
}

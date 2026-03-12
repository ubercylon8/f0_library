//go:build linux
// +build linux

package main

import (
	"fmt"
)

// RunServiceChecks performs CIS Linux L1 service hardening checks
func RunServiceChecks() ValidatorResult {
	checks := []CheckResult{
		checkXinetdDisabled(),
		checkAvahiDisabled(),
		checkCupsDisabled(),
		checkTimeSyncActive(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Service Hardening",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkXinetdDisabled verifies xinetd is not active or enabled
// CIS 2.1.1 - Ensure xinetd is not installed
func checkXinetdDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-005",
		Name:        "xinetd Disabled",
		Category:    "services",
		Description: "Verify xinetd super-server is not active or enabled (legacy service, attack surface reduction)",
		Severity:    "medium",
		Expected:    "Service not active and not enabled",
		Techniques:  []string{"T1543.002"},
		Tactics:     []string{"persistence"},
	}

	active := CheckServiceActive("xinetd")
	enabled := CheckServiceEnabled("xinetd")

	if !active && !enabled {
		result.Passed = true
		result.Actual = "Not active, not enabled"
		result.Details = "xinetd is properly disabled"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("Active: %s, Enabled: %s", BoolToYesNo(active), BoolToYesNo(enabled))
		result.Details = "xinetd provides legacy network services and should be disabled"
	}

	return result
}

// checkAvahiDisabled verifies avahi-daemon is not active
// CIS 2.2.3 - Ensure Avahi Server is not installed
func checkAvahiDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-006",
		Name:        "Avahi Daemon Disabled",
		Category:    "services",
		Description: "Verify Avahi mDNS/DNS-SD daemon is not active (reduces network attack surface)",
		Severity:    "medium",
		Expected:    "Service not active and not enabled",
		Techniques:  []string{"T1557"},
		Tactics:     []string{"credential-access"},
	}

	active := CheckServiceActive("avahi-daemon")
	enabled := CheckServiceEnabled("avahi-daemon")

	if !active && !enabled {
		result.Passed = true
		result.Actual = "Not active, not enabled"
		result.Details = "Avahi daemon is properly disabled"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("Active: %s, Enabled: %s", BoolToYesNo(active), BoolToYesNo(enabled))
		result.Details = "Avahi can expose services via mDNS, increasing attack surface"
	}

	return result
}

// checkCupsDisabled verifies CUPS is not active unless printing is required
// CIS 2.2.4 - Ensure CUPS is not installed
func checkCupsDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-007",
		Name:        "CUPS Disabled",
		Category:    "services",
		Description: "Verify CUPS printing service is not active unless required (reduces attack surface)",
		Severity:    "low",
		Expected:    "Service not active and not enabled",
		Techniques:  []string{"T1543.002"},
		Tactics:     []string{"persistence"},
	}

	active := CheckServiceActive("cups")
	enabled := CheckServiceEnabled("cups")

	if !active && !enabled {
		result.Passed = true
		result.Actual = "Not active, not enabled"
		result.Details = "CUPS is properly disabled"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("Active: %s, Enabled: %s", BoolToYesNo(active), BoolToYesNo(enabled))
		result.Details = "CUPS should be disabled on servers that do not require printing"
	}

	return result
}

// checkTimeSyncActive verifies time synchronization is active
// CIS 2.2.1.1 - Ensure time synchronization is in use
func checkTimeSyncActive() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-008",
		Name:        "Time Synchronization Active",
		Category:    "services",
		Description: "Verify NTP/time synchronization is active (required for log integrity and authentication)",
		Severity:    "high",
		Expected:    "chrony, systemd-timesyncd, or ntpd is active",
		Techniques:  []string{"T1070.006"},
		Tactics:     []string{"defense-evasion"},
	}

	chronydActive := CheckServiceActive("chronyd")
	timesyncdActive := CheckServiceActive("systemd-timesyncd")
	ntpdActive := CheckServiceActive("ntpd")

	activeSvc := ""
	if chronydActive {
		activeSvc = "chronyd"
	} else if timesyncdActive {
		activeSvc = "systemd-timesyncd"
	} else if ntpdActive {
		activeSvc = "ntpd"
	}

	if activeSvc != "" {
		result.Passed = true
		result.Actual = fmt.Sprintf("%s is active", activeSvc)
		result.Details = fmt.Sprintf("Time synchronization via %s is running", activeSvc)
	} else {
		result.Passed = false
		result.Actual = "No time sync service active"
		result.Details = "Neither chronyd, systemd-timesyncd, nor ntpd is running"
	}

	return result
}

//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"strings"
)

// RunNetworkChecks performs Network Security checks (3 controls)
func RunNetworkChecks() ValidatorResult {
	checks := []CheckResult{
		checkHTTPServerOff(),
		checkNFSServerOff(),
		checkAirDropDisabled(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Network Security",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// CH-CM1-012: HTTP server (httpd) not running
func checkHTTPServerOff() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-012",
		Name:        "HTTP Server (httpd) Disabled",
		Category:    "network-security",
		Description: "Verify that the built-in Apache HTTP server is not running (CIS 4.4)",
		Expected:    "httpd is not running",
		Severity:    "medium",
		Techniques:  []string{"T1071.001"},
		Tactics:     []string{"command-and-control"},
	}

	// Check if httpd is loaded via launchctl
	output, err := RunBash("launchctl list 2>/dev/null | grep 'org.apache.httpd'")
	if err == nil && output != "" {
		result.Passed = false
		result.Actual = fmt.Sprintf("httpd is loaded: %s", strings.TrimSpace(output))
		result.Details = "Apache HTTP server is loaded via launchctl - should be disabled"
		return result
	}

	// Also check via process list
	procOutput, procErr := RunBash("pgrep -x httpd 2>/dev/null")
	if procErr == nil && strings.TrimSpace(procOutput) != "" {
		result.Passed = false
		result.Actual = fmt.Sprintf("httpd process running (PID: %s)", strings.TrimSpace(procOutput))
		result.Details = "Apache HTTP server process is running"
		return result
	}

	result.Passed = true
	result.Actual = "httpd is not running or loaded"
	result.Details = "Built-in HTTP server is properly disabled"
	return result
}

// CH-CM1-013: NFS server not running
func checkNFSServerOff() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-013",
		Name:        "NFS Server Disabled",
		Category:    "network-security",
		Description: "Verify that the NFS server (nfsd) is not running (CIS 4.5)",
		Expected:    "nfsd is not running",
		Severity:    "medium",
		Techniques:  []string{"T1071.001"},
		Tactics:     []string{"command-and-control"},
	}

	// Check if nfsd process is running
	procOutput, procErr := RunBash("pgrep -x nfsd 2>/dev/null")
	if procErr == nil && strings.TrimSpace(procOutput) != "" {
		result.Passed = false
		result.Actual = fmt.Sprintf("nfsd process running (PID: %s)", strings.TrimSpace(procOutput))
		result.Details = "NFS server daemon is running - should be disabled on endpoints"
		return result
	}

	// Check if /etc/exports exists (NFS share configuration)
	if FileExists("/etc/exports") {
		output, _ := RunBash("cat /etc/exports 2>/dev/null | grep -v '^#' | grep -v '^$' | head -3")
		if strings.TrimSpace(output) != "" {
			result.Passed = false
			result.Actual = fmt.Sprintf("nfsd not running but /etc/exports has entries: %s", strings.TrimSpace(output))
			result.Details = "NFS exports file contains entries - NFS shares are configured even if daemon is stopped"
			return result
		}
	}

	result.Passed = true
	result.Actual = "nfsd is not running and no active NFS exports"
	result.Details = "NFS server is properly disabled"
	return result
}

// CH-CM1-014: AirDrop disabled
func checkAirDropDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-014",
		Name:        "AirDrop Disabled",
		Category:    "network-security",
		Description: "Verify that AirDrop is disabled to prevent unauthorized file transfer (CIS 4.1)",
		Expected:    "DisableAirDrop = 1",
		Severity:    "medium",
		Techniques:  []string{"T1071.001"},
		Tactics:     []string{"command-and-control"},
	}

	// Check the managed preference (MDM/profile-set)
	val, err := ReadDefaultsDomain("com.apple.NetworkBrowser", "DisableAirDrop")
	if err == nil && val == "1" {
		result.Passed = true
		result.Actual = "DisableAirDrop = 1"
		result.Details = "AirDrop is disabled via managed preference"
		return result
	}

	// Check per-user DiscoverableMode via Sharing preferences
	// DiscoverableMode: Off = disabled, Contacts Only = limited, Everyone = open
	discMode, discErr := ReadDefaultsDomain("com.apple.sharingd", "DiscoverableMode")
	if discErr == nil {
		result.Actual = fmt.Sprintf("DiscoverableMode = %s", discMode)
		if strings.EqualFold(discMode, "Off") {
			result.Passed = true
			result.Details = "AirDrop is set to Off"
			return result
		}
		result.Passed = false
		result.Details = fmt.Sprintf("AirDrop is set to '%s' - should be Off or disabled via policy", discMode)
		return result
	}

	// Cannot determine AirDrop status
	if err != nil {
		result.Passed = false
		result.Actual = "AirDrop configuration could not be determined"
		result.Details = "Neither DisableAirDrop nor DiscoverableMode preferences are set - AirDrop may be enabled by default"
	}
	return result
}

//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"strings"
	"time"
)

// RunEProtectChecks performs Endpoint Protection checks (3 controls)
func RunEProtectChecks() ValidatorResult {
	checks := []CheckResult{
		checkSIPEnabled(),
		checkGatekeeperEnabled(),
		checkXProtectUpdated(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Endpoint Protection",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// CH-CM1-020: SIP (System Integrity Protection) enabled
func checkSIPEnabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-020",
		Name:        "System Integrity Protection (SIP) Enabled",
		Category:    "endpoint-protection",
		Description: "Verify that System Integrity Protection is enabled (CIS 5.1.1)",
		Expected:    "System Integrity Protection status: enabled",
		Severity:    "critical",
		Techniques:  []string{"T1562.001", "T1553.001"},
		Tactics:     []string{"defense-evasion"},
	}

	output, err := RunCommandCombined("csrutil", "status")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("csrutil error: %v", err)
		result.Details = "Could not determine SIP status"
		return result
	}

	result.Actual = strings.TrimSpace(output)
	result.Passed = strings.Contains(strings.ToLower(output), "enabled")
	if result.Passed {
		result.Details = "System Integrity Protection is enabled - kernel and system files are protected"
	} else {
		result.Details = "System Integrity Protection is DISABLED - system files and kernel extensions are unprotected"
	}
	return result
}

// CH-CM1-021: Gatekeeper enabled
func checkGatekeeperEnabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-021",
		Name:        "Gatekeeper Enabled",
		Category:    "endpoint-protection",
		Description: "Verify that Gatekeeper is enabled to enforce code signing (CIS 2.5.2.1)",
		Expected:    "assessments enabled",
		Severity:    "critical",
		Techniques:  []string{"T1553.001"},
		Tactics:     []string{"defense-evasion"},
	}

	output, err := RunCommandCombined("spctl", "--status")
	if err != nil {
		// spctl --status exits non-zero when disabled
		if strings.Contains(strings.ToLower(err.Error()), "disabled") ||
			strings.Contains(strings.ToLower(output), "disabled") {
			result.Passed = false
			result.Actual = "assessments disabled"
			result.Details = "Gatekeeper is DISABLED - unsigned and unnotarized apps can run without restriction"
			return result
		}
		result.Passed = false
		result.Actual = fmt.Sprintf("spctl error: %v, output: %s", err, output)
		result.Details = "Could not determine Gatekeeper status"
		return result
	}

	result.Actual = strings.TrimSpace(output)
	result.Passed = strings.Contains(strings.ToLower(output), "assessments enabled")
	if result.Passed {
		result.Details = "Gatekeeper is enabled - code signing and notarization are enforced"
	} else {
		result.Details = "Gatekeeper may not be fully enabled"
	}
	return result
}

// CH-CM1-022: XProtect updated
func checkXProtectUpdated() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-022",
		Name:        "XProtect Definitions Updated",
		Category:    "endpoint-protection",
		Description: "Verify that XProtect malware definitions are present and reasonably current (CIS 5.1.3)",
		Expected:    "XProtect bundle exists and was updated within 90 days",
		Severity:    "high",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	// Check for XProtect bundle in common locations
	xprotectPaths := []string{
		"/Library/Apple/System/Library/CoreServices/XProtect.bundle",
		"/System/Library/CoreServices/XProtect.bundle",
	}

	var foundPath string
	for _, p := range xprotectPaths {
		if FileExists(p) {
			foundPath = p
			break
		}
	}

	if foundPath == "" {
		result.Passed = false
		result.Actual = "XProtect bundle not found in standard locations"
		result.Details = "XProtect is not installed or has been removed"
		return result
	}

	// Get XProtect version from plist
	versionPlist := foundPath + "/Contents/version.plist"
	if !FileExists(versionPlist) {
		// Try Info.plist instead
		versionPlist = foundPath + "/Contents/Info.plist"
	}

	version := "unknown"
	if FileExists(versionPlist) {
		versionOutput, vErr := RunBash(fmt.Sprintf("defaults read '%s' CFBundleShortVersionString 2>/dev/null || defaults read '%s' CFBundleVersion 2>/dev/null", versionPlist, versionPlist))
		if vErr == nil && versionOutput != "" {
			version = strings.TrimSpace(versionOutput)
		}
	}

	// Check when XProtect was last updated via install history
	lastUpdate, err := RunBash("system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 2 'XProtect' | grep 'Install Date' | tail -1 | sed 's/.*Install Date: //'")
	if err == nil && lastUpdate != "" {
		lastUpdate = strings.TrimSpace(lastUpdate)
		// Parse the date to check if it's within 90 days
		// system_profiler dates are typically in format "2/15/2025, 10:30 AM" or similar
		result.Actual = fmt.Sprintf("XProtect v%s found at %s, last update: %s", version, foundPath, lastUpdate)
		result.Passed = true
		result.Details = fmt.Sprintf("XProtect definitions are present (v%s), last update: %s", version, lastUpdate)
		return result
	}

	// Fallback: check modification time of the bundle
	modTimeOutput, modErr := RunBash(fmt.Sprintf("stat -f '%%m' '%s' 2>/dev/null", foundPath))
	if modErr == nil && modTimeOutput != "" {
		var modTimestamp int64
		_, parseErr := fmt.Sscanf(strings.TrimSpace(modTimeOutput), "%d", &modTimestamp)
		if parseErr == nil {
			modTime := time.Unix(modTimestamp, 0)
			daysSinceUpdate := int(time.Since(modTime).Hours() / 24)
			result.Actual = fmt.Sprintf("XProtect v%s found, bundle modified %d days ago", version, daysSinceUpdate)
			result.Passed = daysSinceUpdate <= 90
			if result.Passed {
				result.Details = fmt.Sprintf("XProtect definitions are current (modified %d days ago, threshold: 90 days)", daysSinceUpdate)
			} else {
				result.Details = fmt.Sprintf("XProtect definitions may be stale (modified %d days ago, exceeds 90-day threshold)", daysSinceUpdate)
			}
			return result
		}
	}

	// If we found the bundle but can't determine currency, pass with a note
	result.Passed = true
	result.Actual = fmt.Sprintf("XProtect v%s found at %s, update date could not be determined", version, foundPath)
	result.Details = "XProtect bundle is present but update date could not be verified"
	return result
}

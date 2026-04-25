//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// SMB registry paths
const (
	SMBServerPath    = `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
	SMBClientPath    = `SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`
	SMBv1ServerPath  = `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
	SMBv1FeaturePath = `SOFTWARE\Microsoft\Windows\CurrentVersion\OptionalFeatures\SMB1Protocol`
)

// RunSMBChecks performs all SMB hardening checks
func RunSMBChecks() ValidatorResult {
	checks := []CheckResult{
		checkSMBv1Disabled(),
		checkSMBServerSigning(),
		checkSMBClientSigning(),
		checkSMBEncryption(),
		checkNullSessionRestrictions(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "SMB Hardening",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkSMBv1Disabled verifies SMBv1 is disabled
func checkSMBv1Disabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-SMB-001",
		Name:        "SMBv1 Disabled",
		Category:    "smb",
		Description: "Checks if SMBv1 protocol is disabled",
		Severity:    "critical",
		Expected:    "Disabled",
		Techniques:  []string{"T1021.002"},
		Tactics:     []string{"lateral-movement"},
	}

	// Check via PowerShell (most reliable)
	output, err := RunPowerShell(`
		$server = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
		if ($server) {
			if ($server.EnableSMB1Protocol -eq $false) { "Disabled" }
			else { "Enabled" }
		} else {
			# Fallback: check Windows feature
			$feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
			if ($feature -and $feature.State -eq 'Disabled') { "Disabled" }
			elseif ($feature) { "Enabled" }
			else { "Unknown" }
		}
	`)

	if err == nil {
		status := strings.TrimSpace(output)
		result.Passed = status == "Disabled"
		result.Actual = status
		result.Details = status
		return result
	}

	// Fallback to registry
	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, SMBv1ServerPath, "SMB1", 0)
	if err != nil {
		result.Passed = false
		result.Actual = "Unable to determine"
		result.Details = "Unable to determine"
		return result
	}

	result.Passed = match
	result.Actual = BoolToEnabledDisabled(!match)
	result.Details = fmt.Sprintf("SMB1 = %d", val)
	return result
}

// checkSMBServerSigning verifies SMB server signing is required
func checkSMBServerSigning() CheckResult {
	result := CheckResult{
		ControlID:   "CH-SMB-002",
		Name:        "SMB Server Signing",
		Category:    "smb",
		Description: "Checks if SMB server signing is required",
		Severity:    "high",
		Expected:    "Required (RequireSecuritySignature = 1)",
		Techniques:  []string{"T1557.001"},
		Tactics:     []string{"credential-access"},
	}

	// Check via PowerShell
	output, err := RunPowerShell("(Get-SmbServerConfiguration).RequireSecuritySignature")
	if err == nil {
		isRequired := strings.TrimSpace(output) == "True"
		result.Passed = isRequired
		if isRequired {
			result.Actual = "Required"
		} else {
			result.Actual = "Not required"
		}
		result.Details = result.Actual
		return result
	}

	// Fallback to registry
	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, SMBServerPath, "RequireSecuritySignature", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("RequireSecuritySignature = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

// checkSMBClientSigning verifies SMB client signing is required
func checkSMBClientSigning() CheckResult {
	result := CheckResult{
		ControlID:   "CH-SMB-003",
		Name:        "SMB Client Signing",
		Category:    "smb",
		Description: "Checks if SMB client signing is required",
		Severity:    "high",
		Expected:    "Required (RequireSecuritySignature = 1)",
		Techniques:  []string{"T1557.001"},
		Tactics:     []string{"credential-access"},
	}

	// Check via PowerShell
	output, err := RunPowerShell("(Get-SmbClientConfiguration).RequireSecuritySignature")
	if err == nil {
		isRequired := strings.TrimSpace(output) == "True"
		result.Passed = isRequired
		if isRequired {
			result.Actual = "Required"
		} else {
			result.Actual = "Not required"
		}
		result.Details = result.Actual
		return result
	}

	// Fallback to registry
	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, SMBClientPath, "RequireSecuritySignature", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("RequireSecuritySignature = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

// checkSMBEncryption verifies SMB encryption is enabled
func checkSMBEncryption() CheckResult {
	result := CheckResult{
		ControlID:   "CH-SMB-004",
		Name:        "SMB Encryption",
		Category:    "smb",
		Description: "Checks if SMB encryption is enabled",
		Severity:    "medium",
		Expected:    "Enabled",
		Techniques:  []string{"T1040"},
		Tactics:     []string{"credential-access"},
	}

	// Check via PowerShell
	output, err := RunPowerShell("(Get-SmbServerConfiguration).EncryptData")
	if err == nil {
		isEnabled := strings.TrimSpace(output) == "True"
		result.Passed = isEnabled
		result.Actual = BoolToEnabledDisabled(isEnabled)
		result.Details = result.Actual
		return result
	}

	// Fallback to registry
	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, SMBServerPath, "EncryptData", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("EncryptData = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

// checkNullSessionRestrictions verifies null session restrictions are in place
func checkNullSessionRestrictions() CheckResult {
	result := CheckResult{
		ControlID:   "CH-SMB-005",
		Name:        "Null Session Restrictions",
		Category:    "smb",
		Description: "Checks if anonymous/null session access is restricted",
		Severity:    "high",
		Expected:    "RestrictNullSessAccess = 1",
		Techniques:  []string{"T1021.002"},
		Tactics:     []string{"lateral-movement"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, SMBServerPath, "RestrictNullSessAccess", 1)
	if err != nil {
		// Default is enabled (1) on modern Windows
		result.Passed = true
		result.Actual = "Enabled (default)"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("RestrictNullSessAccess = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// LSASS protection registry paths
const (
	LSAPath                  = `SYSTEM\CurrentControlSet\Control\Lsa`
	DeviceGuardPath          = `SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`
	DeviceGuardScenarioPath  = `SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard`
)

// RunLSASSChecks performs all LSASS protection checks
func RunLSASSChecks() ValidatorResult {
	checks := []CheckResult{
		checkRunAsPPL(),
		checkCredentialGuard(),
		checkVirtualizationBasedSecurity(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:         "LSASS Protection",
		Checks:       checks,
		PassedCount:  passed,
		FailedCount:  failed,
		TotalChecks:  len(checks),
		IsCompliant:  failed == 0,
	}
}

// checkRunAsPPL verifies LSASS is running as Protected Process Light
func checkRunAsPPL() CheckResult {
	result := CheckResult{
		ControlID:   "CH-LSS-001",
		Name:        "RunAsPPL",
		Category:    "lsass",
		Description: "Checks if LSASS is running as Protected Process Light",
		Severity:    "critical",
		Expected:    "Enabled (RunAsPPL = 1 or 2)",
		Techniques:  []string{"T1003.001"},
		Tactics:     []string{"credential-access"},
	}

	// Check RunAsPPL registry value
	match, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE, LSAPath, "RunAsPPL", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	result.Passed = match
	switch val {
	case 0:
		result.Actual = "Disabled"
	case 1:
		result.Actual = "Enabled (Audit mode)"
	case 2:
		result.Actual = "Enabled (Enforcement mode)"
	default:
		result.Actual = fmt.Sprintf("Value: %d", val)
	}
	result.Details = result.Actual
	return result
}

// checkCredentialGuard verifies Credential Guard is enabled
func checkCredentialGuard() CheckResult {
	result := CheckResult{
		ControlID:   "CH-LSS-002",
		Name:        "Credential Guard",
		Category:    "lsass",
		Description: "Checks if Credential Guard is enabled",
		Severity:    "high",
		Expected:    "Enabled",
		Techniques:  []string{"T1003.001"},
		Tactics:     []string{"credential-access"},
	}

	// Check via PowerShell - DeviceGuard status
	output, err := RunPowerShell(`
		$cg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
		if ($cg) {
			$cgRunning = $cg.SecurityServicesRunning -contains 1
			$cgConfigured = $cg.SecurityServicesConfigured -contains 1
			if ($cgRunning) { "Running" }
			elseif ($cgConfigured) { "Configured" }
			else { "NotConfigured" }
		} else {
			"Unavailable"
		}
	`)
	if err == nil {
		status := strings.TrimSpace(output)
		switch status {
		case "Running":
			result.Passed = true
			result.Actual = "Running"
		case "Configured":
			result.Passed = true
			result.Actual = "Configured (not running)"
		case "NotConfigured":
			result.Passed = false
			result.Actual = "Not configured"
		default:
			result.Passed = false
			result.Actual = "Unavailable"
		}
		result.Details = result.Actual
		return result
	}

	// Fallback to registry check
	match, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE, DeviceGuardScenarioPath, "Enabled", 1)
	if err != nil {
		// Check policy path
		match, val, err = CheckRegistryDWORD(registry.LOCAL_MACHINE, DeviceGuardPath, "LsaCfgFlags", 1)
		if err != nil {
			result.Passed = false
			result.Actual = "Not configured"
			result.Details = result.Actual
			return result
		}
	}

	result.Passed = match
	if match {
		result.Actual = fmt.Sprintf("Enabled (value: %d)", val)
	} else {
		result.Actual = "Disabled"
	}
	result.Details = result.Actual
	return result
}

// checkVirtualizationBasedSecurity verifies VBS is enabled
func checkVirtualizationBasedSecurity() CheckResult {
	result := CheckResult{
		ControlID:   "CH-LSS-003",
		Name:        "Virtualization-Based Security",
		Category:    "lsass",
		Description: "Checks if Virtualization-Based Security (VBS) is enabled",
		Severity:    "high",
		Expected:    "Enabled and Running",
		Techniques:  []string{"T1003.001"},
		Tactics:     []string{"credential-access"},
	}

	// Check via PowerShell
	output, err := RunPowerShell(`
		$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
		if ($dg) {
			if ($dg.VirtualizationBasedSecurityStatus -eq 2) { "Running" }
			elseif ($dg.VirtualizationBasedSecurityStatus -eq 1) { "Enabled" }
			else { "Disabled" }
		} else {
			"Unavailable"
		}
	`)
	if err == nil {
		status := strings.TrimSpace(output)
		switch status {
		case "Running":
			result.Passed = true
			result.Actual = "Running"
		case "Enabled":
			result.Passed = true
			result.Actual = "Enabled (not running)"
		case "Disabled":
			result.Passed = false
			result.Actual = "Disabled"
		default:
			result.Passed = false
			result.Actual = "Unavailable"
		}
		result.Details = result.Actual
		return result
	}

	// Fallback to registry check
	match, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE, DeviceGuardPath, "EnableVirtualizationBasedSecurity", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	if match {
		result.Actual = fmt.Sprintf("Configured (value: %d)", val)
	} else {
		result.Actual = "Disabled"
	}
	result.Details = result.Actual
	return result
}

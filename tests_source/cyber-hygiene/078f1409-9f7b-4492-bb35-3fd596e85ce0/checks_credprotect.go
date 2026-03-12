//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RunCredProtectChecks performs Credential Protection checks (CIS Level 1)
func RunCredProtectChecks() ValidatorResult {
	checks := []CheckResult{
		checkLSASSRunAsPPL(),
		checkWDigestDisabled(),
		checkCredentialGuard(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Credential Protection",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// CH-CW1-027: LSASS RunAsPPL
func checkLSASSRunAsPPL() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-027",
		Name:        "LSASS RunAsPPL",
		Category:    "credprotect",
		Description: "LSA Protection (RunAsPPL) enabled to protect LSASS process (CIS 18.4.x)",
		Severity:    "critical",
		Expected:    "RunAsPPL = 1 or 2",
		Techniques:  []string{"T1003.001"},
		Tactics:     []string{"credential-access"},
	}

	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err != nil {
		result.Passed = false
		result.Actual = "Unable to read LSA registry key"
		result.Details = result.Actual
		return result
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue("RunAsPPL")
	if err != nil {
		result.Passed = false
		result.Actual = "RunAsPPL not configured"
		result.Details = "LSASS is NOT running as Protected Process Light"
		return result
	}

	// 1 = PPL enabled (legacy), 2 = PPL enabled (UEFI lock)
	result.Passed = val == 1 || val == 2
	switch val {
	case 0:
		result.Actual = "RunAsPPL = 0 (Disabled)"
		result.Details = "LSASS not protected"
	case 1:
		result.Actual = "RunAsPPL = 1 (Enabled)"
		result.Details = "LSASS running as PPL"
	case 2:
		result.Actual = "RunAsPPL = 2 (Enabled with UEFI lock)"
		result.Details = "LSASS running as PPL with UEFI lock"
	default:
		result.Actual = fmt.Sprintf("RunAsPPL = %d", val)
		result.Details = result.Actual
	}
	return result
}

// CH-CW1-028: WDigest Authentication Disabled
func checkWDigestDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-028",
		Name:        "WDigest Authentication Disabled",
		Category:    "credprotect",
		Description: "WDigest authentication disabled to prevent cleartext credential caching (CIS 18.4.x)",
		Severity:    "critical",
		Expected:    "UseLogonCredential = 0",
		Techniques:  []string{"T1003.001", "T1003.002"},
		Tactics:     []string{"credential-access"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, "UseLogonCredential", 0)
	if err != nil {
		// On modern Windows (8.1+/2012R2+), WDigest is disabled by default when key is missing
		result.Passed = true
		result.Actual = "Not configured (disabled by default on modern Windows)"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("UseLogonCredential = %d", val)
	if match {
		result.Details = "WDigest disabled (cleartext credentials not cached)"
	} else {
		result.Details = "WDigest ENABLED — cleartext credentials cached in memory!"
	}
	return result
}

// CH-CW1-029: Credential Guard
func checkCredentialGuard() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-029",
		Name:        "Credential Guard",
		Category:    "credprotect",
		Description: "Virtualization Based Security and Credential Guard enabled (CIS 18.9.5.x)",
		Severity:    "critical",
		Expected:    "VBS enabled (EnableVirtualizationBasedSecurity = 1) AND Credential Guard (LsaCfgFlags = 1 or 2)",
		Techniques:  []string{"T1003.001", "T1003.002"},
		Tactics:     []string{"credential-access"},
	}

	// Check VBS enabled
	vbsMatch, vbsVal, vbsErr := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\DeviceGuard`, "EnableVirtualizationBasedSecurity", 1)

	// Check Credential Guard configured
	cgKey, cgErr := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	var cgVal uint64
	var cgSet bool
	if cgErr == nil {
		val, _, err := cgKey.GetIntegerValue("LsaCfgFlags")
		cgKey.Close()
		if err == nil {
			cgVal = val
			cgSet = true
		}
	}

	// Also check running state via PowerShell
	psOutput, psErr := RunPowerShell(`
		$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
		if ($dg) {
			$vbs = $dg.VirtualizationBasedSecurityStatus
			$cg = $dg.SecurityServicesRunning -contains 1
			Write-Output "VBS_STATUS:$vbs"
			Write-Output "CG_RUNNING:$cg"
		} else {
			Write-Output "UNAVAILABLE"
		}
	`)

	vbsRunning := false
	cgRunning := false
	if psErr == nil && !strings.Contains(psOutput, "UNAVAILABLE") {
		for _, line := range strings.Split(psOutput, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "VBS_STATUS:") {
				status := strings.TrimPrefix(line, "VBS_STATUS:")
				vbsRunning = strings.TrimSpace(status) == "2" // 2 = Running
			}
			if strings.HasPrefix(line, "CG_RUNNING:") {
				cgRunning = strings.Contains(line, "True")
			}
		}
	}

	// Determine overall compliance
	vbsConfigured := vbsErr == nil && vbsMatch
	cgConfigured := cgSet && (cgVal == 1 || cgVal == 2)

	result.Passed = (vbsConfigured || vbsRunning) && (cgConfigured || cgRunning)

	// Build status string
	parts := []string{}
	if vbsRunning {
		parts = append(parts, "VBS: Running")
	} else if vbsConfigured {
		parts = append(parts, fmt.Sprintf("VBS: Configured (= %d)", vbsVal))
	} else {
		parts = append(parts, "VBS: Not configured")
	}

	if cgRunning {
		parts = append(parts, "Credential Guard: Running")
	} else if cgConfigured {
		parts = append(parts, fmt.Sprintf("Credential Guard: Configured (LsaCfgFlags = %d)", cgVal))
	} else {
		parts = append(parts, "Credential Guard: Not configured")
	}

	result.Actual = strings.Join(parts, ", ")
	result.Details = result.Actual
	return result
}

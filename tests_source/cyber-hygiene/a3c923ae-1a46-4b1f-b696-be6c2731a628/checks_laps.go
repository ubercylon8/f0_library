//go:build windows
// +build windows

package main

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// LAPS registry paths
const (
	WindowsLAPSPath = `SOFTWARE\Policies\Microsoft\Windows\LAPS`
	LegacyLAPSPath  = `SOFTWARE\Policies\Microsoft Services\AdmPwd`
	LegacyLAPSCSEPath = `C:\Program Files\LAPS\CSE\AdmPwd.dll`
)

// RunLAPSChecks performs all LAPS configuration checks
func RunLAPSChecks() ValidatorResult {
	checks := []CheckResult{
		checkWindowsLAPS(),
		checkLegacyLAPS(),
	}

	passed, failed := AggregateValidatorResults(checks)

	// LAPS is compliant if either Windows LAPS or Legacy LAPS is enabled
	isCompliant := false
	for _, check := range checks {
		if check.Passed {
			isCompliant = true
			break
		}
	}

	return ValidatorResult{
		Name:         "Local Administrator Password Solution (LAPS)",
		Checks:       checks,
		PassedCount:  passed,
		FailedCount:  failed,
		TotalChecks:  len(checks),
		IsCompliant:  isCompliant, // Pass if ANY LAPS solution is configured
	}
}

// checkWindowsLAPS checks if Windows LAPS (built-in) is configured
func checkWindowsLAPS() CheckResult {
	result := CheckResult{
		Name:        "Windows LAPS (Built-in)",
		Category:    "laps",
		Description: "Checks if Windows LAPS (Windows Server 2019+/Windows 10+) is configured",
		Severity:    "high",
		Expected:    "Configured with Azure AD or Active Directory backup",
	}

	// Check via PowerShell - Get-LapsDiagnostics
	output, err := RunPowerShell(`
		try {
			$diag = Get-LapsDiagnostics -ErrorAction Stop
			if ($diag) { "Available" } else { "NotAvailable" }
		} catch {
			"NotAvailable"
		}
	`)

	cmdletAvailable := err == nil && strings.TrimSpace(output) == "Available"

	// Check registry for BackupDirectory (1 = Azure AD, 2 = AD)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, WindowsLAPSPath, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()

		backupDir, _, err := key.GetIntegerValue("BackupDirectory")
		if err == nil && backupDir > 0 {
			result.Passed = true
			switch backupDir {
			case 1:
				result.Actual = "Azure AD backup configured"
				result.Details = "Azure AD"
			case 2:
				result.Actual = "Active Directory backup configured"
				result.Details = "Active Directory"
			default:
				result.Actual = "Backup configured"
				result.Details = "Configured"
			}
			return result
		}
	}

	// Check if LAPS cmdlets are available but not configured
	if cmdletAvailable {
		result.Passed = false
		result.Actual = "Available but not configured"
		result.Details = "Not configured"
		return result
	}

	result.Passed = false
	result.Actual = "Not available or not configured"
	result.Details = "Not configured"
	return result
}

// checkLegacyLAPS checks if Legacy LAPS (Microsoft LAPS) is configured
func checkLegacyLAPS() CheckResult {
	result := CheckResult{
		Name:        "Legacy LAPS (Microsoft LAPS)",
		Category:    "laps",
		Description: "Checks if Legacy Microsoft LAPS is installed and enabled",
		Severity:    "high",
		Expected:    "Installed and enabled (AdmPwdEnabled = 1)",
	}

	// Check if Legacy LAPS CSE DLL exists
	cseExists := false
	if _, err := os.Stat(LegacyLAPSCSEPath); err == nil {
		cseExists = true
	}

	// Also check for x86 path
	if !cseExists {
		x86Path := filepath.Join(os.Getenv("ProgramFiles(x86)"), "LAPS", "CSE", "AdmPwd.dll")
		if _, err := os.Stat(x86Path); err == nil {
			cseExists = true
		}
	}

	// Check registry for AdmPwdEnabled
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, LegacyLAPSPath, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()

		enabled, _, err := key.GetIntegerValue("AdmPwdEnabled")
		if err == nil && enabled == 1 {
			result.Passed = true
			if cseExists {
				result.Actual = "Installed and enabled"
				result.Details = "CSE + GPO configured"
			} else {
				result.Actual = "GPO configured (CSE missing)"
				result.Details = "GPO configured"
			}
			return result
		}
	}

	// Check if CSE exists but not enabled
	if cseExists {
		result.Passed = false
		result.Actual = "Installed but not enabled"
		result.Details = "CSE installed, GPO not configured"
		return result
	}

	result.Passed = false
	result.Actual = "Not installed"
	result.Details = "Not installed"
	return result
}

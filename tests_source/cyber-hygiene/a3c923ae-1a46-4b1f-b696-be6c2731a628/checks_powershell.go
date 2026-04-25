//go:build windows
// +build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// PowerShell registry paths
const (
	PowerShellScriptBlockPath = `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
	PowerShellModulePath      = `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging`
	PowerShellTranscriptPath  = `SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`
	PowerShellCLMPath         = `SOFTWARE\Policies\Microsoft\Windows\PowerShell`
)

// RunPowerShellChecks performs all PowerShell security checks
func RunPowerShellChecks() ValidatorResult {
	checks := []CheckResult{
		checkScriptBlockLogging(),
		checkModuleLogging(),
		checkTranscription(),
		checkConstrainedLanguageMode(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "PowerShell Security",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkScriptBlockLogging verifies PowerShell Script Block Logging is enabled
func checkScriptBlockLogging() CheckResult {
	result := CheckResult{
		ControlID:   "CH-PWS-001",
		Name:        "Script Block Logging",
		Category:    "powershell",
		Description: "Checks if PowerShell Script Block Logging is enabled",
		Severity:    "high",
		Expected:    "Enabled (EnableScriptBlockLogging = 1)",
		Techniques:  []string{"T1059.001"},
		Tactics:     []string{"execution"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, PowerShellScriptBlockPath, "EnableScriptBlockLogging", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("EnableScriptBlockLogging = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

// checkModuleLogging verifies PowerShell Module Logging is enabled
func checkModuleLogging() CheckResult {
	result := CheckResult{
		ControlID:   "CH-PWS-002",
		Name:        "Module Logging",
		Category:    "powershell",
		Description: "Checks if PowerShell Module Logging is enabled",
		Severity:    "high",
		Expected:    "Enabled (EnableModuleLogging = 1)",
		Techniques:  []string{"T1059.001"},
		Tactics:     []string{"execution"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, PowerShellModulePath, "EnableModuleLogging", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("EnableModuleLogging = %d", val)
	result.Details = BoolToEnabledDisabled(match)

	// Also check if module names are configured
	if match {
		// Check for ModuleNames key
		exists, _ := CheckRegistryExists(registry.LOCAL_MACHINE, PowerShellModulePath+`\ModuleNames`, "")
		if !exists {
			result.Details = "Enabled (no modules specified)"
		} else {
			result.Details = "Enabled (modules configured)"
		}
	}

	return result
}

// checkTranscription verifies PowerShell Transcription is enabled
func checkTranscription() CheckResult {
	result := CheckResult{
		ControlID:   "CH-PWS-003",
		Name:        "Transcription",
		Category:    "powershell",
		Description: "Checks if PowerShell Transcription is enabled",
		Severity:    "medium",
		Expected:    "Enabled (EnableTranscripting = 1)",
		Techniques:  []string{"T1059.001"},
		Tactics:     []string{"execution"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, PowerShellTranscriptPath, "EnableTranscripting", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("EnableTranscripting = %d", val)
	result.Details = BoolToEnabledDisabled(match)

	// Check for output directory
	if match {
		dirMatch, dir, dirErr := CheckRegistryString(registry.LOCAL_MACHINE, PowerShellTranscriptPath, "OutputDirectory", "")
		if dirErr == nil && dirMatch {
			result.Details = fmt.Sprintf("Enabled (output: %s)", dir)
		}
	}

	return result
}

// checkConstrainedLanguageMode verifies if Constrained Language Mode policy is configured
func checkConstrainedLanguageMode() CheckResult {
	result := CheckResult{
		ControlID:   "CH-PWS-004",
		Name:        "Constrained Language Mode Policy",
		Category:    "powershell",
		Description: "Checks if Constrained Language Mode is enabled via policy",
		Severity:    "medium",
		Expected:    "Configured via AppLocker or WDAC",
		Techniques:  []string{"T1059.001"},
		Tactics:     []string{"execution", "defense-evasion"},
	}

	// CLM is typically enforced through AppLocker/WDAC, not a direct registry setting
	// Check if system lockdown policy is in place
	output, err := RunPowerShell(`
		$lockdown = [System.Management.Automation.Security.SystemPolicy]::GetSystemLockdownPolicy()
		switch ($lockdown) {
			'None' { 'None' }
			'Audit' { 'Audit' }
			'Enforce' { 'Enforce' }
			default { 'Unknown' }
		}
	`)

	if err == nil {
		switch output {
		case "Enforce":
			result.Passed = true
			result.Actual = "Enforced"
			result.Details = "System lockdown enforced"
		case "Audit":
			result.Passed = false
			result.Actual = "Audit mode"
			result.Details = "Audit mode (not enforcing)"
		case "None":
			result.Passed = false
			result.Actual = "Not configured"
			result.Details = "No system lockdown"
		default:
			result.Passed = false
			result.Actual = "Unknown"
			result.Details = "Unable to determine"
		}
		return result
	}

	// Alternative: check if execution policy is restrictive
	output, err = RunPowerShell("Get-ExecutionPolicy -List | Where-Object { $_.Scope -eq 'LocalMachine' } | Select-Object -ExpandProperty ExecutionPolicy")
	if err == nil {
		policy := output
		// AllSigned or Restricted are considered secure
		switch policy {
		case "AllSigned", "Restricted":
			result.Passed = true
			result.Actual = policy
			result.Details = fmt.Sprintf("ExecutionPolicy: %s", policy)
		default:
			result.Passed = false
			result.Actual = policy
			result.Details = fmt.Sprintf("ExecutionPolicy: %s (not restrictive)", policy)
		}
		return result
	}

	result.Passed = false
	result.Actual = "Unable to determine"
	result.Details = "Unable to determine"
	return result
}

//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Defender registry paths
const (
	DefenderPolicyPath   = `SOFTWARE\Policies\Microsoft\Windows Defender`
	DefenderRealTimePath = `SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
	DefenderMpEnginePath = `SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine`
	DefenderSpynetPath   = `SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`
	DefenderReportPath   = `SOFTWARE\Policies\Microsoft\Windows Defender\Reporting`
)

// RunDefenderChecks performs all Microsoft Defender configuration checks
func RunDefenderChecks() ValidatorResult {
	checks := []CheckResult{
		checkRealTimeProtection(),
		checkBehaviorMonitoring(),
		checkTamperProtection(),
		checkCloudProtection(),
		checkSampleSubmission(),
		checkPUAProtection(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Microsoft Defender Configuration",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkRealTimeProtection verifies real-time protection is enabled
func checkRealTimeProtection() CheckResult {
	result := CheckResult{
		ControlID:   "CH-DEF-001",
		Name:        "Real-time Protection",
		Category:    "defender",
		Description: "Checks if real-time protection is enabled",
		Severity:    "critical",
		Expected:    "Enabled (DisableRealtimeMonitoring = 0 or not set)",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	// Check via PowerShell first (most reliable)
	output, err := RunPowerShell("(Get-MpPreference).DisableRealtimeMonitoring")
	if err == nil {
		isDisabled := strings.TrimSpace(output) == "True"
		result.Passed = !isDisabled
		result.Actual = BoolToEnabledDisabled(!isDisabled)
		result.Details = result.Actual
		return result
	}

	// Fallback to registry
	// If DisableRealtimeMonitoring doesn't exist or is 0, protection is enabled
	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, DefenderRealTimePath, "DisableRealtimeMonitoring", 0)
	if err != nil {
		// Key doesn't exist - protection is enabled by default
		result.Passed = true
		result.Actual = "Enabled (default)"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("DisableRealtimeMonitoring = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

// checkBehaviorMonitoring verifies behavior monitoring is enabled
func checkBehaviorMonitoring() CheckResult {
	result := CheckResult{
		ControlID:   "CH-DEF-002",
		Name:        "Behavior Monitoring",
		Category:    "defender",
		Description: "Checks if behavior monitoring is enabled",
		Severity:    "high",
		Expected:    "Enabled (DisableBehaviorMonitoring = 0 or not set)",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	output, err := RunPowerShell("(Get-MpPreference).DisableBehaviorMonitoring")
	if err == nil {
		isDisabled := strings.TrimSpace(output) == "True"
		result.Passed = !isDisabled
		result.Actual = BoolToEnabledDisabled(!isDisabled)
		result.Details = result.Actual
		return result
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, DefenderRealTimePath, "DisableBehaviorMonitoring", 0)
	if err != nil {
		result.Passed = true
		result.Actual = "Enabled (default)"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("DisableBehaviorMonitoring = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

// checkTamperProtection verifies tamper protection is enabled
func checkTamperProtection() CheckResult {
	result := CheckResult{
		ControlID:   "CH-DEF-003",
		Name:        "Tamper Protection",
		Category:    "defender",
		Description: "Checks if tamper protection is enabled",
		Severity:    "critical",
		Expected:    "Enabled",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	output, err := RunPowerShell("(Get-MpComputerStatus).IsTamperProtected")
	if err == nil {
		isEnabled := strings.TrimSpace(output) == "True"
		result.Passed = isEnabled
		result.Actual = BoolToEnabledDisabled(isEnabled)
		result.Details = result.Actual
		return result
	}

	// Cannot determine status
	result.Passed = false
	result.Actual = "Unable to determine"
	result.Details = "Could not query tamper protection status"
	return result
}

// checkCloudProtection verifies cloud-delivered protection (MAPS) is enabled
func checkCloudProtection() CheckResult {
	result := CheckResult{
		ControlID:   "CH-DEF-004",
		Name:        "Cloud Protection (MAPS)",
		Category:    "defender",
		Description: "Checks if cloud-delivered protection is enabled",
		Severity:    "high",
		Expected:    "Enabled (MAPSReporting >= 1)",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	output, err := RunPowerShell("(Get-MpPreference).MAPSReporting")
	if err == nil {
		level := strings.TrimSpace(output)
		// 0 = Disabled, 1 = Basic, 2 = Advanced
		isEnabled := level != "0" && level != ""
		result.Passed = isEnabled
		switch level {
		case "0":
			result.Actual = "Disabled"
		case "1":
			result.Actual = "Basic"
		case "2":
			result.Actual = "Advanced"
		default:
			result.Actual = level
		}
		result.Details = result.Actual
		return result
	}

	// Fallback to registry - SpynetReporting
	match, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE, DefenderSpynetPath, "SpynetReporting", 1)
	if err != nil {
		result.Passed = true
		result.Actual = "Enabled (default)"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("SpynetReporting = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

// checkSampleSubmission verifies automatic sample submission is enabled
func checkSampleSubmission() CheckResult {
	result := CheckResult{
		ControlID:   "CH-DEF-005",
		Name:        "Sample Submission",
		Category:    "defender",
		Description: "Checks if automatic sample submission is enabled",
		Severity:    "medium",
		Expected:    "Enabled (SubmitSamplesConsent >= 1)",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	output, err := RunPowerShell("(Get-MpPreference).SubmitSamplesConsent")
	if err == nil {
		level := strings.TrimSpace(output)
		// 0 = Always prompt, 1 = Send safe samples, 2 = Never send, 3 = Send all
		isEnabled := level == "1" || level == "3"
		result.Passed = isEnabled
		switch level {
		case "0":
			result.Actual = "Always Prompt"
		case "1":
			result.Actual = "Send Safe Samples"
		case "2":
			result.Actual = "Never Send"
		case "3":
			result.Actual = "Send All Samples"
		default:
			result.Actual = level
		}
		result.Details = result.Actual
		return result
	}

	// Fallback to registry
	match, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE, DefenderSpynetPath, "SubmitSamplesConsent", 1)
	if err != nil {
		result.Passed = true
		result.Actual = "Enabled (default)"
		result.Details = result.Actual
		return result
	}

	result.Passed = match && val != 2
	result.Actual = fmt.Sprintf("SubmitSamplesConsent = %d", val)
	result.Details = BoolToEnabledDisabled(result.Passed)
	return result
}

// checkPUAProtection verifies potentially unwanted application protection is enabled
func checkPUAProtection() CheckResult {
	result := CheckResult{
		ControlID:   "CH-DEF-006",
		Name:        "PUA Protection",
		Category:    "defender",
		Description: "Checks if potentially unwanted application protection is enabled",
		Severity:    "medium",
		Expected:    "Enabled (PUAProtection = 1 or 2)",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	output, err := RunPowerShell("(Get-MpPreference).PUAProtection")
	if err == nil {
		level := strings.TrimSpace(output)
		// 0 = Disabled, 1 = Enabled (block), 2 = Audit mode
		isEnabled := level == "1" || level == "2"
		result.Passed = isEnabled
		switch level {
		case "0":
			result.Actual = "Disabled"
		case "1":
			result.Actual = "Enabled (Block)"
		case "2":
			result.Actual = "Audit Mode"
		default:
			result.Actual = level
		}
		result.Details = result.Actual
		return result
	}

	// Fallback to registry
	match, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE, DefenderMpEnginePath, "MpEnablePus", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("MpEnablePus = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

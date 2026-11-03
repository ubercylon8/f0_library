//go:build windows
// +build windows

package main

import (
	"encoding/json"
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
		checkDefenderServiceMode(),
		checkSignatureFreshness(),
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
		ControlID:      "CH-DEF-001",
		Name:           "Real-time Protection",
		Category:       "defender",
		Description:    "Checks live Defender real-time protection and antimalware service state",
		Severity:       "critical",
		Expected:       "RealTimeProtectionEnabled=True and AMServiceEnabled=True",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "Get-MpComputerStatus",
	}

	output, err := RunPowerShell(`$s = Get-MpComputerStatus -ErrorAction Stop; $s | Select-Object RealTimeProtectionEnabled, AMServiceEnabled | ConvertTo-Json -Compress`)
	if err != nil {
		result.Status = "UNKNOWN"
		result.Actual = "Unable to query Defender status"
		result.Details = err.Error()
		return result
	}
	var status struct {
		RealTimeProtectionEnabled *bool `json:"RealTimeProtectionEnabled"`
		AMServiceEnabled          *bool `json:"AMServiceEnabled"`
	}
	if err := json.Unmarshal([]byte(output), &status); err != nil || status.RealTimeProtectionEnabled == nil || status.AMServiceEnabled == nil {
		result.Status = "UNKNOWN"
		result.Actual = "Defender status response was incomplete"
		result.Details = strings.TrimSpace(output)
		return result
	}
	result.Passed = *status.RealTimeProtectionEnabled && *status.AMServiceEnabled
	result.Actual = fmt.Sprintf("RealTimeProtectionEnabled=%t, AMServiceEnabled=%t", *status.RealTimeProtectionEnabled, *status.AMServiceEnabled)
	result.Details = result.Actual
	return result
}

// checkBehaviorMonitoring verifies behavior monitoring is enabled
func checkBehaviorMonitoring() CheckResult {
	result := CheckResult{
		ControlID:      "CH-DEF-002",
		Name:           "Behavior Monitoring",
		Category:       "defender",
		Description:    "Checks live Defender behavior monitoring state",
		Severity:       "high",
		Expected:       "BehaviorMonitorEnabled=True",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "Get-MpComputerStatus",
	}

	output, err := RunPowerShell(`$s = Get-MpComputerStatus -ErrorAction Stop; $s | Select-Object BehaviorMonitorEnabled | ConvertTo-Json -Compress`)
	if err != nil {
		result.Status = "UNKNOWN"
		result.Actual = "Unable to query Defender behavior monitoring"
		result.Details = err.Error()
		return result
	}
	var status struct {
		BehaviorMonitorEnabled *bool `json:"BehaviorMonitorEnabled"`
	}
	if err := json.Unmarshal([]byte(output), &status); err != nil || status.BehaviorMonitorEnabled == nil {
		result.Status = "UNKNOWN"
		result.Actual = "Behavior monitoring state was not reported"
		result.Details = strings.TrimSpace(output)
		return result
	}
	result.Passed = *status.BehaviorMonitorEnabled
	result.Actual = BoolToEnabledDisabled(result.Passed)
	result.Details = result.Actual
	return result
}

// checkTamperProtection verifies tamper protection is enabled
func checkTamperProtection() CheckResult {
	result := CheckResult{
		ControlID:      "CH-DEF-003",
		Name:           "Tamper Protection",
		Category:       "defender",
		Description:    "Checks if tamper protection is enabled",
		Severity:       "critical",
		Expected:       "Enabled",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "Get-MpComputerStatus.IsTamperProtected",
	}

	output, err := RunPowerShell("(Get-MpComputerStatus).IsTamperProtected")
	value := strings.TrimSpace(output)
	if err == nil && value != "" {
		result.Passed = value == "True"
		result.Actual = BoolToEnabledDisabled(result.Passed)
		result.Details = result.Actual
		return result
	}

	result.Status = "UNKNOWN"
	result.Actual = "Unable to determine"
	result.Details = "Could not query tamper protection status"
	return result
}

// checkCloudProtection verifies cloud-delivered protection (MAPS) is enabled
func checkCloudProtection() CheckResult {
	result := CheckResult{
		ControlID:      "CH-DEF-004",
		Name:           "Cloud Protection (MAPS)",
		Category:       "defender",
		Description:    "Checks if cloud-delivered protection is enabled",
		Severity:       "high",
		Expected:       "Enabled (MAPSReporting >= 1)",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "Get-MpPreference.MAPSReporting or SpynetReporting policy",
	}

	output, err := RunPowerShell("(Get-MpPreference).MAPSReporting")
	if err == nil {
		level := strings.TrimSpace(output)
		if level == "" {
			result.Status = "UNKNOWN"
			result.Actual = "MAPSReporting was not reported"
			result.Details = result.Actual
			return result
		}
		result.Passed = level != "0"
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

	match, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE, DefenderSpynetPath, "SpynetReporting", 1)
	if err != nil {
		result.Status = "UNKNOWN"
		result.Actual = "Cloud protection state unavailable"
		result.Details = "PowerShell query failed and no explicit SpynetReporting policy exists"
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
		ControlID:      "CH-DEF-005",
		Name:           "Sample Submission",
		Category:       "defender",
		Description:    "Checks if automatic sample submission is enabled",
		Severity:       "medium",
		Expected:       "Send safe samples (1) or all samples (3)",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "Get-MpPreference.SubmitSamplesConsent or policy registry",
	}

	output, err := RunPowerShell("(Get-MpPreference).SubmitSamplesConsent")
	if err == nil {
		level := strings.TrimSpace(output)
		if level == "" {
			result.Status = "UNKNOWN"
			result.Actual = "SubmitSamplesConsent was not reported"
			result.Details = result.Actual
			return result
		}
		result.Passed = level == "1" || level == "3"
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

	_, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE, DefenderSpynetPath, "SubmitSamplesConsent", 1)
	if err != nil {
		result.Status = "UNKNOWN"
		result.Actual = "Sample submission state unavailable"
		result.Details = "PowerShell query failed and no explicit SubmitSamplesConsent policy exists"
		return result
	}
	result.Passed = val == 1 || val == 3
	result.Actual = fmt.Sprintf("SubmitSamplesConsent = %d", val)
	result.Details = BoolToEnabledDisabled(result.Passed)
	return result
}

// checkPUAProtection verifies potentially unwanted application protection is enabled
func checkPUAProtection() CheckResult {
	result := CheckResult{
		ControlID:      "CH-DEF-006",
		Name:           "PUA Protection",
		Category:       "defender",
		Description:    "Checks if potentially unwanted application protection blocks unwanted software",
		Severity:       "medium",
		Expected:       "Block mode (PUAProtection = 1); Audit mode is not blocking",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "Get-MpPreference.PUAProtection or MpEnablePus policy",
	}

	output, err := RunPowerShell("(Get-MpPreference).PUAProtection")
	if err == nil {
		level := strings.TrimSpace(output)
		if level == "" {
			result.Status = "UNKNOWN"
			result.Actual = "PUAProtection was not reported"
			result.Details = result.Actual
			return result
		}
		result.Passed = level == "1"
		switch level {
		case "0":
			result.Actual = "Disabled"
		case "1":
			result.Actual = "Enabled (Block)"
		case "2":
			result.Actual = "Audit Mode (not blocking)"
		default:
			result.Actual = level
		}
		result.Details = result.Actual
		return result
	}

	_, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE, DefenderMpEnginePath, "MpEnablePus", 1)
	if err != nil {
		result.Status = "UNKNOWN"
		result.Actual = "PUA protection state unavailable"
		result.Details = "PowerShell query failed and no explicit MpEnablePus policy exists"
		return result
	}
	result.Passed = val == 1
	result.Actual = fmt.Sprintf("MpEnablePus = %d", val)
	result.Details = BoolToEnabledDisabled(result.Passed)
	return result
}

func checkDefenderServiceMode() CheckResult {
	result := CheckResult{
		ControlID:      "CH-DEF-007",
		Name:           "Defender Active Service Mode",
		Category:       "defender",
		Description:    "Checks that Defender Antivirus is active rather than disabled or in passive mode",
		Severity:       "critical",
		Expected:       "AMServiceEnabled=True and AMRunningMode is Normal or Active",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "Get-MpComputerStatus",
	}
	output, err := RunPowerShell(`$s = Get-MpComputerStatus -ErrorAction Stop; $s | Select-Object AMServiceEnabled, AMRunningMode | ConvertTo-Json -Compress`)
	if err != nil {
		result.Status = "UNKNOWN"
		result.Actual = "Unable to query Defender service mode"
		result.Details = err.Error()
		return result
	}
	var status struct {
		AMServiceEnabled *bool  `json:"AMServiceEnabled"`
		AMRunningMode    string `json:"AMRunningMode"`
	}
	if err := json.Unmarshal([]byte(output), &status); err != nil || status.AMServiceEnabled == nil || strings.TrimSpace(status.AMRunningMode) == "" {
		result.Status = "UNKNOWN"
		result.Actual = "Defender service mode was not fully reported"
		result.Details = strings.TrimSpace(output)
		return result
	}
	mode := strings.ToLower(strings.TrimSpace(status.AMRunningMode))
	result.Passed = *status.AMServiceEnabled && (mode == "normal" || mode == "active")
	result.Actual = fmt.Sprintf("AMServiceEnabled=%t, AMRunningMode=%s", *status.AMServiceEnabled, status.AMRunningMode)
	result.Details = result.Actual
	return result
}

func checkSignatureFreshness() CheckResult {
	result := CheckResult{
		ControlID:      "CH-DEF-008",
		Name:           "Defender Signature Freshness",
		Category:       "defender",
		Description:    "Checks that Defender antivirus signatures are current",
		Severity:       "high",
		Expected:       "AntivirusSignatureAge <= 7 days",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		EvidenceSource: "Get-MpComputerStatus",
	}
	output, err := RunPowerShell(`$s = Get-MpComputerStatus -ErrorAction Stop; $s | Select-Object AntivirusSignatureAge, AntivirusSignatureVersion | ConvertTo-Json -Compress`)
	if err != nil {
		result.Status = "UNKNOWN"
		result.Actual = "Unable to query Defender signature age"
		result.Details = err.Error()
		return result
	}
	var status struct {
		AntivirusSignatureAge     *int   `json:"AntivirusSignatureAge"`
		AntivirusSignatureVersion string `json:"AntivirusSignatureVersion"`
	}
	if err := json.Unmarshal([]byte(output), &status); err != nil || status.AntivirusSignatureAge == nil || *status.AntivirusSignatureAge < 0 {
		result.Status = "UNKNOWN"
		result.Actual = "Defender signature age was not reported"
		result.Details = strings.TrimSpace(output)
		return result
	}
	result.Passed = *status.AntivirusSignatureAge <= 7
	result.Actual = fmt.Sprintf("Age=%d days, Version=%s", *status.AntivirusSignatureAge, status.AntivirusSignatureVersion)
	result.Details = result.Actual
	return result
}

//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
)

// ASR Rule GUIDs and their descriptions
var ASRRules = map[string]string{
	"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550": "Block executable content from email client and webmail",
	"D4F940AB-401B-4EFC-AADC-AD5F3C50688A": "Block all Office applications from creating child processes",
	"3B576869-A4EC-4529-8536-B80A7769E899": "Block Office applications from creating executable content",
	"75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84": "Block Office applications from injecting code into other processes",
	"D3E037E1-3EB8-44C8-A917-57927947596D": "Block JavaScript or VBScript from launching downloaded executable content",
	"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC": "Block execution of potentially obfuscated scripts",
	"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B": "Block Win32 API calls from Office macros",
	"26190899-1602-49E8-8B27-EB1D0A1CE869": "Block Office communication apps from creating child processes",
}

// Critical ASR rules that should be in Block mode
var CriticalASRRules = []string{
	"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", // Email executable
	"D4F940AB-401B-4EFC-AADC-AD5F3C50688A", // Office child processes
	"3B576869-A4EC-4529-8536-B80A7769E899", // Office executable content
	"75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", // Office code injection
	"D3E037E1-3EB8-44C8-A917-57927947596D", // JS/VBS downloaded exec
	"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", // Obfuscated scripts
	"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", // Office macro API calls
	"26190899-1602-49E8-8B27-EB1D0A1CE869", // Office comms child processes
}

// RunASRChecks performs all Attack Surface Reduction rule checks
func RunASRChecks() ValidatorResult {
	checks := make([]CheckResult, 0, len(CriticalASRRules))

	// Get all ASR rule states at once
	asrStates := getASRRuleStates()

	for _, ruleGUID := range CriticalASRRules {
		check := checkASRRule(ruleGUID, ASRRules[ruleGUID], asrStates)
		checks = append(checks, check)
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:         "Attack Surface Reduction Rules",
		Checks:       checks,
		PassedCount:  passed,
		FailedCount:  failed,
		TotalChecks:  len(checks),
		IsCompliant:  failed == 0,
	}
}

// getASRRuleStates retrieves all ASR rule states via PowerShell
func getASRRuleStates() map[string]int {
	states := make(map[string]int)

	output, err := RunPowerShell(`
		$prefs = Get-MpPreference -ErrorAction SilentlyContinue
		if ($prefs -and $prefs.AttackSurfaceReductionRules_Ids) {
			$ids = $prefs.AttackSurfaceReductionRules_Ids
			$actions = $prefs.AttackSurfaceReductionRules_Actions
			for ($i = 0; $i -lt $ids.Count; $i++) {
				$action = if ($i -lt $actions.Count) { $actions[$i] } else { 0 }
				Write-Output "$($ids[$i].ToUpper()):$action"
			}
		}
	`)

	if err != nil {
		return states
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if parts := strings.Split(line, ":"); len(parts) == 2 {
			guid := strings.ToUpper(strings.TrimSpace(parts[0]))
			var action int
			fmt.Sscanf(parts[1], "%d", &action)
			states[guid] = action
		}
	}

	return states
}

// checkASRRule checks if a specific ASR rule is enabled
func checkASRRule(ruleGUID, description string, states map[string]int) CheckResult {
	// Truncate description for display
	shortDesc := description
	if len(shortDesc) > 50 {
		shortDesc = shortDesc[:47] + "..."
	}

	result := CheckResult{
		Name:        shortDesc,
		Category:    "asr",
		Description: description,
		Severity:    "high",
		Expected:    "Block mode (1) or Warn mode (6)",
	}

	action, exists := states[strings.ToUpper(ruleGUID)]
	if !exists {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	// Action values:
	// 0 = Disabled
	// 1 = Block
	// 2 = Audit
	// 5 = Not Configured
	// 6 = Warn

	switch action {
	case 1:
		result.Passed = true
		result.Actual = "Block"
		result.Details = "Block"
	case 6:
		result.Passed = true
		result.Actual = "Warn"
		result.Details = "Warn"
	case 2:
		result.Passed = false
		result.Actual = "Audit"
		result.Details = "Audit (not blocking)"
	case 0:
		result.Passed = false
		result.Actual = "Disabled"
		result.Details = "Disabled"
	default:
		result.Passed = false
		result.Actual = fmt.Sprintf("Unknown (%d)", action)
		result.Details = result.Actual
	}

	return result
}

//go:build windows
// +build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// RunAuditLogChecks performs Audit & Logging Policy checks (CIS Level 1)
func RunAuditLogChecks() ValidatorResult {
	checks := []CheckResult{
		checkAuditCredentialValidation(),
		checkAuditAppGroupMgmt(),
		checkAuditSecGroupMgmt(),
		checkAuditUserAccountMgmt(),
		checkAuditProcessCreation(),
		checkAuditAccountLockout(),
		checkAuditLogon(),
		checkAuditPolicyChange(),
		checkPSScriptBlockLogging(),
		checkPSTranscription(),
		checkPSConstrainedLanguage(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Audit & Logging Policy",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// CH-CW1-034: Audit Credential Validation (Success+Failure)
func checkAuditCredentialValidation() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-034",
		Name:        "Audit Credential Validation",
		Category:    "auditlog",
		Description: "Audit Credential Validation = Success and Failure (CIS 17.1.1)",
		Severity:    "high",
		Expected:    "Success and Failure",
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	success, failure, err := RunAuditPol("Credential Validation")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = success && failure
	result.Actual = FormatAuditResult(success, failure)
	result.Details = result.Actual
	return result
}

// CH-CW1-035: Audit Application Group Management (Success+Failure)
func checkAuditAppGroupMgmt() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-035",
		Name:        "Audit Application Group Management",
		Category:    "auditlog",
		Description: "Audit Application Group Management = Success and Failure (CIS 17.2.1)",
		Severity:    "medium",
		Expected:    "Success and Failure",
		Techniques:  []string{"T1078.001"},
		Tactics:     []string{"persistence"},
	}

	success, failure, err := RunAuditPol("Application Group Management")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = success && failure
	result.Actual = FormatAuditResult(success, failure)
	result.Details = result.Actual
	return result
}

// CH-CW1-036: Audit Security Group Management (Success)
func checkAuditSecGroupMgmt() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-036",
		Name:        "Audit Security Group Management",
		Category:    "auditlog",
		Description: "Audit Security Group Management = Success (CIS 17.2.5)",
		Severity:    "high",
		Expected:    "At least Success",
		Techniques:  []string{"T1078.001"},
		Tactics:     []string{"persistence"},
	}

	success, _, err := RunAuditPol("Security Group Management")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	// CIS requires at least Success auditing
	result.Passed = success
	successVal, failureVal, _ := RunAuditPol("Security Group Management")
	result.Actual = FormatAuditResult(successVal, failureVal)
	result.Details = result.Actual
	return result
}

// CH-CW1-037: Audit User Account Management (Success+Failure)
func checkAuditUserAccountMgmt() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-037",
		Name:        "Audit User Account Management",
		Category:    "auditlog",
		Description: "Audit User Account Management = Success and Failure (CIS 17.2.6)",
		Severity:    "high",
		Expected:    "Success and Failure",
		Techniques:  []string{"T1078.001", "T1136"},
		Tactics:     []string{"persistence"},
	}

	success, failure, err := RunAuditPol("User Account Management")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = success && failure
	result.Actual = FormatAuditResult(success, failure)
	result.Details = result.Actual
	return result
}

// CH-CW1-038: Audit Process Creation (Success)
func checkAuditProcessCreation() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-038",
		Name:        "Audit Process Creation",
		Category:    "auditlog",
		Description: "Audit Process Creation = Success (CIS 17.3.1)",
		Severity:    "high",
		Expected:    "At least Success",
		Techniques:  []string{"T1059.001"},
		Tactics:     []string{"execution"},
	}

	success, failure, err := RunAuditPol("Process Creation")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = success
	result.Actual = FormatAuditResult(success, failure)
	result.Details = result.Actual
	return result
}

// CH-CW1-039: Audit Account Lockout (Failure)
func checkAuditAccountLockout() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-039",
		Name:        "Audit Account Lockout",
		Category:    "auditlog",
		Description: "Audit Account Lockout = Failure (CIS 17.5.1)",
		Severity:    "high",
		Expected:    "At least Failure",
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	success, failure, err := RunAuditPol("Account Lockout")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = failure
	result.Actual = FormatAuditResult(success, failure)
	result.Details = result.Actual
	return result
}

// CH-CW1-040: Audit Logon (Success+Failure)
func checkAuditLogon() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-040",
		Name:        "Audit Logon",
		Category:    "auditlog",
		Description: "Audit Logon = Success and Failure (CIS 17.5.3)",
		Severity:    "high",
		Expected:    "Success and Failure",
		Techniques:  []string{"T1078.001"},
		Tactics:     []string{"credential-access"},
	}

	success, failure, err := RunAuditPol("Logon")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = success && failure
	result.Actual = FormatAuditResult(success, failure)
	result.Details = result.Actual
	return result
}

// CH-CW1-041: Audit Policy Change (Success)
func checkAuditPolicyChange() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-041",
		Name:        "Audit Policy Change",
		Category:    "auditlog",
		Description: "Audit Audit Policy Change = Success (CIS 17.7.1)",
		Severity:    "high",
		Expected:    "At least Success",
		Techniques:  []string{"T1562.002"},
		Tactics:     []string{"defense-evasion"},
	}

	success, failure, err := RunAuditPol("Audit Policy Change")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = success
	result.Actual = FormatAuditResult(success, failure)
	result.Details = result.Actual
	return result
}

// CH-CW1-042: PowerShell Script Block Logging
func checkPSScriptBlockLogging() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-042",
		Name:        "PowerShell Script Block Logging",
		Category:    "auditlog",
		Description: "PowerShell Script Block Logging enabled (CIS 18.9.100.1)",
		Severity:    "high",
		Expected:    "EnableScriptBlockLogging = 1",
		Techniques:  []string{"T1059.001"},
		Tactics:     []string{"execution", "defense-evasion"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Script Block Logging not enabled via policy"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("EnableScriptBlockLogging = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

// CH-CW1-043: PowerShell Transcription
func checkPSTranscription() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-043",
		Name:        "PowerShell Transcription",
		Category:    "auditlog",
		Description: "PowerShell Transcription enabled (CIS 18.9.100.2)",
		Severity:    "medium",
		Expected:    "EnableTranscripting = 1",
		Techniques:  []string{"T1059.001"},
		Tactics:     []string{"execution", "defense-evasion"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`, "EnableTranscripting", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "PowerShell Transcription not enabled via policy"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("EnableTranscripting = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

// CH-CW1-044: PowerShell Constrained Language Mode
func checkPSConstrainedLanguage() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-044",
		Name:        "PowerShell Constrained Language Mode",
		Category:    "auditlog",
		Description: "PowerShell Constrained Language Mode enforced (__PSLockdownPolicy = 4) (CIS 18.9.100.x)",
		Severity:    "high",
		Expected:    "__PSLockdownPolicy = 4",
		Techniques:  []string{"T1059.001"},
		Tactics:     []string{"execution", "defense-evasion"},
	}

	// Check the environment variable in Session Manager
	match, val, err := CheckRegistryString(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, "__PSLockdownPolicy", "4")
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Constrained Language Mode not enforced via system environment"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("__PSLockdownPolicy = %s", val)
	if match {
		result.Details = "Constrained Language Mode enforced"
	} else {
		descriptions := map[string]string{
			"0": "FullLanguage (unrestricted)",
			"1": "ConstrainedLanguage (partial)",
			"2": "RestrictedLanguage",
			"3": "NoLanguage",
			"4": "ConstrainedLanguage (full lockdown)",
		}
		desc, ok := descriptions[val]
		if ok {
			result.Details = desc
		} else {
			result.Details = fmt.Sprintf("Unknown value: %s", val)
		}
	}
	return result
}

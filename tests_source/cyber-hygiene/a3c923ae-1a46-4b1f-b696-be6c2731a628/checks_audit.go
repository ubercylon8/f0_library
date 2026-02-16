//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
)

// Audit subcategories to check (GUIDs and names)
var AuditCategories = []struct {
	GUID        string
	Name        string
	Description string
	Severity    string
	ControlID   string
	Techniques  []string
	Tactics     []string
}{
	{"{0CCE9215-69AE-11D9-BED3-505054503030}", "Logon", "Audit logon events", "critical", "CH-AUD-001", []string{"T1078"}, []string{"defense-evasion", "initial-access"}},
	{"{0CCE9216-69AE-11D9-BED3-505054503030}", "Logoff", "Audit logoff events", "high", "CH-AUD-002", []string{"T1078"}, []string{"defense-evasion"}},
	{"{0CCE9217-69AE-11D9-BED3-505054503030}", "Account Lockout", "Audit account lockout events", "high", "CH-AUD-003", []string{"T1110"}, []string{"credential-access"}},
	{"{0CCE921B-69AE-11D9-BED3-505054503030}", "Special Logon", "Audit special logon events", "high", "CH-AUD-004", []string{"T1078"}, []string{"defense-evasion", "privilege-escalation"}},
	{"{0CCE922B-69AE-11D9-BED3-505054503030}", "Process Creation", "Audit process creation events", "critical", "CH-AUD-005", []string{"T1059"}, []string{"execution"}},
	{"{0CCE922F-69AE-11D9-BED3-505054503030}", "Audit Policy Change", "Audit policy change events", "high", "CH-AUD-006", []string{"T1562.002"}, []string{"defense-evasion"}},
	{"{0CCE9235-69AE-11D9-BED3-505054503030}", "User Account Management", "Audit user account management", "critical", "CH-AUD-007", []string{"T1136"}, []string{"persistence"}},
	{"{0CCE9236-69AE-11D9-BED3-505054503030}", "Computer Account Management", "Audit computer account management", "high", "CH-AUD-008", []string{"T1136"}, []string{"persistence"}},
	{"{0CCE9237-69AE-11D9-BED3-505054503030}", "Security Group Management", "Audit security group management", "critical", "CH-AUD-009", []string{"T1098"}, []string{"persistence", "privilege-escalation"}},
}

// RunAuditChecks performs all Windows audit logging checks
func RunAuditChecks() ValidatorResult {
	checks := make([]CheckResult, 0, len(AuditCategories))

	// Get all audit settings at once
	auditSettings := getAuditSettings()

	for _, cat := range AuditCategories {
		check := checkAuditCategory(cat.GUID, cat.Name, cat.Description, cat.Severity, cat.ControlID, cat.Techniques, cat.Tactics, auditSettings)
		checks = append(checks, check)
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:         "Windows Audit Logging",
		Checks:       checks,
		PassedCount:  passed,
		FailedCount:  failed,
		TotalChecks:  len(checks),
		IsCompliant:  failed == 0,
	}
}

// getAuditSettings retrieves all audit policy settings
func getAuditSettings() map[string]string {
	settings := make(map[string]string)

	output, err := RunPowerShell(`
		$result = auditpol /get /category:* /r 2>$null
		if ($result) {
			$result | Where-Object { $_ -match '^\{' } | ForEach-Object {
				$parts = $_ -split ','
				if ($parts.Count -ge 4) {
					Write-Output "$($parts[1])=$($parts[4])"
				}
			}
		}
	`)

	if err != nil {
		return settings
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if parts := strings.Split(line, "="); len(parts) == 2 {
			guid := strings.TrimSpace(parts[0])
			setting := strings.TrimSpace(parts[1])
			settings[guid] = setting
		}
	}

	return settings
}

// checkAuditCategory checks if a specific audit category is properly configured
func checkAuditCategory(guid, name, description, severity, controlID string, techniques, tactics []string, settings map[string]string) CheckResult {
	result := CheckResult{
		ControlID:   controlID,
		Name:        name,
		Category:    "audit",
		Description: description,
		Severity:    severity,
		Expected:    "Success and Failure (or at least Success)",
		Techniques:  techniques,
		Tactics:     tactics,
	}

	setting, exists := settings[guid]
	if !exists {
		// Try alternative method
		output, err := RunPowerShell(fmt.Sprintf(`
			$subcats = auditpol /get /subcategory:"%s" /r 2>$null
			if ($subcats) {
				$line = $subcats | Select-Object -Last 1
				$parts = $line -split ','
				if ($parts.Count -ge 4) { $parts[4] }
			}
		`, name))

		if err != nil {
			result.Passed = false
			result.Actual = "Unable to query"
			result.Details = "Unable to query"
			return result
		}

		setting = strings.TrimSpace(output)
	}

	// Parse setting
	// Possible values: "No Auditing", "Success", "Failure", "Success and Failure"
	switch strings.ToLower(setting) {
	case "success and failure":
		result.Passed = true
		result.Actual = "Success and Failure"
		result.Details = "Full auditing"
	case "success":
		result.Passed = true
		result.Actual = "Success only"
		result.Details = "Success auditing"
	case "failure":
		result.Passed = false
		result.Actual = "Failure only"
		result.Details = "Missing success events"
	case "no auditing", "":
		result.Passed = false
		result.Actual = "No Auditing"
		result.Details = "Not configured"
	default:
		result.Passed = false
		result.Actual = setting
		result.Details = setting
	}

	return result
}

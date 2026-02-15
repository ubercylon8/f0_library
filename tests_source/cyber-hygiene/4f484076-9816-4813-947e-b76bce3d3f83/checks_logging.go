//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
)

// RunLoggingChecks validates CISA SCuBA Section 4: Centralized Log Collection
func RunLoggingChecks() ValidatorResult {
	checks := []CheckResult{
		checkDiagnosticSettings(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Centralized Log Collection",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkDiagnosticSettings verifies Entra ID diagnostic settings are configured.
// SCuBA MS.AAD.4.1: Security logs SHALL be sent to a centralized SIEM.
func checkDiagnosticSettings() CheckResult {
	result := CheckResult{
		Name:        "Diagnostic Settings Configured",
		Category:    "logging",
		Description: "Verifies AuditLogs, SignInLogs, and RiskyUsers logs are sent to a destination",
		Severity:    "high",
		SCuBAID:     "MS.AAD.4.1",
		Expected:    "Diagnostic settings with log categories configured",
	}

	// Diagnostic settings for Entra ID are under Azure Resource Manager, not pure Graph.
	// Use Invoke-MgGraphRequest to call the ARM endpoint.
	script := `
try {
    $uri = 'https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01'
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    $settings = $response.value
    if ($settings -and $settings.Count -gt 0) {
        $allCategories = @()
        foreach ($s in $settings) {
            foreach ($log in $s.properties.logs) {
                if ($log.enabled -eq $true) {
                    $allCategories += $log.category
                }
            }
        }
        $required = @('AuditLogs', 'SignInLogs')
        $missing = @()
        foreach ($r in $required) {
            if ($allCategories -notcontains $r) {
                $missing += $r
            }
        }
        if ($missing.Count -eq 0) {
            Write-Output "CONFIGURED:$($settings.Count)|$($allCategories -join ',')"
        } else {
            Write-Output "PARTIAL:$($missing -join ',')"
        }
    } else {
        Write-Output "NONE"
    }
} catch {
    if ($_.Exception.Message -like '*Forbidden*' -or $_.Exception.Message -like '*Authorization*') {
        Write-Output "NOPERM"
    } else {
        Write-Output "ERROR:$($_.Exception.Message)"
    }
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying diagnostic settings"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "CONFIGURED:") {
		info := strings.TrimPrefix(output, "CONFIGURED:")
		parts := strings.SplitN(info, "|", 2)
		count := parts[0]
		categories := ""
		if len(parts) > 1 {
			categories = parts[1]
		}
		result.Passed = true
		result.Actual = fmt.Sprintf("%s diagnostic setting(s): %s", count, categories)
		result.Details = result.Actual
	} else if strings.HasPrefix(output, "PARTIAL:") {
		missing := strings.TrimPrefix(output, "PARTIAL:")
		result.Passed = false
		result.Actual = fmt.Sprintf("Missing log categories: %s", missing)
		result.Details = result.Actual
	} else if output == "NOPERM" {
		// Cannot verify - treat as informational
		result.Passed = false
		result.Actual = "Insufficient permissions for ARM diagnostic settings"
		result.Details = "Requires Azure subscription-level read permissions"
	} else if output == "NONE" {
		result.Passed = false
		result.Actual = "No diagnostic settings configured"
		result.Details = "No Entra ID diagnostic settings found"
	} else {
		result.Passed = false
		result.Actual = "Unable to verify diagnostic settings"
		result.Details = output
	}

	return result
}

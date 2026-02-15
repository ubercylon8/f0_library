//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
)

// RunLegacyAuthChecks validates CISA SCuBA Section 1: Legacy Authentication
func RunLegacyAuthChecks() ValidatorResult {
	checks := []CheckResult{
		checkLegacyAuthBlocked(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Legacy Authentication",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkLegacyAuthBlocked verifies a Conditional Access policy blocks legacy authentication protocols.
// SCuBA MS.AAD.1.1: Legacy authentication SHALL be blocked.
func checkLegacyAuthBlocked() CheckResult {
	result := CheckResult{
		Name:        "Legacy Authentication Blocked",
		Category:    "legacy-auth",
		Description: "Verifies a CA policy blocks Exchange ActiveSync and other legacy auth clients",
		Severity:    "critical",
		SCuBAID:     "MS.AAD.1.1",
		Expected:    "CA policy blocking legacy auth for all users",
	}

	script := `
$policies = Get-MgIdentityConditionalAccessPolicy -All
$legacyBlock = $policies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -and
    $_.Conditions.ClientAppTypes -contains 'other' -and
    $_.GrantControls.BuiltInControls -contains 'block'
}
if ($legacyBlock) {
    Write-Output "FOUND:$($legacyBlock[0].DisplayName)"
} else {
    # Also check for policies that use 'All' client app types with block
    $anyBlock = $policies | Where-Object {
        $_.State -eq 'enabled' -and
        ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
         $_.Conditions.ClientAppTypes -contains 'other') -and
        $_.GrantControls.BuiltInControls -contains 'block'
    }
    if ($anyBlock) {
        Write-Output "PARTIAL:$($anyBlock[0].DisplayName)"
    } else {
        Write-Output "NOTFOUND"
    }
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying CA policies"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "FOUND:") {
		policyName := strings.TrimPrefix(output, "FOUND:")
		result.Passed = true
		result.Actual = fmt.Sprintf("Blocked by policy: %s", policyName)
		result.Details = result.Actual
	} else if strings.HasPrefix(output, "PARTIAL:") {
		policyName := strings.TrimPrefix(output, "PARTIAL:")
		result.Passed = true
		result.Actual = fmt.Sprintf("Partially blocked by: %s", policyName)
		result.Details = result.Actual
	} else {
		result.Passed = false
		result.Actual = "No CA policy blocks legacy authentication"
		result.Details = "No blocking policy found"
	}

	return result
}

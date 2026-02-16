//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
)

// RunAppGovernanceChecks validates CISA SCuBA Section 5: Application Governance
func RunAppGovernanceChecks() ValidatorResult {
	checks := []CheckResult{
		checkUsersCannotRegisterApps(),
		checkUsersCannotConsentApps(),
		checkAdminConsentWorkflow(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Application Governance",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkUsersCannotRegisterApps verifies users cannot register applications.
// SCuBA MS.AAD.5.1: Only administrators SHALL be allowed to register applications.
func checkUsersCannotRegisterApps() CheckResult {
	result := CheckResult{
		ControlID:   "CH-ITN-013",
		Name:        "Users Cannot Register Apps",
		Category:    "app-governance",
		Description: "Verifies non-admin users cannot register applications in Entra ID",
		Severity:    "high",
		SCuBAID:     "MS.AAD.5.1",
		Expected:    "allowedToCreateApps = false",
		Techniques:  []string{"T1098.001"},
		Tactics:     []string{"persistence"},
	}

	script := `
$authPolicy = Get-MgPolicyAuthorizationPolicy
$allowCreate = $authPolicy.DefaultUserRolePermissions.AllowedToCreateApps
Write-Output "VALUE:$allowCreate"
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying authorization policy"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "VALUE:") {
		value := strings.TrimPrefix(output, "VALUE:")
		isAllowed := strings.EqualFold(strings.TrimSpace(value), "True")
		result.Passed = !isAllowed
		result.Actual = fmt.Sprintf("allowedToCreateApps = %s", value)
		if result.Passed {
			result.Details = "Users cannot register apps"
		} else {
			result.Details = "Users CAN register apps (should be restricted)"
		}
	} else {
		result.Passed = false
		result.Actual = "Unable to determine setting"
		result.Details = output
	}

	return result
}

// checkUsersCannotConsentApps verifies users cannot consent to applications.
// SCuBA MS.AAD.5.2: Only administrators SHALL be allowed to consent to applications.
func checkUsersCannotConsentApps() CheckResult {
	result := CheckResult{
		ControlID:   "CH-ITN-014",
		Name:        "User App Consent Restricted",
		Category:    "app-governance",
		Description: "Verifies non-admin users cannot consent to application permissions",
		Severity:    "high",
		SCuBAID:     "MS.AAD.5.2",
		Expected:    "User consent disabled or admin-only",
		Techniques:  []string{"T1528"},
		Tactics:     []string{"credential-access"},
	}

	script := `
$authPolicy = Get-MgPolicyAuthorizationPolicy
$grantPolicies = $authPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
if ($grantPolicies -eq $null -or $grantPolicies.Count -eq 0) {
    Write-Output "DISABLED"
} else {
    # Check if only admin consent policies are assigned
    $userConsent = $grantPolicies | Where-Object { $_ -like '*user-default*' -or $_ -like '*ManagePermissionGrantsForSelf*' }
    if ($userConsent) {
        Write-Output "USERCONSENT:$($grantPolicies -join ',')"
    } else {
        Write-Output "ADMINONLY:$($grantPolicies -join ',')"
    }
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying consent policies"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if output == "DISABLED" {
		result.Passed = true
		result.Actual = "User consent disabled"
		result.Details = "No permission grant policies assigned"
	} else if strings.HasPrefix(output, "ADMINONLY:") {
		policies := strings.TrimPrefix(output, "ADMINONLY:")
		result.Passed = true
		result.Actual = fmt.Sprintf("Admin-only consent: %s", policies)
		result.Details = result.Actual
	} else if strings.HasPrefix(output, "USERCONSENT:") {
		policies := strings.TrimPrefix(output, "USERCONSENT:")
		result.Passed = false
		result.Actual = fmt.Sprintf("User consent enabled: %s", policies)
		result.Details = "Users can consent to apps (should be restricted)"
	} else {
		result.Passed = false
		result.Actual = "Unable to determine consent policy"
		result.Details = output
	}

	return result
}

// checkAdminConsentWorkflow verifies admin consent workflow is enabled.
// SCuBA MS.AAD.5.3: An admin consent workflow SHALL be configured for applications.
func checkAdminConsentWorkflow() CheckResult {
	result := CheckResult{
		ControlID:   "CH-ITN-015",
		Name:        "Admin Consent Workflow Enabled",
		Category:    "app-governance",
		Description: "Verifies the admin consent request workflow is enabled",
		Severity:    "high",
		SCuBAID:     "MS.AAD.5.3",
		Expected:    "Admin consent workflow isEnabled = true",
		Techniques:  []string{"T1528"},
		Tactics:     []string{"credential-access"},
	}

	script := `
try {
    $consentPolicy = Get-MgPolicyAdminConsentRequestPolicy
    Write-Output "ENABLED:$($consentPolicy.IsEnabled)"
} catch {
    Write-Output "ERROR:$($_.Exception.Message)"
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying admin consent policy"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "ENABLED:") {
		value := strings.TrimPrefix(output, "ENABLED:")
		isEnabled := strings.EqualFold(strings.TrimSpace(value), "True")
		result.Passed = isEnabled
		result.Actual = fmt.Sprintf("isEnabled = %s", value)
		if result.Passed {
			result.Details = "Admin consent workflow is enabled"
		} else {
			result.Details = "Admin consent workflow is disabled"
		}
	} else {
		result.Passed = false
		result.Actual = "Unable to determine workflow status"
		result.Details = output
	}

	return result
}

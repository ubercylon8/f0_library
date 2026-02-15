//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
)

// RunGuestChecks validates CISA SCuBA Section 8: Guest Access
func RunGuestChecks() ValidatorResult {
	checks := []CheckResult{
		checkGuestAccessRestricted(),
		checkGuestInvitesLimited(),
		checkGuestDomainsRestricted(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Guest Access Controls",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkGuestAccessRestricted verifies guest user access is restricted.
// SCuBA MS.AAD.8.1: Guest users SHALL have limited access to directory objects.
func checkGuestAccessRestricted() CheckResult {
	result := CheckResult{
		Name:        "Guest Access Restricted",
		Category:    "guest",
		Description: "Verifies guest user role is set to restricted or more restrictive",
		Severity:    "medium",
		SCuBAID:     "MS.AAD.8.1",
		Expected:    "guestUserRoleId = restricted guest (2af84b1e-...) or more restrictive",
	}

	// Well-known guest role IDs:
	// a0b1b346-4d3e-4e8b-98f8-753987be4970 = Same as member users (most permissive)
	// 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Limited access (default)
	// 2af84b1e-32c8-42b7-82bc-daa82404023b = Restricted access (most restrictive)
	script := `
$authPolicy = Get-MgPolicyAuthorizationPolicy
$guestRoleId = $authPolicy.GuestUserRoleId
Write-Output "ROLEID:$guestRoleId"
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying authorization policy"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "ROLEID:") {
		roleId := strings.TrimSpace(strings.TrimPrefix(output, "ROLEID:"))

		switch strings.ToLower(roleId) {
		case "2af84b1e-32c8-42b7-82bc-daa82404023b":
			result.Passed = true
			result.Actual = "Restricted guest access"
			result.Details = "Most restrictive setting"
		case "10dae51f-b6af-4016-8d66-8c2a99b929b3":
			result.Passed = true
			result.Actual = "Limited guest access (default)"
			result.Details = "Acceptable but consider restricting further"
		case "a0b1b346-4d3e-4e8b-98f8-753987be4970":
			result.Passed = false
			result.Actual = "Guest access same as member users"
			result.Details = "Too permissive -- guests should have limited access"
		default:
			result.Passed = false
			result.Actual = fmt.Sprintf("Unknown guest role ID: %s", roleId)
			result.Details = "Verify guest access configuration"
		}
	} else {
		result.Passed = false
		result.Actual = "Unable to determine guest role"
		result.Details = output
	}

	return result
}

// checkGuestInvitesLimited verifies guest invitations are restricted to admins.
// SCuBA MS.AAD.8.2: Guest invites SHOULD be limited to users with specific admin roles.
func checkGuestInvitesLimited() CheckResult {
	result := CheckResult{
		Name:        "Guest Invites Limited",
		Category:    "guest",
		Description: "Verifies guest invitations are restricted to admins and guest inviters",
		Severity:    "medium",
		SCuBAID:     "MS.AAD.8.2",
		Expected:    "allowInvitesFrom = adminsAndGuestInviters or none",
	}

	script := `
$authPolicy = Get-MgPolicyAuthorizationPolicy
$inviteSetting = $authPolicy.AllowInvitesFrom
Write-Output "SETTING:$inviteSetting"
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying invitation settings"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "SETTING:") {
		setting := strings.TrimSpace(strings.TrimPrefix(output, "SETTING:"))

		switch strings.ToLower(setting) {
		case "none":
			result.Passed = true
			result.Actual = "Guest invitations disabled"
			result.Details = "Most restrictive"
		case "adminsandguestinviters":
			result.Passed = true
			result.Actual = "Admins and guest inviters only"
			result.Details = "Acceptable restriction"
		case "adminsguestinvitersandallmembers", "everyone":
			result.Passed = false
			result.Actual = fmt.Sprintf("allowInvitesFrom = %s", setting)
			result.Details = "Too permissive -- restrict to admins"
		default:
			result.Passed = false
			result.Actual = fmt.Sprintf("allowInvitesFrom = %s", setting)
			result.Details = "Verify invitation restriction settings"
		}
	} else {
		result.Passed = false
		result.Actual = "Unable to determine invitation settings"
		result.Details = output
	}

	return result
}

// checkGuestDomainsRestricted verifies cross-tenant access policies restrict guest domains.
// SCuBA MS.AAD.8.3: Guest access SHALL be restricted by domain.
func checkGuestDomainsRestricted() CheckResult {
	result := CheckResult{
		Name:        "Guest Domains Restricted",
		Category:    "guest",
		Description: "Verifies cross-tenant access policy has domain restrictions for guests",
		Severity:    "medium",
		SCuBAID:     "MS.AAD.8.3",
		Expected:    "Cross-tenant access policy with domain allow/block list",
	}

	script := `
try {
    $ctap = Get-MgPolicyCrossTenantAccessPolicyDefault -ErrorAction Stop
    $inbound = $ctap.B2BCollaborationInbound
    if ($inbound) {
        $usersAndGroups = $inbound.UsersAndGroups
        if ($usersAndGroups -and $usersAndGroups.AccessType -eq 'blocked') {
            Write-Output "RESTRICTED:blocked"
        } elseif ($usersAndGroups -and $usersAndGroups.AccessType -eq 'allowed') {
            Write-Output "RESTRICTED:allowlist"
        } else {
            Write-Output "DEFAULT"
        }
    } else {
        Write-Output "DEFAULT"
    }
} catch {
    # Check partner policies for domain restrictions
    try {
        $partners = Get-MgPolicyCrossTenantAccessPolicyPartner -All -ErrorAction Stop
        if ($partners.Count -gt 0) {
            Write-Output "PARTNERS:$($partners.Count)"
        } else {
            Write-Output "NOPARTNERS"
        }
    } catch {
        Write-Output "ERROR:$($_.Exception.Message)"
    }
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying cross-tenant access policy"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "RESTRICTED:") {
		restrictType := strings.TrimPrefix(output, "RESTRICTED:")
		result.Passed = true
		result.Actual = fmt.Sprintf("Cross-tenant access restricted (%s)", restrictType)
		result.Details = result.Actual
	} else if strings.HasPrefix(output, "PARTNERS:") {
		count := strings.TrimPrefix(output, "PARTNERS:")
		result.Passed = true
		result.Actual = fmt.Sprintf("%s partner organization policies configured", count)
		result.Details = "Domain-level partner restrictions in place"
	} else if output == "DEFAULT" || output == "NOPARTNERS" {
		result.Passed = false
		result.Actual = "Using default cross-tenant access (open to all)"
		result.Details = "Configure domain allowlist or blocklist"
	} else {
		result.Passed = false
		result.Actual = "Unable to assess cross-tenant policy"
		result.Details = output
	}

	return result
}

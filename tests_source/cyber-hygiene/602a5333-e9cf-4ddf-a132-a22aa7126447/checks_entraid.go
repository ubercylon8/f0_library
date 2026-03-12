//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// entraSkipReason is the reason Entra checks were skipped (set when Graph is unavailable)
const entraSkipReason = "Skipped: Graph API not available"

// RunEntraIDChecks validates CIS Entra ID controls (CH-CIA-022 to CH-CIA-028).
// If Graph API is not available (env vars not set), all 7 checks are returned as skipped.
func RunEntraIDChecks() ValidatorResult {
	// If Graph API is not available, return all checks as skipped
	if !graphAvailable {
		checks := entraSkippedChecks()
		return ValidatorResult{
			Name:        "Entra ID Controls",
			Checks:      checks,
			PassedCount: 0,
			FailedCount: len(checks),
			TotalChecks: len(checks),
			IsCompliant: false,
		}
	}

	checks := []CheckResult{
		checkEntraMFAAllUsers(),
		checkEntraMFAAdmins(),
		checkEntraLegacyAuthBlocked(),
		checkEntraPIMEnabled(),
		checkEntraAppRegistration(),
		checkEntraSecurityDefaultsOrCA(),
		checkEntraBreakGlassAccounts(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Entra ID Controls",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// entraSkippedChecks returns all 7 Entra checks as skipped (for when Graph is unavailable)
func entraSkippedChecks() []CheckResult {
	return []CheckResult{
		{ControlID: "CH-CIA-022", Name: "MFA for All Users", Category: "entra-id", Severity: "critical",
			Expected: "CA policy requiring MFA", Actual: "Skipped", Details: entraSkipReason,
			Techniques: []string{"T1078.004", "T1556.007"}, Tactics: []string{"credential-access", "persistence"}},
		{ControlID: "CH-CIA-023", Name: "MFA for Admin Roles", Category: "entra-id", Severity: "critical",
			Expected: "CA policy requiring MFA for admins", Actual: "Skipped", Details: entraSkipReason,
			Techniques: []string{"T1078.004", "T1556.007"}, Tactics: []string{"credential-access", "persistence"}},
		{ControlID: "CH-CIA-024", Name: "Legacy Auth Blocked", Category: "entra-id", Severity: "high",
			Expected: "CA policy blocking legacy auth", Actual: "Skipped", Details: entraSkipReason,
			Techniques: []string{"T1078.004"}, Tactics: []string{"credential-access"}},
		{ControlID: "CH-CIA-025", Name: "PIM for JIT Access", Category: "entra-id", Severity: "high",
			Expected: "PIM enabled for privileged roles", Actual: "Skipped", Details: entraSkipReason,
			Techniques: []string{"T1078.004", "T1098.003"}, Tactics: []string{"credential-access", "persistence"}},
		{ControlID: "CH-CIA-026", Name: "App Registration Restricted", Category: "entra-id", Severity: "medium",
			Expected: "Users cannot register apps", Actual: "Skipped", Details: entraSkipReason,
			Techniques: []string{"T1098.001"}, Tactics: []string{"persistence"}},
		{ControlID: "CH-CIA-027", Name: "Security Defaults or CA", Category: "entra-id", Severity: "high",
			Expected: "Security Defaults or CA policies active", Actual: "Skipped", Details: entraSkipReason,
			Techniques: []string{"T1078.004"}, Tactics: []string{"credential-access"}},
		{ControlID: "CH-CIA-028", Name: "Break-Glass Accounts", Category: "entra-id", Severity: "critical",
			Expected: ">=2 Global Admin accounts for emergency", Actual: "Skipped", Details: entraSkipReason,
			Techniques: []string{"T1078.004"}, Tactics: []string{"credential-access"}},
	}
}

// checkEntraMFAAllUsers verifies Conditional Access policy requires MFA for all users.
func checkEntraMFAAllUsers() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-022",
		Name:        "MFA for All Users",
		Category:    "entra-id",
		Description: "Verifies a Conditional Access policy requires MFA for all users",
		Severity:    "critical",
		Expected:    "CA policy requiring MFA for all users and all cloud apps",
		Techniques:  []string{"T1078.004", "T1556.007"},
		Tactics:     []string{"credential-access", "persistence"},
	}

	script := `
$policies = Get-MgIdentityConditionalAccessPolicy -All
$mfaPolicy = $policies | Where-Object {
    $_.State -eq 'enabled' -and
    ($_.GrantControls.BuiltInControls -contains 'mfa' -or
     $_.GrantControls.AuthenticationStrength.Id -ne $null) -and
    ($_.Conditions.Users.IncludeUsers -contains 'All' -or $_.Conditions.Users.IncludeGroups.Count -gt 0)
}
if ($mfaPolicy) {
    $names = ($mfaPolicy | Select-Object -First 3 | ForEach-Object { $_.DisplayName }) -join '; '
    Write-Output "FOUND:$($mfaPolicy.Count)|$names"
} else {
    Write-Output "NOTFOUND"
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
		parts := strings.SplitN(strings.TrimPrefix(output, "FOUND:"), "|", 2)
		count := parts[0]
		names := ""
		if len(parts) > 1 {
			names = parts[1]
		}
		result.Passed = true
		result.Actual = fmt.Sprintf("%s MFA policies: %s", count, names)
		result.Details = result.Actual
	} else {
		result.Passed = false
		result.Actual = "No MFA enforcement policy found"
		result.Details = "No CA policy requires MFA for all users"
	}

	return result
}

// checkEntraMFAAdmins verifies Conditional Access policy requires MFA for admin roles.
func checkEntraMFAAdmins() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-023",
		Name:        "MFA for Admin Roles",
		Category:    "entra-id",
		Description: "Verifies a Conditional Access policy requires MFA targeting directory admin roles",
		Severity:    "critical",
		Expected:    "CA policy with MFA targeting admin roles",
		Techniques:  []string{"T1078.004", "T1556.007"},
		Tactics:     []string{"credential-access", "persistence"},
	}

	script := `
$policies = Get-MgIdentityConditionalAccessPolicy -All
$adminPolicy = $policies | Where-Object {
    $_.State -eq 'enabled' -and
    ($_.GrantControls.BuiltInControls -contains 'mfa' -or
     $_.GrantControls.AuthenticationStrength.Id -ne $null) -and
    ($_.Conditions.Users.IncludeRoles.Count -gt 0)
}
if ($adminPolicy) {
    $roleCount = ($adminPolicy | ForEach-Object { $_.Conditions.Users.IncludeRoles } | Sort-Object -Unique).Count
    Write-Output "FOUND:$($adminPolicy.Count)|$roleCount"
} else {
    Write-Output "NOTFOUND"
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
		parts := strings.SplitN(strings.TrimPrefix(output, "FOUND:"), "|", 2)
		policyCount := parts[0]
		roleCount := "0"
		if len(parts) > 1 {
			roleCount = parts[1]
		}
		result.Passed = true
		result.Actual = fmt.Sprintf("%s policies covering %s admin roles", policyCount, roleCount)
		result.Details = result.Actual
	} else {
		result.Passed = false
		result.Actual = "No admin-targeted MFA policy found"
		result.Details = "No CA policy targets admin roles with MFA"
	}

	return result
}

// checkEntraLegacyAuthBlocked verifies legacy authentication is blocked via CA policy.
func checkEntraLegacyAuthBlocked() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-024",
		Name:        "Legacy Auth Blocked",
		Category:    "entra-id",
		Description: "Verifies a Conditional Access policy blocks legacy authentication protocols",
		Severity:    "high",
		Expected:    "CA policy blocking legacy auth (exchangeActiveSync, other)",
		Techniques:  []string{"T1078.004"},
		Tactics:     []string{"credential-access"},
	}

	script := `
$policies = Get-MgIdentityConditionalAccessPolicy -All
$blockLegacy = $policies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.GrantControls.BuiltInControls -contains 'block' -and
    ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
     $_.Conditions.ClientAppTypes -contains 'other')
}
if ($blockLegacy) {
    Write-Output "FOUND:$($blockLegacy[0].DisplayName)"
} else {
    Write-Output "NOTFOUND"
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
	} else {
		result.Passed = false
		result.Actual = "Legacy authentication not blocked"
		result.Details = "No CA policy blocks legacy auth protocols"
	}

	return result
}

// checkEntraPIMEnabled verifies Privileged Identity Management is enabled for privileged roles.
func checkEntraPIMEnabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-025",
		Name:        "PIM for JIT Access",
		Category:    "entra-id",
		Description: "Verifies Privileged Identity Management (PIM) is enabled for just-in-time access",
		Severity:    "high",
		Expected:    "PIM enabled and configured for privileged roles",
		Techniques:  []string{"T1078.004", "T1098.003"},
		Tactics:     []string{"credential-access", "persistence"},
	}

	script := `
try {
    $policies = Get-MgPolicyRoleManagementPolicy -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" -All -ErrorAction Stop
    Write-Output "ENABLED:$($policies.Count)"
} catch {
    if ($_.Exception.Message -like '*license*' -or $_.Exception.Message -like '*PIM*' -or $_.Exception.Message -like '*Forbidden*') {
        Write-Output "NOLICENSE"
    } else {
        Write-Output "ERROR:$($_.Exception.Message)"
    }
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying PIM"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "ENABLED:") {
		countStr := strings.TrimPrefix(output, "ENABLED:")
		count, _ := strconv.Atoi(strings.TrimSpace(countStr))
		result.Passed = count > 0
		result.Actual = fmt.Sprintf("PIM active with %d role policies", count)
		result.Details = "PIM is configured for directory roles"
	} else if output == "NOLICENSE" {
		result.Passed = false
		result.Actual = "PIM not available (requires Entra ID P2)"
		result.Details = "PIM requires Entra ID P2 or Governance license"
	} else {
		result.Passed = false
		result.Actual = "Unable to determine PIM status"
		result.Details = output
	}

	return result
}

// checkEntraAppRegistration verifies users cannot freely register applications.
func checkEntraAppRegistration() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-026",
		Name:        "App Registration Restricted",
		Category:    "entra-id",
		Description: "Verifies users are restricted from registering applications (admin-only)",
		Severity:    "medium",
		Expected:    "Users cannot register apps (allowedToCreateApps = false)",
		Techniques:  []string{"T1098.001"},
		Tactics:     []string{"persistence"},
	}

	script := `
try {
    $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
    $defaultPerm = $authPolicy.DefaultUserRolePermissions
    $canCreateApps = $defaultPerm.AllowedToCreateApps
    Write-Output "CANCREATE:$canCreateApps"
} catch {
    Write-Output "ERROR:$($_.Exception.Message)"
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying authorization policy"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "CANCREATE:") {
		val := strings.TrimPrefix(output, "CANCREATE:")
		canCreate := strings.EqualFold(strings.TrimSpace(val), "True")
		result.Passed = !canCreate
		if canCreate {
			result.Actual = "Users CAN register applications"
			result.Details = "Set allowedToCreateApps = false in Authorization Policy"
		} else {
			result.Actual = "Users CANNOT register applications"
			result.Details = "App registration restricted to admins"
		}
	} else {
		result.Passed = false
		result.Actual = "Unable to determine app registration policy"
		result.Details = output
	}

	return result
}

// checkEntraSecurityDefaultsOrCA verifies Security Defaults are on OR Conditional Access policies exist.
func checkEntraSecurityDefaultsOrCA() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-027",
		Name:        "Security Defaults or CA",
		Category:    "entra-id",
		Description: "Verifies either Security Defaults are enabled OR Conditional Access policies are active",
		Severity:    "high",
		Expected:    "Security Defaults enabled OR active CA policies",
		Techniques:  []string{"T1078.004"},
		Tactics:     []string{"credential-access"},
	}

	script := `
# Check Security Defaults
try {
    $secDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
    $secDefaultsEnabled = $secDefaults.IsEnabled
} catch {
    $secDefaultsEnabled = $false
}

# Count active CA policies
$caPolicies = Get-MgIdentityConditionalAccessPolicy -All | Where-Object { $_.State -eq 'enabled' }
$caCount = @($caPolicies).Count

if ($secDefaultsEnabled) {
    Write-Output "SECDEFAULTS:true|$caCount"
} else {
    Write-Output "SECDEFAULTS:false|$caCount"
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying security defaults"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "SECDEFAULTS:") {
		parts := strings.SplitN(strings.TrimPrefix(output, "SECDEFAULTS:"), "|", 2)
		secDefaultsEnabled := strings.EqualFold(strings.TrimSpace(parts[0]), "true")
		caCount := 0
		if len(parts) > 1 {
			caCount, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
		}

		result.Passed = secDefaultsEnabled || caCount > 0
		if secDefaultsEnabled {
			result.Actual = fmt.Sprintf("Security Defaults enabled (%d CA policies)", caCount)
			result.Details = "Security Defaults provides baseline protection"
		} else if caCount > 0 {
			result.Actual = fmt.Sprintf("Security Defaults disabled, %d active CA policies", caCount)
			result.Details = "Conditional Access policies provide custom protection"
		} else {
			result.Actual = "Security Defaults disabled AND no active CA policies"
			result.Details = "CRITICAL: Enable Security Defaults or create CA policies"
		}
	} else {
		result.Passed = false
		result.Actual = "Unable to determine security posture"
		result.Details = output
	}

	return result
}

// checkEntraBreakGlassAccounts verifies at least 2 Global Admin accounts exist for emergency access.
func checkEntraBreakGlassAccounts() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-028",
		Name:        "Break-Glass Accounts",
		Category:    "entra-id",
		Description: "Verifies at least 2 Global Admin accounts exist for emergency access (break-glass)",
		Severity:    "critical",
		Expected:    ">=2 Global Admin accounts",
		Techniques:  []string{"T1078.004"},
		Tactics:     []string{"credential-access"},
	}

	script := `
$gaRoleId = '62e90394-69f5-4237-9190-012177145e10'
try {
    $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$gaRoleId'" -ErrorAction Stop
    if (-not $role) {
        Write-Output "NOROLE"
        return
    }
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
    $userMembers = $members | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' }
    $count = @($userMembers).Count

    # Check which are excluded from CA policies (potential break-glass)
    $caPolicies = Get-MgIdentityConditionalAccessPolicy -All | Where-Object { $_.State -eq 'enabled' }
    $excludedUsers = @()
    foreach ($p in $caPolicies) {
        $excludedUsers += $p.Conditions.Users.ExcludeUsers
    }
    $excludedUsers = $excludedUsers | Sort-Object -Unique

    $breakGlass = @($userMembers | Where-Object { $excludedUsers -contains $_.Id })
    Write-Output "GACOUNT:$count"
    Write-Output "EXCLUDED:$($breakGlass.Count)"
} catch {
    Write-Output "ERROR:$($_.Exception.Message)"
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying Global Admin accounts"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if output == "NOROLE" {
		result.Passed = false
		result.Actual = "Global Admin role not activated"
		result.Details = "No activated Global Admin role found"
		return result
	}

	lines := strings.Split(output, "\n")
	gaCount := 0
	excludedCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "GACOUNT:") {
			gaCount, _ = strconv.Atoi(strings.TrimPrefix(line, "GACOUNT:"))
		}
		if strings.HasPrefix(line, "EXCLUDED:") {
			excludedCount, _ = strconv.Atoi(strings.TrimPrefix(line, "EXCLUDED:"))
		}
	}

	result.Passed = gaCount >= 2
	result.Actual = fmt.Sprintf("%d Global Admins, %d excluded from CA policies (break-glass candidates)", gaCount, excludedCount)
	if gaCount >= 2 {
		if excludedCount >= 2 {
			result.Details = "Adequate emergency access accounts with CA exclusions"
		} else {
			result.Details = fmt.Sprintf("%d GAs exist but only %d excluded from CA (recommend >=2 excluded)", gaCount, excludedCount)
		}
	} else if gaCount == 1 {
		result.Details = "Only 1 Global Admin - create at least 1 more break-glass account"
	} else {
		result.Details = "No Global Admins found (critical issue)"
	}

	return result
}

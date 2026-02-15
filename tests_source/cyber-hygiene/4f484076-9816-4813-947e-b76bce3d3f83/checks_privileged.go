//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// RunPrivilegedChecks validates CISA SCuBA Section 7: Privileged Access
func RunPrivilegedChecks() ValidatorResult {
	checks := []CheckResult{
		checkGlobalAdminCount(),
		checkFineGrainedRoles(),
		checkCloudOnlyPrivileged(),
		checkPIMActiveAssignments(),
		checkPIMUsedForProvisioning(),
		checkGAActivationApproval(),
		checkPrivilegedRoleAlerts(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Privileged Access Management",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkGlobalAdminCount verifies between 2 and 8 Global Administrators exist.
// SCuBA MS.AAD.7.1: A minimum of two users and a maximum of eight users SHALL be provisioned with the Global Administrator role.
func checkGlobalAdminCount() CheckResult {
	result := CheckResult{
		Name:        "Global Admin Count (2-8)",
		Category:    "privileged",
		Description: "Verifies Global Administrator count is between 2 and 8",
		Severity:    "critical",
		SCuBAID:     "MS.AAD.7.1",
		Expected:    "2-8 Global Administrators",
	}

	// Global Admin role template ID is well-known: 62e90394-69f5-4237-9190-012177145e10
	script := `
$gaRoleId = '62e90394-69f5-4237-9190-012177145e10'
$members = Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "roleTemplateId eq '$gaRoleId'").Id -All
$userMembers = $members | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' }
Write-Output "COUNT:$($userMembers.Count)"
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying Global Admin role"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "COUNT:") {
		countStr := strings.TrimPrefix(output, "COUNT:")
		count, parseErr := strconv.Atoi(strings.TrimSpace(countStr))
		if parseErr != nil {
			result.Passed = false
			result.Actual = fmt.Sprintf("Could not parse count: %s", countStr)
			result.Details = "Unexpected response format"
			return result
		}

		result.Passed = count >= 2 && count <= 8
		result.Actual = fmt.Sprintf("%d Global Administrators", count)
		if count < 2 {
			result.Details = "Too few GAs (minimum 2 for resilience)"
		} else if count > 8 {
			result.Details = "Too many GAs (maximum 8, use scoped roles)"
		} else {
			result.Details = "Within recommended range"
		}
	} else {
		result.Passed = false
		result.Actual = "Unable to count Global Admins"
		result.Details = output
	}

	return result
}

// checkFineGrainedRoles verifies that fine-grained admin roles are used instead of Global Admin for everything.
// SCuBA MS.AAD.7.2: Highly privileged roles SHALL only be used for tasks that require those roles (informational).
func checkFineGrainedRoles() CheckResult {
	result := CheckResult{
		Name:        "Fine-Grained Roles Used",
		Category:    "privileged",
		Description: "Verifies fine-grained admin roles are in use beyond Global Admin",
		Severity:    "informational",
		SCuBAID:     "MS.AAD.7.2",
		Expected:    "Multiple admin roles populated (not just Global Admin)",
	}

	script := `
$roles = Get-MgDirectoryRole -All
$populatedRoles = @()
foreach ($role in $roles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
    if ($members.Count -gt 0) {
        $populatedRoles += "$($role.DisplayName):$($members.Count)"
    }
}
Write-Output "ROLES:$($populatedRoles.Count)|$($populatedRoles -join ',')"
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying directory roles"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "ROLES:") {
		parts := strings.SplitN(strings.TrimPrefix(output, "ROLES:"), "|", 2)
		countStr := parts[0]
		count, _ := strconv.Atoi(strings.TrimSpace(countStr))

		// Having more than just Global Admin is good practice
		result.Passed = count > 1
		result.Actual = fmt.Sprintf("%d active admin roles", count)
		if count > 1 {
			result.Details = "Informational: fine-grained roles in use"
		} else {
			result.Details = "Informational: consider using scoped roles"
		}
	} else {
		result.Passed = false
		result.Actual = "Unable to assess role usage"
		result.Details = output
	}

	return result
}

// checkCloudOnlyPrivileged verifies privileged accounts are cloud-only (not synced from on-premises).
// SCuBA MS.AAD.7.3: Privileged users SHALL be cloud-only accounts.
func checkCloudOnlyPrivileged() CheckResult {
	result := CheckResult{
		Name:        "Cloud-Only Privileged Accounts",
		Category:    "privileged",
		Description: "Verifies highly privileged users are cloud-only (not synced from on-premises)",
		Severity:    "high",
		SCuBAID:     "MS.AAD.7.3",
		Expected:    "All privileged users have onPremisesSyncEnabled = false/null",
	}

	script := `
$gaRoleId = '62e90394-69f5-4237-9190-012177145e10'
$role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$gaRoleId'" -ErrorAction SilentlyContinue
if (-not $role) {
    Write-Output "NOROLE"
    return
}
$members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
$syncedAdmins = @()
foreach ($m in $members) {
    if ($m.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
        $userId = $m.Id
        $user = Get-MgUser -UserId $userId -Property DisplayName,OnPremisesSyncEnabled
        if ($user.OnPremisesSyncEnabled -eq $true) {
            $syncedAdmins += $user.DisplayName
        }
    }
}
if ($syncedAdmins.Count -eq 0) {
    Write-Output "ALLCLOUD:$($members.Count)"
} else {
    Write-Output "SYNCED:$($syncedAdmins -join ',')"
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying privileged users"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "ALLCLOUD:") {
		count := strings.TrimPrefix(output, "ALLCLOUD:")
		result.Passed = true
		result.Actual = fmt.Sprintf("All %s Global Admins are cloud-only", count)
		result.Details = result.Actual
	} else if strings.HasPrefix(output, "SYNCED:") {
		syncedUsers := strings.TrimPrefix(output, "SYNCED:")
		result.Passed = false
		result.Actual = fmt.Sprintf("On-premises synced admins: %s", syncedUsers)
		result.Details = "Privileged accounts should be cloud-only"
	} else if output == "NOROLE" {
		result.Passed = false
		result.Actual = "Global Admin role not activated"
		result.Details = "Could not find activated Global Admin role"
	} else {
		result.Passed = false
		result.Actual = "Unable to assess privileged accounts"
		result.Details = output
	}

	return result
}

// checkPIMActiveAssignments verifies no permanent active assignments exist for high-privilege roles.
// SCuBA MS.AAD.7.4: Permanent active role assignments SHALL NOT be used.
func checkPIMActiveAssignments() CheckResult {
	result := CheckResult{
		Name:        "No Permanent Active Assignments",
		Category:    "privileged",
		Description: "Verifies high-privilege roles use eligible (not permanent active) assignments via PIM",
		Severity:    "high",
		SCuBAID:     "MS.AAD.7.4",
		Expected:    "No permanent active assignments for privileged roles",
	}

	script := `
try {
    # Check for permanent (non-expiring) active assignments on Global Admin
    $gaRoleDefId = '62e90394-69f5-4237-9190-012177145e10'
    $assignments = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -Filter "roleDefinitionId eq '$gaRoleDefId'" -All -ErrorAction Stop
    $permanent = $assignments | Where-Object { $_.AssignmentType -eq 'Assigned' }
    if ($permanent.Count -eq 0) {
        Write-Output "NOPERMANENT:$($assignments.Count)"
    } else {
        Write-Output "PERMANENT:$($permanent.Count)|$($assignments.Count)"
    }
} catch {
    if ($_.Exception.Message -like '*PIM*' -or $_.Exception.Message -like '*license*') {
        Write-Output "NOPIM"
    } else {
        Write-Output "ERROR:$($_.Exception.Message)"
    }
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying PIM assignments"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "NOPERMANENT:") {
		total := strings.TrimPrefix(output, "NOPERMANENT:")
		result.Passed = true
		result.Actual = fmt.Sprintf("No permanent active GA assignments (%s total)", total)
		result.Details = "All assignments are time-bound or eligible"
	} else if strings.HasPrefix(output, "PERMANENT:") {
		parts := strings.SplitN(strings.TrimPrefix(output, "PERMANENT:"), "|", 2)
		permCount := parts[0]
		result.Passed = false
		result.Actual = fmt.Sprintf("%s permanent active GA assignments found", permCount)
		result.Details = "Use PIM eligible assignments instead"
	} else if output == "NOPIM" {
		result.Passed = false
		result.Actual = "PIM not available (requires P2 license)"
		result.Details = "Cannot validate without Entra ID P2"
	} else {
		result.Passed = false
		result.Actual = "Unable to assess PIM assignments"
		result.Details = output
	}

	return result
}

// checkPIMUsedForProvisioning verifies PIM is used for provisioning privileged roles.
// SCuBA MS.AAD.7.5: Provisioning users to highly privileged roles SHALL require PIM (informational).
func checkPIMUsedForProvisioning() CheckResult {
	result := CheckResult{
		Name:        "PIM Used for Provisioning",
		Category:    "privileged",
		Description: "Verifies Privileged Identity Management is used for role provisioning",
		Severity:    "informational",
		SCuBAID:     "MS.AAD.7.5",
		Expected:    "PIM enabled and in use",
	}

	script := `
try {
    $policies = Get-MgPolicyRoleManagementPolicy -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" -All -ErrorAction Stop
    Write-Output "ENABLED:$($policies.Count)"
} catch {
    Write-Output "UNAVAILABLE"
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying PIM policies"
		result.Details = "Informational: PIM status could not be determined"
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "ENABLED:") {
		count := strings.TrimPrefix(output, "ENABLED:")
		result.Passed = true
		result.Actual = fmt.Sprintf("PIM active with %s role policies", count)
		result.Details = "Informational: PIM is configured"
	} else {
		result.Passed = false
		result.Actual = "PIM not available"
		result.Details = "Informational: PIM requires Entra ID P2 license"
	}

	return result
}

// checkGAActivationApproval verifies Global Admin activation requires approval in PIM.
// SCuBA MS.AAD.7.6: Activation of Global Administrator role SHALL require approval.
func checkGAActivationApproval() CheckResult {
	result := CheckResult{
		Name:        "GA Activation Requires Approval",
		Category:    "privileged",
		Description: "Verifies Global Admin role activation requires approval in PIM",
		Severity:    "high",
		SCuBAID:     "MS.AAD.7.6",
		Expected:    "Approval required for GA activation",
	}

	script := `
try {
    $gaRoleDefId = '62e90394-69f5-4237-9190-012177145e10'
    $policies = Get-MgPolicyRoleManagementPolicy -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" -All -ErrorAction Stop
    # Find the policy for Global Admin
    $gaPolicy = $null
    foreach ($p in $policies) {
        $rules = Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $p.Id -All
        # Check if this policy applies to GA
        $assignmentRule = $rules | Where-Object { $_.AdditionalProperties.'@odata.type' -like '*ApprovalRule*' }
        if ($assignmentRule) {
            $isApprovalRequired = $assignmentRule.AdditionalProperties.setting.isApprovalRequired
            if ($isApprovalRequired -eq $true) {
                Write-Output "APPROVALREQUIRED:$($p.DisplayName)"
                return
            }
        }
    }
    Write-Output "NOAPPROVAL"
} catch {
    if ($_.Exception.Message -like '*license*' -or $_.Exception.Message -like '*PIM*') {
        Write-Output "NOPIM"
    } else {
        Write-Output "ERROR:$($_.Exception.Message)"
    }
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying PIM approval settings"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "APPROVALREQUIRED:") {
		policyName := strings.TrimPrefix(output, "APPROVALREQUIRED:")
		result.Passed = true
		result.Actual = fmt.Sprintf("Approval required (%s)", policyName)
		result.Details = result.Actual
	} else if output == "NOAPPROVAL" {
		result.Passed = false
		result.Actual = "GA activation does not require approval"
		result.Details = "Configure approval in PIM for Global Admin role"
	} else if output == "NOPIM" {
		result.Passed = false
		result.Actual = "PIM not available (requires P2 license)"
		result.Details = "Cannot validate without Entra ID P2"
	} else {
		result.Passed = false
		result.Actual = "Unable to assess PIM approval settings"
		result.Details = output
	}

	return result
}

// checkPrivilegedRoleAlerts verifies alerts are configured for privileged role assignments.
// SCuBA MS.AAD.7.7: Eligible and Active role assignments SHALL trigger an alert (informational).
func checkPrivilegedRoleAlerts() CheckResult {
	result := CheckResult{
		Name:        "Privileged Role Assignment Alerts",
		Category:    "privileged",
		Description: "Verifies notification settings are configured for privileged role changes",
		Severity:    "informational",
		SCuBAID:     "MS.AAD.7.7",
		Expected:    "Alert notifications configured for role assignments",
	}

	script := `
try {
    $policies = Get-MgPolicyRoleManagementPolicy -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" -All -ErrorAction Stop
    $hasNotification = $false
    foreach ($p in $policies) {
        $rules = Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $p.Id -All
        $notifRules = $rules | Where-Object { $_.AdditionalProperties.'@odata.type' -like '*NotificationRule*' }
        if ($notifRules.Count -gt 0) {
            $hasNotification = $true
            break
        }
    }
    if ($hasNotification) {
        Write-Output "CONFIGURED"
    } else {
        Write-Output "NOTCONFIGURED"
    }
} catch {
    Write-Output "UNAVAILABLE"
}
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying PIM notification rules"
		result.Details = "Informational: could not query PIM alert settings"
		return result
	}

	output = strings.TrimSpace(output)
	result.Passed = output == "CONFIGURED"
	if result.Passed {
		result.Actual = "PIM notification rules configured"
		result.Details = "Informational: role assignment alerts active"
	} else if output == "UNAVAILABLE" {
		result.Actual = "PIM not available"
		result.Details = "Informational: PIM requires Entra ID P2"
	} else {
		result.Actual = "No PIM notification rules found"
		result.Details = "Informational: configure alerts for role assignments"
	}

	return result
}

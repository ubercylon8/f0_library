//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// RunPrivAccountChecks validates CIS Privileged Account Management controls (CH-CIA-001 to CH-CIA-005)
func RunPrivAccountChecks() ValidatorResult {
	checks := []CheckResult{
		checkDomainAdminsCount(),
		checkEnterpriseAdminsCount(),
		checkSchemaAdminsCount(),
		checkProtectedUsersPopulated(),
		checkAdminSDHolderClean(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Privileged Account Management",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkDomainAdminsCount verifies Domain Admins group has 5 or fewer members.
// CIS L1: Minimize the number of members in the Domain Admins group.
func checkDomainAdminsCount() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-001",
		Name:        "Domain Admins Count <=5",
		Category:    "privileged-account",
		Description: "Verifies Domain Admins group has 5 or fewer direct members",
		Severity:    "critical",
		Expected:    "<=5 members in Domain Admins",
		Techniques:  []string{"T1078.002", "T1098.003"},
		Tactics:     []string{"credential-access", "privilege-escalation"},
	}

	script := `
$members = Get-ADGroupMember 'Domain Admins' -ErrorAction Stop
$count = @($members).Count
Write-Output "COUNT:$count"
$names = ($members | ForEach-Object { $_.SamAccountName }) -join ', '
Write-Output "NAMES:$names"
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying Domain Admins group"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	lines := strings.Split(output, "\n")
	count := 0
	names := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COUNT:") {
			countStr := strings.TrimPrefix(line, "COUNT:")
			count, _ = strconv.Atoi(strings.TrimSpace(countStr))
		}
		if strings.HasPrefix(line, "NAMES:") {
			names = strings.TrimPrefix(line, "NAMES:")
		}
	}

	result.Passed = count <= 5
	result.Actual = fmt.Sprintf("%d members: %s", count, names)
	if count <= 5 {
		result.Details = fmt.Sprintf("%d Domain Admins (within limit)", count)
	} else {
		result.Details = fmt.Sprintf("%d Domain Admins (exceeds limit of 5)", count)
	}

	return result
}

// checkEnterpriseAdminsCount verifies Enterprise Admins group is empty (or minimal).
// CIS L1: Enterprise Admins group should be empty for day-to-day operations.
func checkEnterpriseAdminsCount() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-002",
		Name:        "Enterprise Admins Empty",
		Category:    "privileged-account",
		Description: "Verifies Enterprise Admins group has 0 members (forest-level privilege)",
		Severity:    "critical",
		Expected:    "0 members in Enterprise Admins",
		Techniques:  []string{"T1078.002", "T1098.003"},
		Tactics:     []string{"credential-access", "privilege-escalation"},
	}

	script := `
try {
    $members = Get-ADGroupMember 'Enterprise Admins' -ErrorAction Stop
    $count = @($members).Count
    Write-Output "COUNT:$count"
    if ($count -gt 0) {
        $names = ($members | ForEach-Object { $_.SamAccountName }) -join ', '
        Write-Output "NAMES:$names"
    }
} catch {
    if ($_.Exception.Message -like '*cannot find*') {
        Write-Output "NOTFOUND"
    } else {
        throw $_
    }
}
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying Enterprise Admins group"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if output == "NOTFOUND" {
		result.Passed = true
		result.Actual = "Enterprise Admins group not found (single-domain forest)"
		result.Details = "Not applicable in this domain"
		return result
	}

	lines := strings.Split(output, "\n")
	count := 0
	names := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COUNT:") {
			countStr := strings.TrimPrefix(line, "COUNT:")
			count, _ = strconv.Atoi(strings.TrimSpace(countStr))
		}
		if strings.HasPrefix(line, "NAMES:") {
			names = strings.TrimPrefix(line, "NAMES:")
		}
	}

	result.Passed = count == 0
	if count == 0 {
		result.Actual = "Enterprise Admins group is empty"
		result.Details = "No members (compliant)"
	} else {
		result.Actual = fmt.Sprintf("%d members: %s", count, names)
		result.Details = fmt.Sprintf("%d members found (should be 0)", count)
	}

	return result
}

// checkSchemaAdminsCount verifies Schema Admins group is empty.
// CIS L1: Schema Admins group should be empty unless schema changes are in progress.
func checkSchemaAdminsCount() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-003",
		Name:        "Schema Admins Empty",
		Category:    "privileged-account",
		Description: "Verifies Schema Admins group has 0 members (schema modification privilege)",
		Severity:    "critical",
		Expected:    "0 members in Schema Admins",
		Techniques:  []string{"T1078.002", "T1098.003"},
		Tactics:     []string{"credential-access", "privilege-escalation"},
	}

	script := `
try {
    $members = Get-ADGroupMember 'Schema Admins' -ErrorAction Stop
    $count = @($members).Count
    Write-Output "COUNT:$count"
    if ($count -gt 0) {
        $names = ($members | ForEach-Object { $_.SamAccountName }) -join ', '
        Write-Output "NAMES:$names"
    }
} catch {
    if ($_.Exception.Message -like '*cannot find*') {
        Write-Output "NOTFOUND"
    } else {
        throw $_
    }
}
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying Schema Admins group"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if output == "NOTFOUND" {
		result.Passed = true
		result.Actual = "Schema Admins group not found"
		result.Details = "Not applicable in this domain"
		return result
	}

	lines := strings.Split(output, "\n")
	count := 0
	names := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COUNT:") {
			countStr := strings.TrimPrefix(line, "COUNT:")
			count, _ = strconv.Atoi(strings.TrimSpace(countStr))
		}
		if strings.HasPrefix(line, "NAMES:") {
			names = strings.TrimPrefix(line, "NAMES:")
		}
	}

	result.Passed = count == 0
	if count == 0 {
		result.Actual = "Schema Admins group is empty"
		result.Details = "No members (compliant)"
	} else {
		result.Actual = fmt.Sprintf("%d members: %s", count, names)
		result.Details = fmt.Sprintf("%d members found (should be 0)", count)
	}

	return result
}

// checkProtectedUsersPopulated verifies the Protected Users group has members.
// CIS L1: Privileged accounts should be in the Protected Users security group.
func checkProtectedUsersPopulated() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-004",
		Name:        "Protected Users Group Populated",
		Category:    "privileged-account",
		Description: "Verifies the Protected Users security group has privileged accounts as members",
		Severity:    "high",
		Expected:    ">=1 member in Protected Users group",
		Techniques:  []string{"T1078.002"},
		Tactics:     []string{"credential-access"},
	}

	script := `
try {
    $members = Get-ADGroupMember 'Protected Users' -ErrorAction Stop
    $count = @($members).Count
    Write-Output "COUNT:$count"
    if ($count -gt 0) {
        $names = ($members | Select-Object -First 5 | ForEach-Object { $_.SamAccountName }) -join ', '
        Write-Output "NAMES:$names"
    }
} catch {
    if ($_.Exception.Message -like '*cannot find*') {
        Write-Output "NOTFOUND"
    } else {
        throw $_
    }
}
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying Protected Users group"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if output == "NOTFOUND" {
		result.Passed = false
		result.Actual = "Protected Users group not found"
		result.Details = "Requires domain functional level 2012 R2+"
		return result
	}

	lines := strings.Split(output, "\n")
	count := 0
	names := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COUNT:") {
			countStr := strings.TrimPrefix(line, "COUNT:")
			count, _ = strconv.Atoi(strings.TrimSpace(countStr))
		}
		if strings.HasPrefix(line, "NAMES:") {
			names = strings.TrimPrefix(line, "NAMES:")
		}
	}

	result.Passed = count > 0
	if count > 0 {
		result.Actual = fmt.Sprintf("%d members (e.g., %s)", count, names)
		result.Details = fmt.Sprintf("%d privileged accounts protected", count)
	} else {
		result.Actual = "Protected Users group is empty"
		result.Details = "Add privileged accounts to Protected Users group"
	}

	return result
}

// checkAdminSDHolderClean verifies no orphaned objects have AdminCount=1.
// CIS L1: Audit AdminSDHolder for orphaned objects with elevated privileges.
func checkAdminSDHolderClean() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-005",
		Name:        "AdminSDHolder Clean Audit",
		Category:    "privileged-account",
		Description: "Verifies no orphaned objects have AdminCount=1 without being in an admin group",
		Severity:    "high",
		Expected:    "0 orphaned objects with AdminCount=1",
		Techniques:  []string{"T1078.002", "T1098.003"},
		Tactics:     []string{"credential-access", "privilege-escalation"},
	}

	script := `
# Get all users with AdminCount=1
$adminCountUsers = Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount,MemberOf -ErrorAction Stop

# Get known admin group DNs
$adminGroups = @(
    (Get-ADGroup 'Domain Admins').DistinguishedName,
    (Get-ADGroup 'Enterprise Admins' -ErrorAction SilentlyContinue).DistinguishedName,
    (Get-ADGroup 'Schema Admins' -ErrorAction SilentlyContinue).DistinguishedName,
    (Get-ADGroup 'Administrators').DistinguishedName,
    (Get-ADGroup 'Account Operators' -ErrorAction SilentlyContinue).DistinguishedName,
    (Get-ADGroup 'Backup Operators' -ErrorAction SilentlyContinue).DistinguishedName,
    (Get-ADGroup 'Server Operators' -ErrorAction SilentlyContinue).DistinguishedName,
    (Get-ADGroup 'Print Operators' -ErrorAction SilentlyContinue).DistinguishedName
) | Where-Object { $_ -ne $null }

$orphaned = @()
foreach ($user in $adminCountUsers) {
    $inAdminGroup = $false
    foreach ($group in $user.MemberOf) {
        if ($adminGroups -contains $group) {
            $inAdminGroup = $true
            break
        }
    }
    if (-not $inAdminGroup) {
        $orphaned += $user.SamAccountName
    }
}
Write-Output "TOTAL:$(@($adminCountUsers).Count)"
Write-Output "ORPHANED:$($orphaned.Count)"
if ($orphaned.Count -gt 0) {
    $names = ($orphaned | Select-Object -First 10) -join ', '
    Write-Output "NAMES:$names"
}
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying AdminSDHolder"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	lines := strings.Split(output, "\n")
	totalCount := 0
	orphanedCount := 0
	names := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "TOTAL:") {
			totalCount, _ = strconv.Atoi(strings.TrimPrefix(line, "TOTAL:"))
		}
		if strings.HasPrefix(line, "ORPHANED:") {
			orphanedCount, _ = strconv.Atoi(strings.TrimPrefix(line, "ORPHANED:"))
		}
		if strings.HasPrefix(line, "NAMES:") {
			names = strings.TrimPrefix(line, "NAMES:")
		}
	}

	result.Passed = orphanedCount == 0
	if orphanedCount == 0 {
		result.Actual = fmt.Sprintf("%d users with AdminCount=1, 0 orphaned", totalCount)
		result.Details = "All AdminCount=1 users are in admin groups"
	} else {
		result.Actual = fmt.Sprintf("%d orphaned AdminCount users: %s", orphanedCount, names)
		result.Details = fmt.Sprintf("%d users have AdminCount=1 but are not in any admin group (stale permissions)", orphanedCount)
	}

	return result
}

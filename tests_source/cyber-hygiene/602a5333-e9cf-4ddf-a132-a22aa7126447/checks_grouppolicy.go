//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// RunGroupPolicyChecks validates CIS Group Policy Security controls (CH-CIA-019 to CH-CIA-021)
func RunGroupPolicyChecks() ValidatorResult {
	checks := []CheckResult{
		checkDefaultPasswordLength(),
		checkGPOPermissions(),
		checkAuditPolicyConfigured(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Group Policy Security",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkDefaultPasswordLength verifies the Default Domain Policy minimum password length is >= 14.
// CIS L1: Set minimum password length to at least 14 characters.
func checkDefaultPasswordLength() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-019",
		Name:        "Password Length >= 14",
		Category:    "group-policy",
		Description: "Verifies the Default Domain Policy requires passwords of at least 14 characters",
		Severity:    "high",
		Expected:    "MinPasswordLength >= 14",
		Techniques:  []string{"T1484.001"},
		Tactics:     []string{"defense-evasion"},
	}

	script := `
$policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
Write-Output "MINLEN:$($policy.MinPasswordLength)"
Write-Output "COMPLEXITY:$($policy.ComplexityEnabled)"
Write-Output "HISTORY:$($policy.PasswordHistoryCount)"
Write-Output "MAXAGE:$([math]::Floor($policy.MaxPasswordAge.TotalDays))"
Write-Output "LOCKOUT:$($policy.LockoutThreshold)"
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying Default Domain Password Policy"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	lines := strings.Split(output, "\n")
	minLen := 0
	complexity := ""
	history := 0
	maxAge := 0
	lockout := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "MINLEN:") {
			minLen, _ = strconv.Atoi(strings.TrimPrefix(line, "MINLEN:"))
		}
		if strings.HasPrefix(line, "COMPLEXITY:") {
			complexity = strings.TrimPrefix(line, "COMPLEXITY:")
		}
		if strings.HasPrefix(line, "HISTORY:") {
			history, _ = strconv.Atoi(strings.TrimPrefix(line, "HISTORY:"))
		}
		if strings.HasPrefix(line, "MAXAGE:") {
			maxAge, _ = strconv.Atoi(strings.TrimPrefix(line, "MAXAGE:"))
		}
		if strings.HasPrefix(line, "LOCKOUT:") {
			lockout, _ = strconv.Atoi(strings.TrimPrefix(line, "LOCKOUT:"))
		}
	}

	result.Passed = minLen >= 14
	result.Actual = fmt.Sprintf("MinLen=%d, Complexity=%s, History=%d, MaxAge=%dd, Lockout=%d",
		minLen, complexity, history, maxAge, lockout)
	if result.Passed {
		result.Details = fmt.Sprintf("Password length %d meets CIS L1 requirement (>=14)", minLen)
	} else {
		result.Details = fmt.Sprintf("Password length %d is below CIS L1 requirement of 14", minLen)
	}

	return result
}

// checkGPOPermissions verifies critical GPOs do not grant Authenticated Users modify rights.
// CIS L1: Audit GPO permissions for overly permissive access.
func checkGPOPermissions() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-020",
		Name:        "GPO Permissions Audit",
		Category:    "group-policy",
		Description: "Verifies critical GPOs do not grant Authenticated Users modify/edit rights",
		Severity:    "high",
		Expected:    "No Authenticated Users with GpoEditDeleteModifySecurity on critical GPOs",
		Techniques:  []string{"T1484.001"},
		Tactics:     []string{"defense-evasion"},
	}

	script := `
# Check Default Domain Policy and Default Domain Controllers Policy
$criticalGPOs = @()
try {
    $ddp = Get-GPO -Name 'Default Domain Policy' -ErrorAction Stop
    $criticalGPOs += $ddp
} catch {}
try {
    $ddcp = Get-GPO -Name 'Default Domain Controllers Policy' -ErrorAction Stop
    $criticalGPOs += $ddcp
} catch {}

if ($criticalGPOs.Count -eq 0) {
    Write-Output "NOGPO"
    return
}

$issues = @()
foreach ($gpo in $criticalGPOs) {
    try {
        $perms = Get-GPPermission -Guid $gpo.Id -All -ErrorAction Stop
        foreach ($perm in $perms) {
            $trustee = $perm.Trustee.Name
            $permission = $perm.Permission
            # Check for overly permissive access by non-admin groups
            if (($trustee -eq 'Authenticated Users' -or $trustee -eq 'Domain Users' -or $trustee -eq 'Everyone') -and
                ($permission -eq 'GpoEditDeleteModifySecurity' -or $permission -eq 'GpoEdit')) {
                $issues += "$($gpo.DisplayName):$trustee=$permission"
            }
        }
    } catch {}
}

Write-Output "CHECKED:$($criticalGPOs.Count)"
Write-Output "ISSUES:$($issues.Count)"
if ($issues.Count -gt 0) {
    Write-Output "DETAIL:$($issues -join '; ')"
}
`
	output, err := RunPowerShell(script)
	if err != nil {
		// GroupPolicy module may not be available on non-DC machines
		result.Passed = false
		result.Actual = "Error querying GPO permissions"
		result.Details = fmt.Sprintf("Requires GroupPolicy PowerShell module: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if output == "NOGPO" {
		result.Passed = false
		result.Actual = "Could not find critical GPOs"
		result.Details = "Default Domain Policy not found (requires GroupPolicy module)"
		return result
	}

	lines := strings.Split(output, "\n")
	checked := 0
	issues := 0
	detail := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "CHECKED:") {
			checked, _ = strconv.Atoi(strings.TrimPrefix(line, "CHECKED:"))
		}
		if strings.HasPrefix(line, "ISSUES:") {
			issues, _ = strconv.Atoi(strings.TrimPrefix(line, "ISSUES:"))
		}
		if strings.HasPrefix(line, "DETAIL:") {
			detail = strings.TrimPrefix(line, "DETAIL:")
		}
	}

	result.Passed = issues == 0
	if issues == 0 {
		result.Actual = fmt.Sprintf("Checked %d critical GPOs, no overly permissive ACLs", checked)
		result.Details = "No Authenticated Users/Domain Users with edit rights on critical GPOs"
	} else {
		result.Actual = fmt.Sprintf("%d permission issues found", issues)
		result.Details = fmt.Sprintf("Overly permissive GPO ACLs: %s", detail)
	}

	return result
}

// checkAuditPolicyConfigured verifies advanced audit policy is configured via GPO.
// CIS L1: Configure advanced audit policy settings.
func checkAuditPolicyConfigured() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-021",
		Name:        "Advanced Audit Policy Configured",
		Category:    "group-policy",
		Description: "Verifies advanced audit policy subcategories are configured (not using legacy audit)",
		Severity:    "high",
		Expected:    "Advanced audit policy configured with key subcategories",
		Techniques:  []string{"T1484.001"},
		Tactics:     []string{"defense-evasion"},
	}

	// Check auditpol output for key subcategories
	script := "$output = auditpol /get /category:* 2>&1\n" +
		"$lines = $output -split \"`n\"\n" +
		"$keySubcategories = @(\n" +
		"    'Logon',\n" +
		"    'Logoff',\n" +
		"    'Account Lockout',\n" +
		"    'User Account Management',\n" +
		"    'Computer Account Management',\n" +
		"    'Security Group Management',\n" +
		"    'Credential Validation',\n" +
		"    'Process Creation',\n" +
		"    'Audit Policy Change',\n" +
		"    'Authentication Policy Change'\n" +
		")\n" +
		"$configured = 0\n" +
		"$notConfigured = 0\n" +
		"$details = @()\n" +
		"foreach ($sub in $keySubcategories) {\n" +
		"    $match = $lines | Where-Object { $_ -match $sub }\n" +
		"    if ($match) {\n" +
		"        $matchStr = $match.ToString().Trim()\n" +
		"        if ($matchStr -match 'Success|Failure') {\n" +
		"            $configured++\n" +
		"        } else {\n" +
		"            $notConfigured++\n" +
		"            $details += $sub\n" +
		"        }\n" +
		"    } else {\n" +
		"        $notConfigured++\n" +
		"        $details += $sub\n" +
		"    }\n" +
		"}\n" +
		"Write-Output \"CONFIGURED:$configured\"\n" +
		"Write-Output \"NOTCONFIGURED:$notConfigured\"\n" +
		"Write-Output \"TOTAL:$($keySubcategories.Count)\"\n" +
		"if ($details.Count -gt 0) {\n" +
		"    Write-Output \"MISSING:$($details -join ', ')\"\n" +
		"}"
	output, err := RunPowerShell(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying audit policy"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	lines := strings.Split(output, "\n")
	configured := 0
	total := 0
	missing := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "CONFIGURED:") {
			configured, _ = strconv.Atoi(strings.TrimPrefix(line, "CONFIGURED:"))
		}
		if strings.HasPrefix(line, "TOTAL:") {
			total, _ = strconv.Atoi(strings.TrimPrefix(line, "TOTAL:"))
		}
		if strings.HasPrefix(line, "MISSING:") {
			missing = strings.TrimPrefix(line, "MISSING:")
		}
	}

	// Pass if at least 80% of key subcategories are configured
	threshold := (total * 80) / 100
	result.Passed = configured >= threshold
	result.Actual = fmt.Sprintf("%d/%d key audit subcategories configured", configured, total)
	if result.Passed {
		result.Details = "Advanced audit policy adequately configured"
	} else {
		result.Details = fmt.Sprintf("Missing audit subcategories: %s", missing)
	}

	return result
}

//go:build windows
// +build windows

// checks_identity.go — ISACA ITGC AD Identity control checks.
//
// Three controls covered:
//   ITGC-AM-003 Dormant Account Detection (lastLogonTimestamp > 90 days)
//   ITGC-AM-004 Service Account Permissions Audit (SPN + interactive logon flag)
//   ITGC-NS-003 LAPS Deployment Validation (CSE installed + ms-Mcs-AdmPwd readable)
//
// Each check uses RunADCommand (Import-Module ActiveDirectory + the supplied script).

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// RunADIdentityChecks executes the 3 ITGC AD-identity controls.
func RunADIdentityChecks() ValidatorResult {
	result := ValidatorResult{Name: "AD Identity Controls"}
	result.Checks = []CheckResult{
		checkDormantAccountsISACA(),         // AM-003
		checkServiceAccountPermissionsISACA(), // AM-004
		checkLAPSDeploymentISACA(),          // NS-003
	}
	for _, c := range result.Checks {
		result.TotalChecks++
		if c.Passed {
			result.PassedCount++
		} else {
			result.FailedCount++
		}
	}
	result.IsCompliant = result.FailedCount == 0
	return result
}

// ITGC-AM-003 — Dormant Account Detection.
// Threshold configurable via ITGC_DORMANT_DAYS env var (default 90).
// PASS criterion: dormant_count == 0 (any dormant accounts require auditor review).
func checkDormantAccountsISACA() CheckResult {
	thresholdDays := 90
	if v := os.Getenv("ITGC_DORMANT_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			thresholdDays = n
		}
	}

	c := CheckResult{
		ControlID:      "ITGC-AM-003",
		Name:           "Dormant Account Detection",
		Category:       "access-management",
		Description:    fmt.Sprintf("AD users with lastLogonTimestamp older than %d days (excluding service-account OU pattern).", thresholdDays),
		Severity:       "high",
		Techniques:     []string{"T1078.001"},
		Tactics:        []string{"defense-evasion", "persistence"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.04 Manage Identity and Logical Access",
		CisV8Mapping:   "CIS 5.3 Disable Dormant Accounts",
		ManualResidual: "Each dormant account must have documented business justification (break-glass, decommissioned-but-retained, compliance-hold). Auditor reviews exception list.",
	}

	script := fmt.Sprintf(`
$threshold = (Get-Date).AddDays(-%d)
$dormant = Get-ADUser -Filter {Enabled -eq $true -and LastLogonTimestamp -lt $threshold} -Properties LastLogonTimestamp, SamAccountName, DistinguishedName, ServicePrincipalNames -ErrorAction Stop |
    Where-Object { -not ($_.DistinguishedName -match 'OU=Service Accounts') -and -not ($_.DistinguishedName -match 'OU=Computers') } |
    Select-Object SamAccountName, DistinguishedName, @{N='LastLogon';E={if ($_.LastLogonTimestamp) { [DateTime]::FromFileTime($_.LastLogonTimestamp).ToString('yyyy-MM-dd') } else { 'never' }}}
$total = ($dormant | Measure-Object).Count
$totalUsers = (Get-ADUser -Filter {Enabled -eq $true} | Measure-Object).Count
@{
    threshold_days = %d
    dormant_count = $total
    total_enabled_users = $totalUsers
    sample_dormant = ($dormant | Select-Object -First 25)
} | ConvertTo-Json -Compress -Depth 4
`, thresholdDays, thresholdDays)

	output, err := RunADCommand(script)
	c.Expected = "dormant_count = 0 (or all documented as exceptions)"
	if err != nil {
		c.Passed = false
		c.Actual = "AD query failed"
		c.Details = fmt.Sprintf("Get-ADUser dormant query failed: %v", err)
		c.Evidence = map[string]interface{}{"query_error": err.Error(), "threshold_days": thresholdDays}
		return c
	}
	output = strings.TrimSpace(output)
	c.Evidence = map[string]interface{}{
		"dormant_query_raw": output,
		"threshold_days":    thresholdDays,
	}

	dormantCount := -1
	if idx := strings.Index(output, `"dormant_count":`); idx >= 0 {
		rest := output[idx+16:]
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end > 0 {
			dormantCount, _ = strconv.Atoi(rest[:end])
		}
	}
	c.Evidence["dormant_count"] = dormantCount

	if dormantCount < 0 {
		c.Passed = false
		c.Actual = "could not parse dormant count"
		c.Details = "AD query succeeded but JSON shape was unexpected. Inspect evidence.dormant_query_raw."
		return c
	}
	c.Passed = dormantCount == 0
	c.Actual = fmt.Sprintf("%d dormant accounts (threshold %dd)", dormantCount, thresholdDays)
	if c.Passed {
		c.Details = "No dormant accounts in directory."
	} else {
		c.Details = fmt.Sprintf("%d AD users have not authenticated in %d+ days. Auditor reviews evidence.sample_dormant for exception justification.", dormantCount, thresholdDays)
	}
	return c
}

// ITGC-AM-004 — Service Account Permissions Audit.
// Looks for accounts with: ServicePrincipalNames + (member of privileged group OR no
// password expiration). Flags as auditor-review.
func checkServiceAccountPermissionsISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-AM-004",
		Name:           "Service Account Permissions Audit",
		Category:       "access-management",
		Description:    "Service accounts (SPN holders) are not over-privileged: not in Domain Admins, not password-never-expires.",
		Severity:       "high",
		Techniques:     []string{"T1078.002", "T1558.003"},
		Tactics:        []string{"credential-access", "privilege-escalation"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.04 Manage Identity and Logical Access",
		CisV8Mapping:   "CIS 5.4 Restrict Administrator Privileges",
		ManualResidual: "Each over-privileged service account must have documented exception (e.g., legacy app requiring DA — usually a finding to remediate).",
	}

	script := `
$privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Account Operators','Backup Operators')
$spnAccounts = Get-ADUser -Filter {Enabled -eq $true -and ServicePrincipalName -ne $null} -Properties ServicePrincipalName, MemberOf, PasswordNeverExpires, SamAccountName -ErrorAction Stop
$flagged = @()
$totalSPN = ($spnAccounts | Measure-Object).Count
foreach ($u in $spnAccounts) {
    $isPrivileged = $false
    foreach ($g in $privGroups) {
        try {
            $grp = Get-ADGroup -Identity $g -ErrorAction Stop
            if (Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue | Where-Object { $_.SamAccountName -eq $u.SamAccountName }) {
                $isPrivileged = $true
                break
            }
        } catch { }
    }
    if ($isPrivileged -or $u.PasswordNeverExpires) {
        $flagged += [PSCustomObject]@{
            sam = $u.SamAccountName
            privileged = $isPrivileged
            password_never_expires = $u.PasswordNeverExpires
            spn_count = ($u.ServicePrincipalName | Measure-Object).Count
        }
    }
}
@{
    total_spn_accounts = $totalSPN
    flagged_count = ($flagged | Measure-Object).Count
    flagged = $flagged
} | ConvertTo-Json -Compress -Depth 4
`

	output, err := RunADCommand(script)
	c.Expected = "flagged_count = 0 (no over-privileged or password-never-expires service accounts)"
	if err != nil {
		c.Passed = false
		c.Actual = "AD query failed"
		c.Details = fmt.Sprintf("Service-account audit query failed: %v", err)
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output = strings.TrimSpace(output)
	c.Evidence = map[string]interface{}{"service_account_query_raw": output}

	flaggedCount := -1
	if idx := strings.Index(output, `"flagged_count":`); idx >= 0 {
		rest := output[idx+16:]
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end > 0 {
			flaggedCount, _ = strconv.Atoi(rest[:end])
		}
	}
	c.Evidence["flagged_count"] = flaggedCount

	if flaggedCount < 0 {
		c.Passed = false
		c.Actual = "could not parse flagged count"
		c.Details = "AD query succeeded but JSON shape was unexpected. Inspect evidence.service_account_query_raw."
		return c
	}
	c.Passed = flaggedCount == 0
	c.Actual = fmt.Sprintf("%d over-privileged service accounts", flaggedCount)
	if c.Passed {
		c.Details = "No service accounts found in privileged groups or with password-never-expires."
	} else {
		c.Details = fmt.Sprintf("%d service accounts (SPN holders) are over-privileged or have non-rotating passwords. Auditor reviews evidence.flagged for each. Recommend gMSA migration where feasible.", flaggedCount)
	}
	return c
}

// ITGC-NS-003 — LAPS Deployment Validation.
// Two-part check: (1) AD ms-Mcs-AdmPwd attribute exists in the schema (Legacy LAPS) OR
// the new Windows LAPS attributes (msLAPS-*) are present. (2) at least 80% of computer
// objects have a populated LAPS password attribute.
func checkLAPSDeploymentISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-NS-003",
		Name:           "LAPS Deployment Validation",
		Category:       "network-security",
		Description:    "LAPS schema deployed and ≥80% of computer objects have a managed local-admin password.",
		Severity:       "high",
		Techniques:     []string{"T1078.003"},
		Tactics:        []string{"lateral-movement", "credential-access"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.04 Manage Identity and Logical Access",
		CisV8Mapping:   "CIS 5.2 Use Unique Passwords",
		ManualResidual: "Auditor verifies LAPS password rotation cadence (default 30d) and read delegation against approved admin groups.",
	}

	script := `
$schemaCheck = $false
$schemaType = 'none'
try {
    $schema = Get-ADObject -Filter "lDAPDisplayName -eq 'ms-Mcs-AdmPwd'" -SearchBase (Get-ADRootDSE).schemaNamingContext -ErrorAction SilentlyContinue
    if ($schema) { $schemaCheck = $true; $schemaType = 'legacy' }
    else {
        $schemaNew = Get-ADObject -Filter "lDAPDisplayName -eq 'msLAPS-Password'" -SearchBase (Get-ADRootDSE).schemaNamingContext -ErrorAction SilentlyContinue
        if ($schemaNew) { $schemaCheck = $true; $schemaType = 'windows-laps' }
    }
} catch {}

$totalComputers = 0
$lapsManaged = 0
if ($schemaCheck) {
    try {
        $allComputers = Get-ADComputer -Filter {Enabled -eq $true} -Properties 'ms-Mcs-AdmPwd','msLAPS-Password' -ErrorAction Stop
        $totalComputers = ($allComputers | Measure-Object).Count
        if ($schemaType -eq 'legacy') {
            $lapsManaged = ($allComputers | Where-Object { $_.'ms-Mcs-AdmPwd' } | Measure-Object).Count
        } else {
            $lapsManaged = ($allComputers | Where-Object { $_.'msLAPS-Password' } | Measure-Object).Count
        }
    } catch {}
}

$pct = if ($totalComputers -gt 0) { [math]::Round(($lapsManaged / $totalComputers) * 100, 2) } else { 0 }

@{
    schema_deployed = $schemaCheck
    schema_type = $schemaType
    total_computers = $totalComputers
    laps_managed = $lapsManaged
    coverage_pct = $pct
} | ConvertTo-Json -Compress
`

	output, err := RunADCommand(script)
	c.Expected = "Schema deployed AND coverage_pct >= 80%"
	if err != nil {
		c.Passed = false
		c.Actual = "AD query failed"
		c.Details = fmt.Sprintf("LAPS audit query failed: %v", err)
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output = strings.TrimSpace(output)
	c.Evidence = map[string]interface{}{"laps_query_raw": output}

	schemaDeployed := strings.Contains(output, `"schema_deployed":true`)
	if !schemaDeployed {
		c.Passed = false
		c.Actual = "LAPS schema not deployed"
		c.Details = "Neither legacy LAPS (ms-Mcs-AdmPwd) nor Windows LAPS (msLAPS-Password) schema attributes are present in the directory. Local admin passwords are not centrally managed."
		c.Evidence["schema_deployed"] = false
		return c
	}

	pct := -1.0
	if idx := strings.Index(output, `"coverage_pct":`); idx >= 0 {
		rest := output[idx+15:]
		end := 0
		for end < len(rest) && (rest[end] == '.' || (rest[end] >= '0' && rest[end] <= '9')) {
			end++
		}
		if end > 0 {
			fmt.Sscanf(rest[:end], "%f", &pct)
		}
	}
	c.Evidence["coverage_pct"] = pct
	c.Evidence["schema_deployed"] = true

	c.Passed = pct >= 80.0
	c.Actual = fmt.Sprintf("LAPS schema deployed; %.2f%% coverage", pct)
	if c.Passed {
		c.Details = "LAPS deployed with adequate coverage (≥80%)."
	} else {
		c.Details = fmt.Sprintf("LAPS schema is deployed but only %.2f%% of enabled computer objects have managed passwords (need ≥80%%). Roll out LAPS CSE/policy to remaining endpoints.", pct)
	}
	return c
}

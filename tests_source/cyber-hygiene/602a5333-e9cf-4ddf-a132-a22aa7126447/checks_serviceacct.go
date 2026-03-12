//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// RunServiceAcctChecks validates CIS Service Account Security controls (CH-CIA-006 to CH-CIA-008)
func RunServiceAcctChecks() ValidatorResult {
	checks := []CheckResult{
		checkGMSAUsage(),
		checkServiceAccountPasswordAge(),
		checkUnconstrainedDelegation(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Service Account Security",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkGMSAUsage verifies Group Managed Service Accounts (gMSA) exist.
// CIS L1: Use gMSA for service accounts where possible.
func checkGMSAUsage() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-006",
		Name:        "gMSA Usage Audit",
		Category:    "service-account",
		Description: "Verifies Group Managed Service Accounts (gMSA) are deployed for service accounts",
		Severity:    "medium",
		Expected:    ">=1 gMSA accounts exist",
		Techniques:  []string{"T1558.003"},
		Tactics:     []string{"credential-access"},
	}

	script := `
try {
    $gmsas = Get-ADServiceAccount -Filter * -ErrorAction Stop
    $count = @($gmsas).Count
    Write-Output "COUNT:$count"
    if ($count -gt 0) {
        $names = ($gmsas | Select-Object -First 5 | ForEach-Object { $_.SamAccountName }) -join ', '
        Write-Output "NAMES:$names"
    }
} catch {
    if ($_.Exception.Message -like '*cmdlet*' -or $_.Exception.Message -like '*not recognized*') {
        Write-Output "CMDLETNA"
    } else {
        Write-Output "COUNT:0"
    }
}
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying gMSA accounts"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if output == "CMDLETNA" {
		result.Passed = false
		result.Actual = "Get-ADServiceAccount cmdlet not available"
		result.Details = "Requires RSAT AD PowerShell tools with service account support"
		return result
	}

	lines := strings.Split(output, "\n")
	count := 0
	names := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COUNT:") {
			count, _ = strconv.Atoi(strings.TrimPrefix(line, "COUNT:"))
		}
		if strings.HasPrefix(line, "NAMES:") {
			names = strings.TrimPrefix(line, "NAMES:")
		}
	}

	result.Passed = count > 0
	if count > 0 {
		result.Actual = fmt.Sprintf("%d gMSA accounts (e.g., %s)", count, names)
		result.Details = fmt.Sprintf("%d gMSA accounts deployed", count)
	} else {
		result.Actual = "No gMSA accounts found"
		result.Details = "Consider deploying gMSA for service accounts (automatic password rotation)"
	}

	return result
}

// checkServiceAccountPasswordAge verifies no service accounts have passwords older than 365 days.
// CIS L1: Service account passwords should be rotated at least annually.
func checkServiceAccountPasswordAge() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-007",
		Name:        "Service Account Password Age <=365d",
		Category:    "service-account",
		Description: "Verifies service accounts have passwords rotated within 365 days",
		Severity:    "high",
		Expected:    "All service accounts with PasswordLastSet within 365 days",
		Techniques:  []string{"T1558.003"},
		Tactics:     []string{"credential-access"},
	}

	// Query user accounts that appear to be service accounts (name patterns)
	// and check password age
	script := `
$threshold = (Get-Date).AddDays(-365)
$svcAccounts = Get-ADUser -Filter {
    (SamAccountName -like 'svc*' -or SamAccountName -like 'srv*' -or SamAccountName -like 'sa_*' -or SamAccountName -like '*_svc' -or SamAccountName -like '*_service') -and Enabled -eq $true
} -Properties PasswordLastSet,SamAccountName -ErrorAction Stop

$stale = @()
$total = @($svcAccounts).Count
foreach ($acct in $svcAccounts) {
    if ($acct.PasswordLastSet -lt $threshold -or $acct.PasswordLastSet -eq $null) {
        $age = if ($acct.PasswordLastSet) { [math]::Floor(((Get-Date) - $acct.PasswordLastSet).TotalDays) } else { 'never' }
        $stale += "$($acct.SamAccountName):$age"
    }
}
Write-Output "TOTAL:$total"
Write-Output "STALE:$($stale.Count)"
if ($stale.Count -gt 0) {
    $detail = ($stale | Select-Object -First 5) -join ', '
    Write-Output "DETAIL:$detail"
}
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying service accounts"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	lines := strings.Split(output, "\n")
	total := 0
	staleCount := 0
	detail := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "TOTAL:") {
			total, _ = strconv.Atoi(strings.TrimPrefix(line, "TOTAL:"))
		}
		if strings.HasPrefix(line, "STALE:") {
			staleCount, _ = strconv.Atoi(strings.TrimPrefix(line, "STALE:"))
		}
		if strings.HasPrefix(line, "DETAIL:") {
			detail = strings.TrimPrefix(line, "DETAIL:")
		}
	}

	if total == 0 {
		result.Passed = true
		result.Actual = "No service accounts found matching naming convention"
		result.Details = "No accounts matching svc*/srv*/sa_*/*_svc/*_service patterns"
		return result
	}

	result.Passed = staleCount == 0
	if staleCount == 0 {
		result.Actual = fmt.Sprintf("All %d service accounts have recent passwords", total)
		result.Details = "All passwords rotated within 365 days"
	} else {
		result.Actual = fmt.Sprintf("%d/%d service accounts with stale passwords", staleCount, total)
		result.Details = fmt.Sprintf("Stale accounts (name:days): %s", detail)
	}

	return result
}

// checkUnconstrainedDelegation verifies no computers have unconstrained delegation.
// CIS L1: Unconstrained delegation is a high-risk configuration.
func checkUnconstrainedDelegation() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-008",
		Name:        "No Unconstrained Delegation",
		Category:    "service-account",
		Description: "Verifies no computers are configured with unconstrained Kerberos delegation",
		Severity:    "critical",
		Expected:    "0 non-DC computers with unconstrained delegation",
		Techniques:  []string{"T1558.003"},
		Tactics:     []string{"credential-access"},
	}

	script := `
# Find all computers trusted for unconstrained delegation, excluding domain controllers
$dcs = (Get-ADDomainController -Filter *).Name
$unconstrained = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation -ErrorAction Stop
$nonDC = @()
foreach ($comp in $unconstrained) {
    $hostname = $comp.Name
    if ($dcs -notcontains $hostname) {
        $nonDC += $hostname
    }
}
Write-Output "TOTAL:$(@($unconstrained).Count)"
Write-Output "NONDC:$($nonDC.Count)"
if ($nonDC.Count -gt 0) {
    $names = ($nonDC | Select-Object -First 10) -join ', '
    Write-Output "NAMES:$names"
}
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying delegation settings"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	lines := strings.Split(output, "\n")
	totalCount := 0
	nonDCCount := 0
	names := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "TOTAL:") {
			totalCount, _ = strconv.Atoi(strings.TrimPrefix(line, "TOTAL:"))
		}
		if strings.HasPrefix(line, "NONDC:") {
			nonDCCount, _ = strconv.Atoi(strings.TrimPrefix(line, "NONDC:"))
		}
		if strings.HasPrefix(line, "NAMES:") {
			names = strings.TrimPrefix(line, "NAMES:")
		}
	}

	result.Passed = nonDCCount == 0
	if nonDCCount == 0 {
		result.Actual = fmt.Sprintf("%d computers with delegation (all DCs)", totalCount)
		result.Details = "No non-DC computers have unconstrained delegation"
	} else {
		result.Actual = fmt.Sprintf("%d non-DC computers with unconstrained delegation: %s", nonDCCount, names)
		result.Details = fmt.Sprintf("Remove unconstrained delegation or switch to constrained/RBCD for: %s", names)
	}

	return result
}

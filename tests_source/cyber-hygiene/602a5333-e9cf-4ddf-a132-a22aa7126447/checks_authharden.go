//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// RunAuthHardenChecks validates CIS Authentication Hardening controls (CH-CIA-009 to CH-CIA-012)
func RunAuthHardenChecks() ValidatorResult {
	checks := []CheckResult{
		checkFineGrainedPasswordPolicy(),
		checkKRBTGTPasswordAge(),
		checkNoReversibleEncryption(),
		checkKerberosPreAuth(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Authentication Hardening",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkFineGrainedPasswordPolicy verifies at least one Fine-Grained Password Policy exists.
// CIS L1: Implement fine-grained password policies for privileged accounts.
func checkFineGrainedPasswordPolicy() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-009",
		Name:        "Fine-Grained Password Policy Exists",
		Category:    "auth-hardening",
		Description: "Verifies at least one Fine-Grained Password Policy (PSO) is configured",
		Severity:    "medium",
		Expected:    ">=1 Fine-Grained Password Policy",
		Techniques:  []string{"T1558.003"},
		Tactics:     []string{"credential-access"},
	}

	script := `
try {
    $psos = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop
    $count = @($psos).Count
    Write-Output "COUNT:$count"
    if ($count -gt 0) {
        $details = ($psos | Select-Object -First 3 | ForEach-Object {
            "$($_.Name):MinLen=$($_.MinPasswordLength),MaxAge=$([math]::Floor($_.MaxPasswordAge.TotalDays))d"
        }) -join '; '
        Write-Output "DETAIL:$details"
    }
} catch {
    Write-Output "ERROR:$($_.Exception.Message)"
}
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying password policies"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	lines := strings.Split(output, "\n")
	count := 0
	detail := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COUNT:") {
			count, _ = strconv.Atoi(strings.TrimPrefix(line, "COUNT:"))
		}
		if strings.HasPrefix(line, "DETAIL:") {
			detail = strings.TrimPrefix(line, "DETAIL:")
		}
		if strings.HasPrefix(line, "ERROR:") {
			result.Passed = false
			result.Actual = "Error querying FGPPs"
			result.Details = strings.TrimPrefix(line, "ERROR:")
			return result
		}
	}

	result.Passed = count > 0
	if count > 0 {
		result.Actual = fmt.Sprintf("%d FGPP(s): %s", count, detail)
		result.Details = fmt.Sprintf("%d fine-grained password policies configured", count)
	} else {
		result.Actual = "No Fine-Grained Password Policies found"
		result.Details = "Create FGPPs for privileged accounts with stricter password requirements"
	}

	return result
}

// checkKRBTGTPasswordAge verifies KRBTGT password was rotated within 180 days.
// CIS L1: Rotate KRBTGT password at least every 180 days.
func checkKRBTGTPasswordAge() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-010",
		Name:        "KRBTGT Password Age <=180d",
		Category:    "auth-hardening",
		Description: "Verifies the KRBTGT account password was rotated within 180 days",
		Severity:    "critical",
		Expected:    "KRBTGT PasswordLastSet within 180 days",
		Techniques:  []string{"T1558.003", "T1558.004"},
		Tactics:     []string{"credential-access"},
	}

	script := `
$krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet -ErrorAction Stop
if ($krbtgt.PasswordLastSet) {
    $age = [math]::Floor(((Get-Date) - $krbtgt.PasswordLastSet).TotalDays)
    $lastSet = $krbtgt.PasswordLastSet.ToString('yyyy-MM-dd')
    Write-Output "AGE:$age"
    Write-Output "DATE:$lastSet"
} else {
    Write-Output "NEVER"
}
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying KRBTGT account"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	lines := strings.Split(output, "\n")
	ageDays := -1
	lastDate := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AGE:") {
			ageDays, _ = strconv.Atoi(strings.TrimPrefix(line, "AGE:"))
		}
		if strings.HasPrefix(line, "DATE:") {
			lastDate = strings.TrimPrefix(line, "DATE:")
		}
	}

	if strings.TrimSpace(output) == "NEVER" {
		result.Passed = false
		result.Actual = "KRBTGT password has never been set"
		result.Details = "CRITICAL: Rotate KRBTGT password immediately"
		return result
	}

	result.Passed = ageDays >= 0 && ageDays <= 180
	result.Actual = fmt.Sprintf("KRBTGT password age: %d days (last set: %s)", ageDays, lastDate)
	if result.Passed {
		result.Details = fmt.Sprintf("Password rotated %d days ago (within 180-day limit)", ageDays)
	} else {
		result.Details = fmt.Sprintf("Password is %d days old (exceeds 180-day limit)", ageDays)
	}

	return result
}

// checkNoReversibleEncryption verifies no users have reversible encryption enabled.
// CIS L1: No users should store passwords using reversible encryption.
func checkNoReversibleEncryption() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-011",
		Name:        "No Reversible Encryption Users",
		Category:    "auth-hardening",
		Description: "Verifies no user accounts have AllowReversiblePasswordEncryption enabled",
		Severity:    "high",
		Expected:    "0 users with reversible encryption",
		Techniques:  []string{"T1558.003"},
		Tactics:     []string{"credential-access"},
	}

	script := `
$users = Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} -Properties AllowReversiblePasswordEncryption -ErrorAction Stop
$count = @($users).Count
Write-Output "COUNT:$count"
if ($count -gt 0) {
    $names = ($users | Select-Object -First 10 | ForEach-Object { $_.SamAccountName }) -join ', '
    Write-Output "NAMES:$names"
}
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying reversible encryption"
		result.Details = fmt.Sprintf("Query failed: %v", err)
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

	result.Passed = count == 0
	if count == 0 {
		result.Actual = "No users with reversible encryption"
		result.Details = "All accounts use standard one-way password hashing"
	} else {
		result.Actual = fmt.Sprintf("%d users with reversible encryption: %s", count, names)
		result.Details = fmt.Sprintf("Disable AllowReversiblePasswordEncryption for %d account(s)", count)
	}

	return result
}

// checkKerberosPreAuth verifies no users have Do Not Require Kerberos Pre-Authentication.
// CIS L1: All accounts should require Kerberos pre-authentication (prevents AS-REP roasting).
func checkKerberosPreAuth() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-012",
		Name:        "Kerberos Pre-Auth Enforced",
		Category:    "auth-hardening",
		Description: "Verifies no user accounts have DoesNotRequirePreAuth enabled (AS-REP Roasting risk)",
		Severity:    "critical",
		Expected:    "0 users with DoesNotRequirePreAuth",
		Techniques:  []string{"T1558.004"},
		Tactics:     []string{"credential-access"},
	}

	script := `
$users = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth -ErrorAction Stop
$count = @($users).Count
Write-Output "COUNT:$count"
if ($count -gt 0) {
    $names = ($users | Select-Object -First 10 | ForEach-Object { $_.SamAccountName }) -join ', '
    Write-Output "NAMES:$names"
}
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying Kerberos pre-auth"
		result.Details = fmt.Sprintf("Query failed: %v", err)
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

	result.Passed = count == 0
	if count == 0 {
		result.Actual = "All accounts require Kerberos pre-authentication"
		result.Details = "No AS-REP Roasting targets found"
	} else {
		result.Actual = fmt.Sprintf("%d users vulnerable to AS-REP Roasting: %s", count, names)
		result.Details = fmt.Sprintf("Enable Kerberos pre-auth for %d account(s) to prevent AS-REP Roasting", count)
	}

	return result
}

//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// RunADInfraChecks validates CIS AD Infrastructure controls (CH-CIA-013 to CH-CIA-018)
func RunADInfraChecks() ValidatorResult {
	checks := []CheckResult{
		checkADRecycleBin(),
		checkDomainFunctionalLevel(),
		checkStaleComputers(),
		checkStaleUsers(),
		checkLDAPSigning(),
		checkLDAPChannelBinding(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "AD Infrastructure",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkADRecycleBin verifies the AD Recycle Bin optional feature is enabled.
// CIS L1: Enable the Active Directory Recycle Bin.
func checkADRecycleBin() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-013",
		Name:        "AD Recycle Bin Enabled",
		Category:    "ad-infrastructure",
		Description: "Verifies the Active Directory Recycle Bin optional feature is enabled",
		Severity:    "medium",
		Expected:    "AD Recycle Bin feature enabled",
		Techniques:  []string{"T1078.002"},
		Tactics:     []string{"persistence"},
	}

	script := `
try {
    $feature = Get-ADOptionalFeature -Filter 'Name -like "Recycle*"' -ErrorAction Stop
    if ($feature -and $feature.EnabledScopes.Count -gt 0) {
        Write-Output "ENABLED"
    } else {
        Write-Output "DISABLED"
    }
} catch {
    Write-Output "ERROR:$($_.Exception.Message)"
}
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying AD Recycle Bin"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if output == "ENABLED" {
		result.Passed = true
		result.Actual = "AD Recycle Bin is enabled"
		result.Details = "Deleted objects can be recovered"
	} else if output == "DISABLED" {
		result.Passed = false
		result.Actual = "AD Recycle Bin is NOT enabled"
		result.Details = "Enable AD Recycle Bin to allow recovery of deleted objects"
	} else {
		result.Passed = false
		result.Actual = "Unable to determine AD Recycle Bin status"
		result.Details = output
	}

	return result
}

// checkDomainFunctionalLevel verifies the domain functional level is at least 2016.
// CIS L1: Ensure domain functional level supports modern security features.
func checkDomainFunctionalLevel() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-014",
		Name:        "Domain Functional Level >= 2016",
		Category:    "ad-infrastructure",
		Description: "Verifies the domain functional level is Windows Server 2016 or higher",
		Severity:    "medium",
		Expected:    "DomainMode >= Windows2016Domain",
		Techniques:  []string{"T1078.002"},
		Tactics:     []string{"persistence"},
	}

	script := `
$domain = Get-ADDomain -ErrorAction Stop
$level = $domain.DomainMode.ToString()
Write-Output "LEVEL:$level"
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying domain functional level"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	lines := strings.Split(output, "\n")
	level := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "LEVEL:") {
			level = strings.TrimPrefix(line, "LEVEL:")
		}
	}

	// Acceptable levels: Windows2016Domain, Windows2019Domain, Windows2025Domain, etc.
	// Unacceptable: Windows2000Domain, Windows2003Domain, Windows2008Domain, Windows2008R2Domain, Windows2012Domain, Windows2012R2Domain
	acceptable := map[string]bool{
		"Windows2016Domain": true,
		"Windows2019Domain": true,
		"Windows2025Domain": true,
		"7":                 true, // Numeric representation for 2016
		"8":                 true, // Numeric for 2019
		"10":                true, // Numeric for 2025
	}

	result.Passed = acceptable[level]
	result.Actual = fmt.Sprintf("Domain functional level: %s", level)
	if result.Passed {
		result.Details = "Meets minimum requirement for modern security features"
	} else {
		result.Details = fmt.Sprintf("Current level '%s' is below Windows 2016 (required for credential guard, PAM, etc.)", level)
	}

	return result
}

// checkStaleComputers counts computer accounts that have not authenticated in 90+ days.
// CIS L1: Audit and disable stale computer accounts.
func checkStaleComputers() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-015",
		Name:        "Stale Computers Audit (>90d)",
		Category:    "ad-infrastructure",
		Description: "Counts computer accounts that have not logged in for 90+ days",
		Severity:    "medium",
		Expected:    "0 stale computer accounts (informational if >0)",
		Techniques:  []string{"T1078.002"},
		Tactics:     []string{"persistence"},
	}

	script := `
$threshold = (Get-Date).AddDays(-90)
$stale = Get-ADComputer -Filter {LastLogonDate -lt $threshold -and Enabled -eq $true} -Properties LastLogonDate -ErrorAction Stop
$count = @($stale).Count
Write-Output "COUNT:$count"
if ($count -gt 0) {
    $sample = ($stale | Sort-Object LastLogonDate | Select-Object -First 5 | ForEach-Object {
        "$($_.Name):$([math]::Floor(((Get-Date) - $_.LastLogonDate).TotalDays))d"
    }) -join ', '
    Write-Output "SAMPLE:$sample"
}
$totalComputers = @(Get-ADComputer -Filter {Enabled -eq $true}).Count
Write-Output "TOTAL:$totalComputers"
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying stale computers"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	lines := strings.Split(output, "\n")
	staleCount := 0
	totalCount := 0
	sample := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COUNT:") {
			staleCount, _ = strconv.Atoi(strings.TrimPrefix(line, "COUNT:"))
		}
		if strings.HasPrefix(line, "TOTAL:") {
			totalCount, _ = strconv.Atoi(strings.TrimPrefix(line, "TOTAL:"))
		}
		if strings.HasPrefix(line, "SAMPLE:") {
			sample = strings.TrimPrefix(line, "SAMPLE:")
		}
	}

	// Pass if stale count is less than 10% of total or 0
	threshold := totalCount / 10
	if threshold < 5 {
		threshold = 5
	}
	result.Passed = staleCount <= threshold
	result.Actual = fmt.Sprintf("%d stale computers out of %d total", staleCount, totalCount)
	if staleCount == 0 {
		result.Details = "No stale computer accounts found"
	} else if result.Passed {
		result.Details = fmt.Sprintf("%d stale computers (within acceptable threshold). Examples: %s", staleCount, sample)
	} else {
		result.Details = fmt.Sprintf("%d stale computers exceed threshold (>%d). Oldest: %s", staleCount, threshold, sample)
	}

	return result
}

// checkStaleUsers counts user accounts that have not authenticated in 90+ days.
// CIS L1: Audit and disable stale user accounts.
func checkStaleUsers() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-016",
		Name:        "Stale Users Audit (>90d)",
		Category:    "ad-infrastructure",
		Description: "Counts user accounts that have not logged in for 90+ days",
		Severity:    "medium",
		Expected:    "Stale user count within acceptable threshold",
		Techniques:  []string{"T1078.002"},
		Tactics:     []string{"persistence"},
	}

	script := `
$threshold = (Get-Date).AddDays(-90)
$stale = Get-ADUser -Filter {LastLogonDate -lt $threshold -and Enabled -eq $true} -Properties LastLogonDate -ErrorAction Stop
$count = @($stale).Count
Write-Output "COUNT:$count"
if ($count -gt 0) {
    $sample = ($stale | Sort-Object LastLogonDate | Select-Object -First 5 | ForEach-Object {
        "$($_.SamAccountName):$([math]::Floor(((Get-Date) - $_.LastLogonDate).TotalDays))d"
    }) -join ', '
    Write-Output "SAMPLE:$sample"
}
$totalUsers = @(Get-ADUser -Filter {Enabled -eq $true}).Count
Write-Output "TOTAL:$totalUsers"
`
	output, err := RunADCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying stale users"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	lines := strings.Split(output, "\n")
	staleCount := 0
	totalCount := 0
	sample := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COUNT:") {
			staleCount, _ = strconv.Atoi(strings.TrimPrefix(line, "COUNT:"))
		}
		if strings.HasPrefix(line, "TOTAL:") {
			totalCount, _ = strconv.Atoi(strings.TrimPrefix(line, "TOTAL:"))
		}
		if strings.HasPrefix(line, "SAMPLE:") {
			sample = strings.TrimPrefix(line, "SAMPLE:")
		}
	}

	// Pass if stale count is less than 10% of total or 0
	threshold := totalCount / 10
	if threshold < 5 {
		threshold = 5
	}
	result.Passed = staleCount <= threshold
	result.Actual = fmt.Sprintf("%d stale users out of %d total", staleCount, totalCount)
	if staleCount == 0 {
		result.Details = "No stale user accounts found"
	} else if result.Passed {
		result.Details = fmt.Sprintf("%d stale users (within acceptable threshold). Examples: %s", staleCount, sample)
	} else {
		result.Details = fmt.Sprintf("%d stale users exceed threshold (>%d). Oldest: %s", staleCount, threshold, sample)
	}

	return result
}

// checkLDAPSigning verifies LDAP signing is required on the domain controller.
// CIS L1: Require LDAP signing (LDAPServerIntegrity = 2).
func checkLDAPSigning() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-017",
		Name:        "LDAP Signing Required",
		Category:    "ad-infrastructure",
		Description: "Verifies LDAP server signing is set to 'Require signing' (registry value 2)",
		Severity:    "high",
		Expected:    "LDAPServerIntegrity = 2 (Require signing)",
		Techniques:  []string{"T1078.002"},
		Tactics:     []string{"credential-access"},
	}

	// Check local registry (on domain-joined machine, this reflects GP-applied setting)
	// Also query via PowerShell for DC-side setting if available
	script := `
try {
    $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -ErrorAction Stop
    Write-Output "VALUE:$($val.LDAPServerIntegrity)"
} catch {
    # On non-DC, check ldap client signing requirement instead
    try {
        $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap' -Name 'LDAPClientIntegrity' -ErrorAction Stop
        Write-Output "CLIENT:$($val.LDAPClientIntegrity)"
    } catch {
        Write-Output "NOTSET"
    }
}
`
	output, err := RunPowerShell(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error reading LDAP signing registry"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "VALUE:") {
		valStr := strings.TrimPrefix(output, "VALUE:")
		val, _ := strconv.Atoi(strings.TrimSpace(valStr))
		result.Passed = val == 2
		switch val {
		case 0:
			result.Actual = "LDAPServerIntegrity = 0 (None)"
			result.Details = "LDAP signing not required"
		case 1:
			result.Actual = "LDAPServerIntegrity = 1 (Negotiated)"
			result.Details = "LDAP signing negotiated but not required"
		case 2:
			result.Actual = "LDAPServerIntegrity = 2 (Required)"
			result.Details = "LDAP signing is required"
		default:
			result.Actual = fmt.Sprintf("LDAPServerIntegrity = %d (Unknown)", val)
			result.Details = "Unexpected value"
		}
	} else if strings.HasPrefix(output, "CLIENT:") {
		valStr := strings.TrimPrefix(output, "CLIENT:")
		val, _ := strconv.Atoi(strings.TrimSpace(valStr))
		// Client signing: 1 = Negotiate, 2 = Require
		result.Passed = val >= 1
		result.Actual = fmt.Sprintf("LDAPClientIntegrity = %d (non-DC machine)", val)
		if val >= 1 {
			result.Details = "LDAP client signing enabled (check DC-side setting separately)"
		} else {
			result.Details = "LDAP client signing not configured"
		}
	} else {
		result.Passed = false
		result.Actual = "LDAP signing registry value not set"
		result.Details = "Configure via Group Policy: Network security: LDAP client signing requirements"
	}

	return result
}

// checkLDAPChannelBinding verifies LDAP channel binding is enabled.
// CIS L1: Enable LDAP channel binding (LdapEnforceChannelBinding >= 1).
func checkLDAPChannelBinding() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CIA-018",
		Name:        "LDAP Channel Binding",
		Category:    "ad-infrastructure",
		Description: "Verifies LDAP channel binding is enabled (registry LdapEnforceChannelBinding >= 1)",
		Severity:    "high",
		Expected:    "LdapEnforceChannelBinding >= 1",
		Techniques:  []string{"T1078.002"},
		Tactics:     []string{"credential-access"},
	}

	script := `
try {
    $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -ErrorAction Stop
    Write-Output "VALUE:$($val.LdapEnforceChannelBinding)"
} catch {
    Write-Output "NOTSET"
}
`
	output, err := RunPowerShell(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error reading LDAP channel binding registry"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "VALUE:") {
		valStr := strings.TrimPrefix(output, "VALUE:")
		val, _ := strconv.Atoi(strings.TrimSpace(valStr))
		result.Passed = val >= 1
		switch val {
		case 0:
			result.Actual = "LdapEnforceChannelBinding = 0 (Disabled)"
			result.Details = "LDAP channel binding not enforced"
		case 1:
			result.Actual = "LdapEnforceChannelBinding = 1 (When supported)"
			result.Details = "Channel binding enabled when client supports it"
		case 2:
			result.Actual = "LdapEnforceChannelBinding = 2 (Always)"
			result.Details = "Channel binding always required"
		default:
			result.Actual = fmt.Sprintf("LdapEnforceChannelBinding = %d", val)
			result.Details = "Unexpected value"
		}
	} else {
		result.Passed = false
		result.Actual = "LdapEnforceChannelBinding not configured"
		result.Details = "Registry value not set (defaults to disabled). Configure on domain controllers."
	}

	return result
}

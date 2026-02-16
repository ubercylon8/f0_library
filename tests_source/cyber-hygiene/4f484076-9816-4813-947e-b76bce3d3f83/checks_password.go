//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
)

// RunPasswordChecks validates CISA SCuBA Section 6: Password Policies
func RunPasswordChecks() ValidatorResult {
	checks := []CheckResult{
		checkPasswordsDoNotExpire(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Password Policies",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkPasswordsDoNotExpire verifies password expiration is disabled per NIST SP 800-63B.
// SCuBA MS.AAD.6.1: Passwords SHALL NOT expire.
func checkPasswordsDoNotExpire() CheckResult {
	result := CheckResult{
		ControlID:   "CH-ITN-016",
		Name:        "Passwords Do Not Expire",
		Category:    "password",
		Description: "Verifies password expiration is disabled per NIST SP 800-63B guidance",
		Severity:    "medium",
		SCuBAID:     "MS.AAD.6.1",
		Expected:    "passwordValidityPeriodInDays = 2147483647 (never expire)",
		Techniques:  []string{"T1110.001"},
		Tactics:     []string{"credential-access"},
	}

	script := `
$domains = Get-MgDomain
$results = @()
foreach ($d in $domains) {
    if ($d.IsVerified) {
        $validity = $d.PasswordValidityPeriodInDays
        $results += "$($d.Id):$validity"
    }
}
Write-Output ($results -join '|')
`
	output, err := RunGraphCommand(script)
	if err != nil {
		result.Passed = false
		result.Actual = "Error querying domain password policies"
		result.Details = fmt.Sprintf("Query failed: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	if output == "" {
		result.Passed = false
		result.Actual = "No verified domains found"
		result.Details = "Could not retrieve domain password policies"
		return result
	}

	// Check all domains -- passwords should not expire (2147483647 = never)
	domains := strings.Split(output, "|")
	allNonExpiring := true
	expiringDomains := []string{}

	for _, d := range domains {
		parts := strings.SplitN(d, ":", 2)
		if len(parts) != 2 {
			continue
		}
		domainName := parts[0]
		validity := strings.TrimSpace(parts[1])

		if validity != "2147483647" {
			allNonExpiring = false
			expiringDomains = append(expiringDomains, fmt.Sprintf("%s(%s days)", domainName, validity))
		}
	}

	result.Passed = allNonExpiring
	if allNonExpiring {
		result.Actual = fmt.Sprintf("All %d domains: passwords do not expire", len(domains))
		result.Details = "NIST SP 800-63B compliant"
	} else {
		result.Actual = fmt.Sprintf("Password expiration set on: %s", strings.Join(expiringDomains, ", "))
		result.Details = "Should be set to never expire per NIST SP 800-63B"
	}

	return result
}

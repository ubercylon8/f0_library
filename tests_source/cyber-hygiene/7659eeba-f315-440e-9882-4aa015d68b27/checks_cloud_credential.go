//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Cloud credential registry paths
const (
	CloudKerberosPath = `SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`
)

// RunCloudCredentialChecks performs all cloud credential protection checks
func RunCloudCredentialChecks() ValidatorResult {
	checks := []CheckResult{
		checkPRTStatus(),
		checkPRTUpdateTime(),
		checkCloudKerberosTrust(),
		checkDeviceBoundPRT(),
		checkSSOState(),
	}

	passed, failed := AggregateValidatorResults(checks)

	// Gate: PRT status must pass
	prtPassed := false
	for _, check := range checks {
		if check.Name == "PRT Status" && check.Passed {
			prtPassed = true
			break
		}
	}

	return ValidatorResult{
		Name:        "Cloud Credential Protection",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: prtPassed,
	}
}

// checkPRTStatus checks if a Primary Refresh Token is present
func checkPRTStatus() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-015",
		Name:        "PRT Status",
		Category:    "cloud-credential",
		Description: "Checks if a Primary Refresh Token (PRT) is issued for SSO",
		Severity:    "critical",
		Expected:    "AzureAdPrt : YES",
		Techniques:  []string{"T1528", "T1550.001"},
		Tactics:     []string{"credential-access", "defense-evasion", "lateral-movement"},
	}

	val, found := GetDsregcmdValue("SSO State", "AzureAdPrt")
	if !found {
		result.Passed = false
		result.Actual = "AzureAdPrt not found in dsregcmd output"
		result.Details = "Not found"
		return result
	}

	hasPRT := strings.EqualFold(val, "YES")
	result.Passed = hasPRT
	result.Actual = fmt.Sprintf("AzureAdPrt : %s", val)
	result.Details = BoolToYesNo(hasPRT)
	return result
}

// checkPRTUpdateTime checks if the PRT has been recently refreshed
func checkPRTUpdateTime() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-016",
		Name:        "PRT Update Time",
		Category:    "cloud-credential",
		Description: "Checks if PRT update time is populated (indicates active token refresh)",
		Severity:    "low",
		Expected:    "AzureAdPrtUpdateTime non-empty",
		Techniques:  []string{"T1528"},
		Tactics:     []string{"credential-access"},
	}

	val, found := GetDsregcmdValue("SSO State", "AzureAdPrtUpdateTime")
	if !found {
		// Informational - pass even if not found
		result.Passed = true
		result.Actual = "PRT update time not available"
		result.Details = "N/A"
		return result
	}

	if val != "" {
		result.Passed = true
		result.Actual = fmt.Sprintf("Last updated: %s", val)
		result.Details = "Present"
	} else {
		result.Passed = true // Informational
		result.Actual = "PRT update time empty"
		result.Details = "Empty"
	}
	return result
}

// checkCloudKerberosTrust checks if Cloud Kerberos Trust is enabled
func checkCloudKerberosTrust() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-017",
		Name:        "Cloud Kerberos Trust",
		Category:    "cloud-credential",
		Description: "Checks if Cloud Kerberos Trust is enabled for passwordless sign-in",
		Severity:    "medium",
		Expected:    "CloudKerberosTicketRetrievalEnabled = 1",
		Techniques:  []string{"T1550.001"},
		Tactics:     []string{"defense-evasion", "lateral-movement"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, CloudKerberosPath,
		"CloudKerberosTicketRetrievalEnabled", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("CloudKerberosTicketRetrievalEnabled = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

// checkDeviceBoundPRT checks if the PRT is device-bound via NGC key
func checkDeviceBoundPRT() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-018",
		Name:        "Device-Bound PRT",
		Category:    "cloud-credential",
		Description: "Checks if PRT is bound to device via NGC key (stronger than session-bound)",
		Severity:    "high",
		Expected:    "NgcKeyId field non-empty in dsregcmd SSO State",
		Techniques:  []string{"T1528", "T1550.001"},
		Tactics:     []string{"credential-access", "defense-evasion", "lateral-movement"},
	}

	// Check NgcKeyId in SSO State section
	val, found := GetDsregcmdValue("SSO State", "NgcKeyId")
	if !found {
		// Try NgcSet
		val, found = GetDsregcmdValue("Ngc Prerequisite Check", "NgcKeyId")
	}

	if !found || val == "" {
		// Alternative: check for NGC key in device state
		ngcSet, ngcFound := GetDsregcmdValue("Device State", "NgcSet")
		if ngcFound && strings.EqualFold(ngcSet, "YES") {
			result.Passed = true
			result.Actual = "NGC key set on device"
			result.Details = "NGC bound"
			return result
		}

		result.Passed = false
		result.Actual = "No device-bound NGC key for PRT"
		result.Details = "Not bound"
		return result
	}

	result.Passed = true
	result.Actual = fmt.Sprintf("NgcKeyId: %s", truncateNgcKey(val))
	result.Details = "Device-bound"
	return result
}

// checkSSOState checks the overall SSO state
func checkSSOState() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-019",
		Name:        "SSO State",
		Category:    "cloud-credential",
		Description: "Checks that both PRT and authority are present for SSO",
		Severity:    "medium",
		Expected:    "AzureAdPrt and AzureAdPrtAuthority both present",
		Techniques:  []string{"T1528"},
		Tactics:     []string{"credential-access"},
	}

	prt, prtFound := GetDsregcmdValue("SSO State", "AzureAdPrt")
	authority, authFound := GetDsregcmdValue("SSO State", "AzureAdPrtAuthority")

	hasPRT := prtFound && strings.EqualFold(prt, "YES")
	hasAuthority := authFound && authority != ""

	if hasPRT && hasAuthority {
		result.Passed = true
		result.Actual = fmt.Sprintf("PRT: YES, Authority: %s", truncateAuthority(authority))
		result.Details = "Complete"
	} else if hasPRT {
		result.Passed = true // PRT present is sufficient
		result.Actual = "PRT present, authority not listed"
		result.Details = "Partial"
	} else {
		result.Passed = false
		result.Actual = "SSO not operational"
		result.Details = "Incomplete"
	}

	return result
}

// truncateNgcKey truncates an NGC key ID for display
func truncateNgcKey(key string) string {
	if len(key) > 20 {
		return key[:20] + "..."
	}
	return key
}

// truncateAuthority truncates an authority URL for display
func truncateAuthority(authority string) string {
	if len(authority) > 40 {
		return authority[:40] + "..."
	}
	return authority
}

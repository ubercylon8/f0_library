//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RunDeviceJoinChecks performs all Azure AD / Hybrid Join status checks
func RunDeviceJoinChecks() ValidatorResult {
	checks := []CheckResult{
		checkAzureADJoined(),
		checkDomainJoined(),
		checkDeviceJoinType(),
		checkTenantInfoPresent(),
		checkDeviceAuthStatus(),
	}

	passed, failed := AggregateValidatorResults(checks)

	// Gate: join type AND tenant info must pass
	joinTypePass := false
	tenantInfoPass := false
	for _, check := range checks {
		if check.Name == "Device Join Type" && check.Passed {
			joinTypePass = true
		}
		if check.Name == "Tenant Info Present" && check.Passed {
			tenantInfoPass = true
		}
	}

	return ValidatorResult{
		Name:        "Device Join Status",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: joinTypePass && tenantInfoPass,
	}
}

// checkAzureADJoined checks if the device is Azure AD joined
func checkAzureADJoined() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-001",
		Name:        "Azure AD Joined",
		Category:    "device-join",
		Description: "Checks if device is joined to Azure Active Directory",
		Severity:    "critical",
		Expected:    "AzureAdJoined : YES",
		Techniques:  []string{"T1078.004", "T1556.007"},
		Tactics:     []string{"credential-access", "defense-evasion", "persistence", "initial-access"},
	}

	val, found := GetDsregcmdValue("Device State", "AzureAdJoined")
	if !found {
		// Fallback: check registry
		subkeys, err := CheckRegistrySubkeys(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`)
		if err == nil && len(subkeys) > 0 {
			result.Passed = true
			result.Actual = "YES (registry)"
			result.Details = "Joined (registry fallback)"
			return result
		}

		result.Passed = false
		result.Actual = "Unable to determine"
		result.Details = "dsregcmd unavailable"
		return result
	}

	isJoined := strings.EqualFold(val, "YES")
	result.Passed = isJoined
	result.Actual = fmt.Sprintf("AzureAdJoined : %s", val)
	result.Details = BoolToYesNo(isJoined)
	return result
}

// checkDomainJoined checks if the device is on-premises domain joined
func checkDomainJoined() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-002",
		Name:        "Domain Joined",
		Category:    "device-join",
		Description: "Checks if device is joined to on-premises Active Directory (informational)",
		Severity:    "medium",
		Expected:    "DomainJoined : YES (informational)",
		Techniques:  []string{"T1556.007"},
		Tactics:     []string{"credential-access", "defense-evasion"},
	}

	val, found := GetDsregcmdValue("Device State", "DomainJoined")
	if !found {
		result.Passed = true // Informational - not required
		result.Actual = "Unable to determine"
		result.Details = "N/A"
		return result
	}

	isJoined := strings.EqualFold(val, "YES")
	result.Passed = true // Informational check - always passes
	result.Actual = fmt.Sprintf("DomainJoined : %s", val)
	if isJoined {
		result.Details = "Yes (on-prem AD)"
	} else {
		result.Details = "No (cloud-only)"
	}
	return result
}

// checkDeviceJoinType determines the effective join type
func checkDeviceJoinType() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-003",
		Name:        "Device Join Type",
		Category:    "device-join",
		Description: "Determines if device is AAD-joined, hybrid-joined, or unjoined",
		Severity:    "critical",
		Expected:    "AAD-joined or Hybrid-joined (not unjoined)",
		Techniques:  []string{"T1078.004", "T1556.007"},
		Tactics:     []string{"credential-access", "defense-evasion", "persistence", "initial-access"},
	}

	aadVal, aadFound := GetDsregcmdValue("Device State", "AzureAdJoined")
	domVal, domFound := GetDsregcmdValue("Device State", "DomainJoined")

	aadJoined := aadFound && strings.EqualFold(aadVal, "YES")
	domJoined := domFound && strings.EqualFold(domVal, "YES")

	if !aadFound && !domFound {
		// Fallback: check registry for cloud join
		subkeys, err := CheckRegistrySubkeys(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`)
		if err == nil && len(subkeys) > 0 {
			result.Passed = true
			result.Actual = "Azure AD Joined (registry)"
			result.Details = "AAD-joined"
			return result
		}

		result.Passed = false
		result.Actual = "Unable to determine join status"
		result.Details = "Unknown"
		return result
	}

	if aadJoined && domJoined {
		result.Passed = true
		result.Actual = "Hybrid Azure AD Joined"
		result.Details = "Hybrid-joined"
	} else if aadJoined {
		result.Passed = true
		result.Actual = "Azure AD Joined"
		result.Details = "AAD-joined"
	} else if domJoined {
		// Domain-only without AAD: partial compliance
		result.Passed = false
		result.Actual = "On-premises Domain Joined only"
		result.Details = "Domain-only (no AAD)"
	} else {
		result.Passed = false
		result.Actual = "Not joined to any directory"
		result.Details = "Unjoined"
	}

	return result
}

// checkTenantInfoPresent checks if tenant details are populated
func checkTenantInfoPresent() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-004",
		Name:        "Tenant Info Present",
		Category:    "device-join",
		Description: "Checks if Azure AD tenant details (TenantId, TenantName) are populated",
		Severity:    "high",
		Expected:    "TenantId and TenantName non-empty",
		Techniques:  []string{"T1078.004"},
		Tactics:     []string{"credential-access", "defense-evasion", "persistence", "initial-access"},
	}

	tenantID, tidFound := GetDsregcmdValue("Tenant Details", "TenantId")
	tenantName, tnFound := GetDsregcmdValue("Tenant Details", "TenantName")

	hasTenantID := tidFound && tenantID != ""
	hasTenantName := tnFound && tenantName != ""

	if hasTenantID && hasTenantName {
		result.Passed = true
		result.Actual = fmt.Sprintf("Tenant: %s (%s)", tenantName, tenantID[:8]+"...")
		result.Details = tenantName
	} else if hasTenantID {
		result.Passed = true
		result.Actual = fmt.Sprintf("TenantId: %s (name missing)", tenantID[:8]+"...")
		result.Details = "ID present"
	} else {
		result.Passed = false
		result.Actual = "No tenant information found"
		result.Details = "Missing"
	}

	return result
}

// checkDeviceAuthStatus checks if device authentication is successful
func checkDeviceAuthStatus() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-005",
		Name:        "Device Auth Status",
		Category:    "device-join",
		Description: "Checks if device authentication to Azure AD is successful",
		Severity:    "medium",
		Expected:    "DeviceAuthStatus : SUCCESS",
		Techniques:  []string{"T1078.004"},
		Tactics:     []string{"credential-access", "defense-evasion"},
	}

	val, found := GetDsregcmdValue("Device State", "DeviceAuthStatus")
	if !found {
		result.Passed = false
		result.Actual = "DeviceAuthStatus not found"
		result.Details = "N/A"
		return result
	}

	isSuccess := strings.EqualFold(val, "SUCCESS")
	result.Passed = isSuccess
	result.Actual = fmt.Sprintf("DeviceAuthStatus : %s", val)
	result.Details = val
	return result
}

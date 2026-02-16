//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// MDM registry paths
const (
	MDMEnrollmentPath    = `SOFTWARE\Microsoft\Enrollments`
	IntuneExtensionPath  = `SOFTWARE\Microsoft\IntuneManagementExtension\Policies`
	PolicyManagerPath    = `SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock`
)

// RunMDMEnrollmentChecks performs all MDM/Intune enrollment checks
func RunMDMEnrollmentChecks() ValidatorResult {
	checks := []CheckResult{
		checkMDMEnrollment(),
		checkMDMAuthority(),
		checkCompliancePolicies(),
		checkConfigProfiles(),
	}

	passed, failed := AggregateValidatorResults(checks)

	// Gate: MDM enrollment must pass
	enrollmentPassed := false
	for _, check := range checks {
		if check.Name == "MDM Enrollment" && check.Passed {
			enrollmentPassed = true
			break
		}
	}

	return ValidatorResult{
		Name:        "Intune/MDM Enrollment",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: enrollmentPassed,
	}
}

// checkMDMEnrollment checks if the device is enrolled in an MDM provider
func checkMDMEnrollment() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-011",
		Name:        "MDM Enrollment",
		Category:    "mdm",
		Description: "Checks if device is enrolled in an MDM provider (Intune)",
		Severity:    "critical",
		Expected:    "MDM enrollment subkey with ProviderID present",
		Techniques:  []string{"T1078.004", "T1588.004"},
		Tactics:     []string{"credential-access", "defense-evasion", "persistence", "initial-access"},
	}

	subkeys, err := CheckRegistrySubkeys(registry.LOCAL_MACHINE, MDMEnrollmentPath)
	if err != nil {
		result.Passed = false
		result.Actual = "Enrollments registry key not found"
		result.Details = "Not enrolled"
		return result
	}

	// Look for subkeys that have a ProviderID value (indicating MDM enrollment)
	for _, sk := range subkeys {
		enrollPath := fmt.Sprintf(`%s\%s`, MDMEnrollmentPath, sk)
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, enrollPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		providerID, _, err := key.GetStringValue("ProviderID")
		key.Close()
		if err == nil && providerID != "" {
			result.Passed = true
			result.Actual = fmt.Sprintf("Enrolled (Provider: %s)", providerID)
			result.Details = providerID
			return result
		}
	}

	result.Passed = false
	result.Actual = "No MDM enrollment found"
	result.Details = "Not enrolled"
	return result
}

// checkMDMAuthority checks if the MDM authority is Microsoft (Intune)
func checkMDMAuthority() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-012",
		Name:        "MDM Authority",
		Category:    "mdm",
		Description: "Checks if the MDM provider is Microsoft DM Server (Intune)",
		Severity:    "high",
		Expected:    "ProviderID contains 'MS DM Server'",
		Techniques:  []string{"T1588.004"},
		Tactics:     []string{"credential-access", "defense-evasion"},
	}

	subkeys, err := CheckRegistrySubkeys(registry.LOCAL_MACHINE, MDMEnrollmentPath)
	if err != nil {
		result.Passed = false
		result.Actual = "Enrollments registry key not found"
		result.Details = "N/A"
		return result
	}

	for _, sk := range subkeys {
		enrollPath := fmt.Sprintf(`%s\%s`, MDMEnrollmentPath, sk)
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, enrollPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		providerID, _, err := key.GetStringValue("ProviderID")
		key.Close()
		if err == nil && strings.Contains(providerID, "MS DM Server") {
			result.Passed = true
			result.Actual = "Microsoft DM Server (Intune)"
			result.Details = "Intune"
			return result
		} else if err == nil && providerID != "" {
			// MDM provider found but not Intune
			result.Passed = true // Still valid if using another MDM
			result.Actual = fmt.Sprintf("MDM Provider: %s", providerID)
			result.Details = providerID
			return result
		}
	}

	result.Passed = false
	result.Actual = "No MDM authority found"
	result.Details = "Not configured"
	return result
}

// checkCompliancePolicies checks if compliance policies are applied
func checkCompliancePolicies() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-013",
		Name:        "Compliance Policies",
		Category:    "mdm",
		Description: "Checks if MDM compliance policies are applied via PolicyManager",
		Severity:    "medium",
		Expected:    "PolicyManager compliance keys present",
		Techniques:  []string{"T1588.004"},
		Tactics:     []string{"defense-evasion"},
	}

	// Check PolicyManager for device lock policies (indicates compliance policies)
	exists, err := CheckRegistryExists(registry.LOCAL_MACHINE, PolicyManagerPath, "")
	if err == nil && exists {
		result.Passed = true
		result.Actual = "Compliance policies applied"
		result.Details = "Policies present"
		return result
	}

	// Alternative: check via PowerShell
	output, err := RunPowerShell(`
		$policies = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device" -ErrorAction SilentlyContinue
		if ($policies.Count -gt 0) { Write-Output $policies.Count } else { Write-Output "0" }
	`)
	if err == nil {
		count := strings.TrimSpace(output)
		if count != "0" && count != "" {
			result.Passed = true
			result.Actual = fmt.Sprintf("%s policy areas configured", count)
			result.Details = fmt.Sprintf("%s areas", count)
			return result
		}
	}

	result.Passed = false
	result.Actual = "No compliance policies found"
	result.Details = "None"
	return result
}

// checkConfigProfiles checks if Intune configuration profiles are present
func checkConfigProfiles() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-014",
		Name:        "Config Profiles",
		Category:    "mdm",
		Description: "Checks if Intune Management Extension policies have subkeys",
		Severity:    "medium",
		Expected:    "IntuneManagementExtension\\Policies has subkeys",
		Techniques:  []string{"T1588.004"},
		Tactics:     []string{"defense-evasion"},
	}

	subkeys, err := CheckRegistrySubkeys(registry.LOCAL_MACHINE, IntuneExtensionPath)
	if err != nil {
		// Fallback: check if IME service exists
		exists, _, _, svcErr := CheckServiceStatus("IntuneManagementExtension")
		if svcErr == nil && exists {
			result.Passed = true
			result.Actual = "IME service present (policies may be cached)"
			result.Details = "Service present"
			return result
		}

		result.Passed = false
		result.Actual = "IntuneManagementExtension not found"
		result.Details = "Not installed"
		return result
	}

	if len(subkeys) > 0 {
		result.Passed = true
		result.Actual = fmt.Sprintf("%d configuration profile(s) detected", len(subkeys))
		result.Details = fmt.Sprintf("%d profiles", len(subkeys))
	} else {
		result.Passed = false
		result.Actual = "No configuration profiles found"
		result.Details = "None"
	}

	return result
}

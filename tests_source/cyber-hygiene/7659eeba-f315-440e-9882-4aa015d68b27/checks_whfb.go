//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// WHfB registry paths
const (
	PassportPolicyPath = `SOFTWARE\Policies\Microsoft\PassportForWork`
	PassportSystemPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}`
	NgcPath            = `ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc`
	BiometricPolicyPath = `SOFTWARE\Policies\Microsoft\Biometrics`
)

// RunWHfBChecks performs all Windows Hello for Business checks
func RunWHfBChecks() ValidatorResult {
	checks := []CheckResult{
		checkWHfBPolicyEnabled(),
		checkNGCCredentialProvider(),
		checkPINComplexity(),
		checkNGCKeyContainer(),
		checkBiometricAvailable(),
	}

	passed, failed := AggregateValidatorResults(checks)

	// LAPS-style OR compliance: (policy OR provider) AND NGC keys
	policyOrProvider := false
	ngcKeysExist := false

	for _, check := range checks {
		if (check.Name == "WHfB Policy Enabled" || check.Name == "NGC Credential Provider") && check.Passed {
			policyOrProvider = true
		}
		if check.Name == "NGC Key Container" && check.Passed {
			ngcKeysExist = true
		}
	}

	return ValidatorResult{
		Name:        "Windows Hello for Business",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: policyOrProvider && ngcKeysExist,
	}
}

// checkWHfBPolicyEnabled checks if WHfB is enabled via policy
func checkWHfBPolicyEnabled() CheckResult {
	result := CheckResult{
		Name:        "WHfB Policy Enabled",
		Category:    "whfb",
		Description: "Checks if Windows Hello for Business is enabled via Group Policy",
		Severity:    "high",
		Expected:    "PassportForWork\\Enabled = 1",
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, PassportPolicyPath, "Enabled", 1)
	if err != nil {
		// Check if tenant-specific policy exists (PassportForWork\<TenantId>\Policies)
		subkeys, subErr := CheckRegistrySubkeys(registry.LOCAL_MACHINE, PassportPolicyPath)
		if subErr == nil {
			for _, sk := range subkeys {
				tenantPath := fmt.Sprintf(`%s\%s\Policies`, PassportPolicyPath, sk)
				m, _, e := CheckRegistryDWORD(registry.LOCAL_MACHINE, tenantPath, "UsePassportForWork", 1)
				if e == nil && m {
					result.Passed = true
					result.Actual = "Enabled (tenant policy)"
					result.Details = "Enabled"
					return result
				}
			}
		}

		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("Enabled = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

// checkNGCCredentialProvider checks if the NGC credential provider is registered
func checkNGCCredentialProvider() CheckResult {
	result := CheckResult{
		Name:        "NGC Credential Provider",
		Category:    "whfb",
		Description: "Checks if the NGC (Windows Hello) credential provider key exists",
		Severity:    "high",
		Expected:    "{D6886603-9D2F-4EB2-B667-1971041FA96B} provider key exists",
	}

	exists, err := CheckRegistryExists(registry.LOCAL_MACHINE, PassportSystemPath, "")
	if err != nil {
		result.Passed = false
		result.Actual = "Error checking provider"
		result.Details = "Error"
		return result
	}

	result.Passed = exists
	if exists {
		result.Actual = "NGC credential provider registered"
		result.Details = "Registered"
	} else {
		result.Actual = "NGC credential provider not found"
		result.Details = "Not found"
	}
	return result
}

// checkPINComplexity checks if PIN complexity requirements are configured
func checkPINComplexity() CheckResult {
	result := CheckResult{
		Name:        "PIN Complexity",
		Category:    "whfb",
		Description: "Checks if minimum PIN length is at least 6 digits",
		Severity:    "medium",
		Expected:    "MinimumPINLength >= 6",
	}

	pinPolicyPath := PassportPolicyPath + `\PINComplexity`
	match, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE, pinPolicyPath, "MinimumPINLength", 6)
	if err != nil {
		// Check tenant-specific paths
		subkeys, subErr := CheckRegistrySubkeys(registry.LOCAL_MACHINE, PassportPolicyPath)
		if subErr == nil {
			for _, sk := range subkeys {
				tenantPinPath := fmt.Sprintf(`%s\%s\Policies\PINComplexity`, PassportPolicyPath, sk)
				m, v, e := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE, tenantPinPath, "MinimumPINLength", 6)
				if e == nil {
					result.Passed = m
					result.Actual = fmt.Sprintf("MinimumPINLength = %d", v)
					result.Details = fmt.Sprintf("%d digits", v)
					return result
				}
			}
		}

		// Default Windows PIN minimum is 4, which is below our threshold
		result.Passed = false
		result.Actual = "Not configured (default: 4)"
		result.Details = "Default (4)"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("MinimumPINLength = %d", val)
	result.Details = fmt.Sprintf("%d digits", val)
	return result
}

// checkNGCKeyContainer checks if the NGC key container directory exists and is non-empty
func checkNGCKeyContainer() CheckResult {
	result := CheckResult{
		Name:        "NGC Key Container",
		Category:    "whfb",
		Description: "Checks if the NGC key container directory exists with enrolled keys",
		Severity:    "high",
		Expected:    "NGC directory exists and is non-empty",
	}

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	ngcDir := filepath.Join(systemRoot, NgcPath)

	exists, nonEmpty := CheckDirectoryExists(ngcDir)
	if !exists {
		result.Passed = false
		result.Actual = "NGC directory not found"
		result.Details = "Not found"
		return result
	}

	if !nonEmpty {
		result.Passed = false
		result.Actual = "NGC directory exists but empty"
		result.Details = "Empty"
		return result
	}

	result.Passed = true
	result.Actual = "NGC keys enrolled"
	result.Details = "Keys present"
	return result
}

// checkBiometricAvailable checks if biometric authentication is available
func checkBiometricAvailable() CheckResult {
	result := CheckResult{
		Name:        "Biometric Available",
		Category:    "whfb",
		Description: "Checks if biometric authentication is enabled (informational)",
		Severity:    "low",
		Expected:    "Biometric hardware or policy enabled",
	}

	// Check policy
	match, _, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, BiometricPolicyPath, "Enabled", 1)
	if err == nil && match {
		result.Passed = true
		result.Actual = "Biometrics enabled via policy"
		result.Details = "Policy enabled"
		return result
	}

	// Check WBF (Windows Biometric Framework) service
	output, err := RunPowerShell(`
		$wbf = Get-WmiObject -Class Win32_BiometricUnit -ErrorAction SilentlyContinue
		if ($wbf) { "Available" } else { "NotAvailable" }
	`)
	if err == nil && strings.TrimSpace(output) == "Available" {
		result.Passed = true
		result.Actual = "Biometric hardware detected"
		result.Details = "Hardware available"
		return result
	}

	// Informational - pass even if not available
	result.Passed = true
	result.Actual = "No biometric hardware detected"
	result.Details = "Not available"
	return result
}

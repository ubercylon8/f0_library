//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RunAccountChecks performs Account Management checks (CIS Level 1)
func RunAccountChecks() ValidatorResult {
	checks := []CheckResult{
		checkBlockMicrosoftAccounts(),
		checkGuestAccountDisabled(),
		checkRenameAdministrator(),
		checkRenameGuest(),
		checkLAPSEnabled(),
		checkLAPSPasswordComplexity(),
		checkLAPSPasswordLength(),
		checkLAPSPasswordAge(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Account Management",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// CH-CW1-011: Block Microsoft Accounts
func checkBlockMicrosoftAccounts() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-011",
		Name:        "Block Microsoft Accounts",
		Category:    "accounts",
		Description: "Accounts: Block Microsoft accounts (CIS 2.3.1.2)",
		Severity:    "medium",
		Expected:    "Users can't add or log on with Microsoft accounts (NoConnectedUser = 3)",
		Techniques:  []string{"T1078.001"},
		Tactics:     []string{"persistence"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "NoConnectedUser", 3)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured (Microsoft accounts allowed)"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	switch val {
	case 0:
		result.Actual = "Microsoft accounts allowed"
	case 1:
		result.Actual = "Users can't add Microsoft accounts"
	case 3:
		result.Actual = "Users can't add or log on with Microsoft accounts"
	default:
		result.Actual = fmt.Sprintf("NoConnectedUser = %d", val)
	}
	result.Details = result.Actual
	return result
}

// CH-CW1-012: Guest Account Disabled
func checkGuestAccountDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-012",
		Name:        "Guest Account Disabled",
		Category:    "accounts",
		Description: "Guest account status is Disabled (CIS 2.3.1.3)",
		Severity:    "high",
		Expected:    "Guest account disabled",
		Techniques:  []string{"T1078.001"},
		Tactics:     []string{"persistence", "credential-access"},
	}

	output, err := RunPowerShell(`
		$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
		if ($guest) {
			Write-Output "ENABLED:$($guest.Enabled)"
		} else {
			Write-Output "NOT_FOUND"
		}
	`)

	if err != nil {
		// Fallback to net user
		output, err = RunCommand("net", "user", "Guest")
		if err != nil {
			result.Passed = false
			result.Actual = "Unable to determine Guest account status"
			result.Details = result.Actual
			return result
		}
		isActive := strings.Contains(strings.ToLower(output), "account active") &&
			strings.Contains(strings.ToLower(output), "yes")
		result.Passed = !isActive
		result.Actual = BoolToEnabledDisabled(isActive)
		if !isActive {
			result.Actual = "Disabled"
		}
		result.Details = result.Actual
		return result
	}

	if strings.Contains(output, "NOT_FOUND") {
		result.Passed = true
		result.Actual = "Guest account not found (effectively disabled)"
		result.Details = result.Actual
		return result
	}

	isEnabled := strings.Contains(output, "ENABLED:True")
	result.Passed = !isEnabled
	if isEnabled {
		result.Actual = "Enabled (non-compliant)"
	} else {
		result.Actual = "Disabled"
	}
	result.Details = result.Actual
	return result
}

// CH-CW1-013: Rename Administrator Account
func checkRenameAdministrator() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-013",
		Name:        "Rename Administrator Account",
		Category:    "accounts",
		Description: "Rename administrator account to something other than 'Administrator' (CIS 2.3.1.5)",
		Severity:    "medium",
		Expected:    "Account name is NOT 'Administrator'",
		Techniques:  []string{"T1078.001", "T1078.003"},
		Tactics:     []string{"persistence"},
	}

	// Get the actual name of the built-in Administrator account (SID ending in -500)
	output, err := RunPowerShell(`
		$admin = Get-LocalUser | Where-Object { $_.SID -like '*-500' }
		if ($admin) {
			Write-Output $admin.Name
		} else {
			Write-Output "NOT_FOUND"
		}
	`)

	if err != nil {
		result.Passed = false
		result.Actual = "Unable to determine Administrator account name"
		result.Details = result.Actual
		return result
	}

	name := strings.TrimSpace(output)
	isDefault := strings.EqualFold(name, "Administrator")
	result.Passed = !isDefault
	result.Actual = fmt.Sprintf("Account name: '%s'", name)
	if isDefault {
		result.Details = "Still using default name 'Administrator'"
	} else {
		result.Details = fmt.Sprintf("Renamed to '%s'", name)
	}
	return result
}

// CH-CW1-014: Rename Guest Account
func checkRenameGuest() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-014",
		Name:        "Rename Guest Account",
		Category:    "accounts",
		Description: "Rename guest account to something other than 'Guest' (CIS 2.3.1.6)",
		Severity:    "low",
		Expected:    "Account name is NOT 'Guest'",
		Techniques:  []string{"T1078.001"},
		Tactics:     []string{"persistence"},
	}

	// Get the actual name of the built-in Guest account (SID ending in -501)
	output, err := RunPowerShell(`
		$guest = Get-LocalUser | Where-Object { $_.SID -like '*-501' }
		if ($guest) {
			Write-Output $guest.Name
		} else {
			Write-Output "NOT_FOUND"
		}
	`)

	if err != nil {
		result.Passed = false
		result.Actual = "Unable to determine Guest account name"
		result.Details = result.Actual
		return result
	}

	name := strings.TrimSpace(output)
	if name == "NOT_FOUND" {
		result.Passed = true
		result.Actual = "Guest account not found"
		result.Details = result.Actual
		return result
	}

	isDefault := strings.EqualFold(name, "Guest")
	result.Passed = !isDefault
	result.Actual = fmt.Sprintf("Account name: '%s'", name)
	if isDefault {
		result.Details = "Still using default name 'Guest'"
	} else {
		result.Details = fmt.Sprintf("Renamed to '%s'", name)
	}
	return result
}

// CH-CW1-015: LAPS Enabled
func checkLAPSEnabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-015",
		Name:        "LAPS Enabled",
		Category:    "accounts",
		Description: "Windows LAPS or Legacy LAPS is enabled (CIS 18.2.x)",
		Severity:    "high",
		Expected:    "LAPS configured and enabled",
		Techniques:  []string{"T1078.003"},
		Tactics:     []string{"credential-access", "persistence"},
	}

	// Check for Windows LAPS (built-in, Windows Server 2019+ / Windows 10 21H2+)
	windowsLAPSExists, _ := CheckRegistryExists(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS`, "")

	// Check for Legacy LAPS (Microsoft LAPS add-on)
	legacyLAPSExists, _ := CheckRegistryExists(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft Services\AdmPwd`, "")

	// Check if LAPS DLL exists (Legacy LAPS)
	legacyDLLExists, _ := CheckRegistryExists(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Client Extensions\{D76B9641-3288-4F75-942D-087DE603E3EA}`, "")

	if windowsLAPSExists {
		result.Passed = true
		result.Actual = "Windows LAPS (built-in) configured"
		result.Details = result.Actual
		return result
	}

	if legacyLAPSExists || legacyDLLExists {
		result.Passed = true
		result.Actual = "Legacy LAPS (Microsoft LAPS) configured"
		result.Details = result.Actual
		return result
	}

	result.Passed = false
	result.Actual = "Neither Windows LAPS nor Legacy LAPS detected"
	result.Details = result.Actual
	return result
}

// CH-CW1-016: LAPS Password Complexity >= 4
func checkLAPSPasswordComplexity() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-016",
		Name:        "LAPS Password Complexity",
		Category:    "accounts",
		Description: "LAPS password complexity is Large letters + small letters + numbers + special characters (CIS 18.2.x)",
		Severity:    "medium",
		Expected:    "PasswordComplexity >= 4",
		Techniques:  []string{"T1078.003"},
		Tactics:     []string{"credential-access"},
	}

	// Try Windows LAPS first
	match, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS`, "PasswordComplexity", 4)
	if err == nil {
		result.Passed = match
		result.Actual = fmt.Sprintf("PasswordComplexity = %d (Windows LAPS)", val)
		result.Details = result.Actual
		return result
	}

	// Try Legacy LAPS
	match, val, err = CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft Services\AdmPwd`, "PasswordComplexity", 4)
	if err == nil {
		result.Passed = match
		result.Actual = fmt.Sprintf("PasswordComplexity = %d (Legacy LAPS)", val)
		result.Details = result.Actual
		return result
	}

	result.Passed = false
	result.Actual = "LAPS password complexity not configured"
	result.Details = result.Actual
	return result
}

// CH-CW1-017: LAPS Password Length >= 15
func checkLAPSPasswordLength() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-017",
		Name:        "LAPS Password Length",
		Category:    "accounts",
		Description: "LAPS password length >= 15 characters (CIS 18.2.x)",
		Severity:    "medium",
		Expected:    "PasswordLength >= 15",
		Techniques:  []string{"T1078.003"},
		Tactics:     []string{"credential-access"},
	}

	// Try Windows LAPS first
	match, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS`, "PasswordLength", 15)
	if err == nil {
		result.Passed = match
		result.Actual = fmt.Sprintf("PasswordLength = %d (Windows LAPS)", val)
		result.Details = result.Actual
		return result
	}

	// Try Legacy LAPS
	match, val, err = CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft Services\AdmPwd`, "PasswordLength", 15)
	if err == nil {
		result.Passed = match
		result.Actual = fmt.Sprintf("PasswordLength = %d (Legacy LAPS)", val)
		result.Details = result.Actual
		return result
	}

	result.Passed = false
	result.Actual = "LAPS password length not configured"
	result.Details = result.Actual
	return result
}

// CH-CW1-018: LAPS Password Age <= 30 days
func checkLAPSPasswordAge() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-018",
		Name:        "LAPS Password Age",
		Category:    "accounts",
		Description: "LAPS password age <= 30 days (CIS 18.2.x)",
		Severity:    "medium",
		Expected:    "PasswordAgeDays <= 30",
		Techniques:  []string{"T1078.003"},
		Tactics:     []string{"credential-access"},
	}

	// Try Windows LAPS first
	match, val, err := CheckRegistryDWORDMaximum(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS`, "PasswordAgeDays", 30)
	if err == nil {
		result.Passed = match
		result.Actual = fmt.Sprintf("PasswordAgeDays = %d (Windows LAPS)", val)
		result.Details = result.Actual
		return result
	}

	// Try Legacy LAPS
	match, val, err = CheckRegistryDWORDMaximum(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft Services\AdmPwd`, "PasswordAgeDays", 30)
	if err == nil {
		result.Passed = match
		result.Actual = fmt.Sprintf("PasswordAgeDays = %d (Legacy LAPS)", val)
		result.Details = result.Actual
		return result
	}

	result.Passed = false
	result.Actual = "LAPS password age not configured"
	result.Details = result.Actual
	return result
}

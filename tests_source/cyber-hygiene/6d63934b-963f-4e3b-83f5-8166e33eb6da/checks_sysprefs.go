//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"strings"
)

// RunSysPrefsChecks performs System Preferences & Security checks (8 controls)
func RunSysPrefsChecks() ValidatorResult {
	checks := []CheckResult{
		checkAutoUpdateEnabled(),
		checkAutoInstallMacOSUpdates(),
		checkAutoInstallSecurityUpdates(),
		checkBluetoothDiscoverable(),
		checkScreenSaverIdleTime(),
		checkFileVaultEnabled(),
		checkApplicationFirewall(),
		checkFirewallStealthMode(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "System Preferences & Security",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// CH-CM1-001: Auto Update enabled
func checkAutoUpdateEnabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-001",
		Name:        "Automatic Update Check Enabled",
		Category:    "system-preferences",
		Description: "Verify that automatic software update checking is enabled (CIS 1.1)",
		Expected:    "AutomaticCheckEnabled = 1",
		Severity:    "high",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	val, err := ReadDefaultsDomain("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Error reading preference: %v", err)
		result.Details = "Could not read AutomaticCheckEnabled (may indicate updates are not configured)"
		return result
	}

	result.Actual = fmt.Sprintf("AutomaticCheckEnabled = %s", val)
	result.Passed = val == "1"
	if result.Passed {
		result.Details = "Automatic update checking is enabled"
	} else {
		result.Details = fmt.Sprintf("Automatic update checking is disabled (value: %s, expected: 1)", val)
	}
	return result
}

// CH-CM1-002: Auto Install macOS Updates
func checkAutoInstallMacOSUpdates() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-002",
		Name:        "Automatic macOS Update Installation",
		Category:    "system-preferences",
		Description: "Verify that macOS updates are automatically installed (CIS 1.2)",
		Expected:    "AutomaticallyInstallMacOSUpdates = 1",
		Severity:    "high",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	val, err := ReadDefaultsDomain("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates")
	if err != nil {
		// Try alternative key name used on some macOS versions
		val, err = ReadDefaultsDomain("/Library/Preferences/com.apple.commerce", "AutoUpdate")
		if err != nil {
			result.Passed = false
			result.Actual = "Preference not set"
			result.Details = "AutomaticallyInstallMacOSUpdates is not configured"
			return result
		}
	}

	result.Actual = fmt.Sprintf("AutomaticallyInstallMacOSUpdates = %s", val)
	result.Passed = val == "1"
	if result.Passed {
		result.Details = "Automatic macOS update installation is enabled"
	} else {
		result.Details = fmt.Sprintf("Automatic macOS update installation is disabled (value: %s)", val)
	}
	return result
}

// CH-CM1-003: Auto Install Security Updates (Critical + ConfigData)
func checkAutoInstallSecurityUpdates() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-003",
		Name:        "Automatic Security Update Installation",
		Category:    "system-preferences",
		Description: "Verify that critical and configuration data updates are installed automatically (CIS 1.3)",
		Expected:    "ConfigDataInstall = 1 AND CriticalUpdateInstall = 1",
		Severity:    "critical",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	configData, errConfig := ReadDefaultsDomain("/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall")
	criticalUpdate, errCritical := ReadDefaultsDomain("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall")

	if errConfig != nil && errCritical != nil {
		result.Passed = false
		result.Actual = "Security update preferences not configured"
		result.Details = "Neither ConfigDataInstall nor CriticalUpdateInstall are set"
		return result
	}

	configOK := configData == "1"
	criticalOK := criticalUpdate == "1"

	result.Actual = fmt.Sprintf("ConfigDataInstall=%s, CriticalUpdateInstall=%s", configData, criticalUpdate)
	result.Passed = configOK && criticalOK

	if result.Passed {
		result.Details = "Both configuration data and critical security updates install automatically"
	} else {
		issues := []string{}
		if !configOK {
			issues = append(issues, "ConfigDataInstall is not enabled")
		}
		if !criticalOK {
			issues = append(issues, "CriticalUpdateInstall is not enabled")
		}
		result.Details = strings.Join(issues, "; ")
	}
	return result
}

// CH-CM1-004: Bluetooth discoverable mode off
func checkBluetoothDiscoverable() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-004",
		Name:        "Bluetooth Discoverability Disabled",
		Category:    "system-preferences",
		Description: "Verify that Bluetooth is not set to discoverable mode when not in setup (CIS 2.1.1)",
		Expected:    "Bluetooth not discoverable or disabled",
		Severity:    "medium",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	// Check if Bluetooth is powered on
	powerState, err := ReadDefaultsDomain("/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState")
	if err != nil {
		// Bluetooth preference may not exist if no Bluetooth hardware (e.g., server)
		result.Passed = true
		result.Actual = "Bluetooth preference not found (likely no Bluetooth hardware)"
		result.Details = "No Bluetooth controller detected - not applicable"
		return result
	}

	if powerState == "0" {
		result.Passed = true
		result.Actual = "Bluetooth is powered off"
		result.Details = "Bluetooth controller is disabled"
		return result
	}

	// Bluetooth is on; check discoverability via system_profiler
	output, err := RunBash("system_profiler SPBluetoothDataType 2>/dev/null | grep -i 'Discoverable'")
	if err != nil || output == "" {
		// If we can't determine discoverability, check via defaults
		result.Passed = true
		result.Actual = fmt.Sprintf("Bluetooth powered on (ControllerPowerState=%s), discoverability status could not be determined", powerState)
		result.Details = "Bluetooth is on but discoverability status is indeterminate (macOS typically disables discoverable mode after setup)"
		return result
	}

	isDiscoverable := strings.Contains(strings.ToLower(output), "yes") || strings.Contains(strings.ToLower(output), "on")
	result.Actual = fmt.Sprintf("Bluetooth on, discoverable: %s", output)
	result.Passed = !isDiscoverable
	if result.Passed {
		result.Details = "Bluetooth is powered on but not discoverable"
	} else {
		result.Details = "Bluetooth is in discoverable mode - should be disabled when not in setup"
	}
	return result
}

// CH-CM1-005: Screen saver idle time <= 20 minutes (1200 seconds)
func checkScreenSaverIdleTime() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-005",
		Name:        "Screen Saver Idle Time <= 20 Minutes",
		Category:    "system-preferences",
		Description: "Verify screen saver activates within 20 minutes of inactivity (CIS 2.3.1)",
		Expected:    "idleTime <= 1200 seconds",
		Severity:    "medium",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	// Try currentHost read first (user-level preference)
	val, err := ReadDefaultsByHost("com.apple.screensaver", "idleTime")
	if err != nil {
		// Try global preference
		val, err = ReadDefaultsDomain("com.apple.screensaver", "idleTime")
		if err != nil {
			result.Passed = false
			result.Actual = "Screen saver idle time not configured"
			result.Details = "idleTime preference not found - screen saver may not be configured"
			return result
		}
	}

	// Parse the idle time value
	var idleSeconds int
	_, parseErr := fmt.Sscanf(val, "%d", &idleSeconds)
	if parseErr != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("idleTime = %s (could not parse)", val)
		result.Details = "Could not parse screen saver idle time value"
		return result
	}

	result.Actual = fmt.Sprintf("idleTime = %d seconds (%d minutes)", idleSeconds, idleSeconds/60)
	result.Passed = idleSeconds > 0 && idleSeconds <= 1200
	if result.Passed {
		result.Details = fmt.Sprintf("Screen saver activates after %d minutes (within 20-minute threshold)", idleSeconds/60)
	} else if idleSeconds == 0 {
		result.Details = "Screen saver is disabled (idleTime = 0)"
	} else {
		result.Details = fmt.Sprintf("Screen saver idle time is %d minutes (exceeds 20-minute maximum)", idleSeconds/60)
	}
	return result
}

// CH-CM1-006: FileVault enabled
func checkFileVaultEnabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-006",
		Name:        "FileVault Full Disk Encryption Enabled",
		Category:    "system-preferences",
		Description: "Verify FileVault 2 full disk encryption is enabled (CIS 2.5.1)",
		Expected:    "FileVault is On",
		Severity:    "critical",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	output, err := RunCommand("fdesetup", "status")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("fdesetup error: %v", err)
		result.Details = "Could not determine FileVault status"
		return result
	}

	result.Actual = output
	result.Passed = strings.Contains(output, "FileVault is On")
	if result.Passed {
		result.Details = "FileVault full disk encryption is active"
	} else if strings.Contains(output, "FileVault is Off") {
		result.Details = "FileVault is disabled - disk is not encrypted"
	} else {
		result.Details = fmt.Sprintf("Unexpected FileVault status: %s", output)
	}
	return result
}

// CH-CM1-007: Application Firewall enabled
func checkApplicationFirewall() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-007",
		Name:        "Application Firewall Enabled",
		Category:    "system-preferences",
		Description: "Verify the macOS Application Firewall (ALF) is enabled (CIS 3.1)",
		Expected:    "globalstate >= 1",
		Severity:    "high",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	val, err := ReadDefaultsDomain("/Library/Preferences/com.apple.alf", "globalstate")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Error reading ALF preference: %v", err)
		result.Details = "Could not read Application Firewall state"
		return result
	}

	var state int
	_, parseErr := fmt.Sscanf(val, "%d", &state)
	if parseErr != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("globalstate = %s (could not parse)", val)
		result.Details = "Could not parse firewall state value"
		return result
	}

	result.Actual = fmt.Sprintf("globalstate = %d", state)
	result.Passed = state >= 1
	if state == 0 {
		result.Details = "Application Firewall is disabled"
	} else if state == 1 {
		result.Details = "Application Firewall is enabled (standard mode)"
	} else if state == 2 {
		result.Details = "Application Firewall is enabled (block all incoming connections)"
	} else {
		result.Details = fmt.Sprintf("Application Firewall state: %d (enabled)", state)
	}
	return result
}

// CH-CM1-008: Firewall Stealth Mode enabled
func checkFirewallStealthMode() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-008",
		Name:        "Firewall Stealth Mode Enabled",
		Category:    "system-preferences",
		Description: "Verify the macOS firewall stealth mode is enabled (CIS 3.2)",
		Expected:    "Stealth mode enabled",
		Severity:    "high",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	output, err := RunCommandCombined("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("socketfilterfw error: %v", err)
		result.Details = "Could not determine firewall stealth mode status"
		return result
	}

	result.Actual = output
	result.Passed = strings.Contains(strings.ToLower(output), "enabled")
	if result.Passed {
		result.Details = "Firewall stealth mode is enabled - system does not respond to probing requests"
	} else {
		result.Details = "Firewall stealth mode is disabled - system responds to ICMP and other probing requests"
	}
	return result
}

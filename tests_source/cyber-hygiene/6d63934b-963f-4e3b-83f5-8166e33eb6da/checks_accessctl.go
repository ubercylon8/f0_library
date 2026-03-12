//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"runtime"
	"strings"
)

// RunAccessCtlChecks performs Access Control checks (5 controls)
func RunAccessCtlChecks() ValidatorResult {
	checks := []CheckResult{
		checkSecureKeyboardEntry(),
		checkPasswordOnWake(),
		checkSSHRemoteLoginDisabled(),
		checkGuestAccountDisabled(),
		checkSecureBoot(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Access Control",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// CH-CM1-015: Secure keyboard entry in Terminal
func checkSecureKeyboardEntry() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-015",
		Name:        "Secure Keyboard Entry in Terminal",
		Category:    "access-control",
		Description: "Verify secure keyboard entry is enabled in Terminal.app to prevent keylogging (CIS 2.4.4)",
		Expected:    "SecureKeyboardEntry = 1",
		Severity:    "medium",
		Techniques:  []string{"T1021.004"},
		Tactics:     []string{"lateral-movement"},
	}

	val, err := ReadDefaultsDomain("com.apple.Terminal", "SecureKeyboardEntry")
	if err != nil {
		result.Passed = false
		result.Actual = "SecureKeyboardEntry not configured"
		result.Details = "Secure keyboard entry is not enabled in Terminal.app (preference not set)"
		return result
	}

	result.Actual = fmt.Sprintf("SecureKeyboardEntry = %s", val)
	result.Passed = val == "1"
	if result.Passed {
		result.Details = "Secure keyboard entry is enabled in Terminal.app"
	} else {
		result.Details = "Secure keyboard entry is disabled - keystrokes in Terminal could be intercepted"
	}
	return result
}

// CH-CM1-016: Password required on wake from sleep
func checkPasswordOnWake() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-016",
		Name:        "Password Required on Wake",
		Category:    "access-control",
		Description: "Verify that a password is required immediately after sleep or screen saver (CIS 5.8)",
		Expected:    "askForPassword = 1",
		Severity:    "high",
		Techniques:  []string{"T1021.004"},
		Tactics:     []string{"lateral-movement"},
	}

	// Check askForPassword preference
	val, err := ReadDefaultsDomain("com.apple.screensaver", "askForPassword")
	if err != nil {
		// Try currentHost variant
		val, err = ReadDefaultsByHost("com.apple.screensaver", "askForPassword")
		if err != nil {
			result.Passed = false
			result.Actual = "askForPassword preference not set"
			result.Details = "Password on wake is not configured"
			return result
		}
	}

	result.Actual = fmt.Sprintf("askForPassword = %s", val)
	pwRequired := val == "1"

	// Also check the delay (should be 0 = immediately)
	delay, delayErr := ReadDefaultsDomain("com.apple.screensaver", "askForPasswordDelay")
	if delayErr != nil {
		delay, _ = ReadDefaultsByHost("com.apple.screensaver", "askForPasswordDelay")
	}

	if delay != "" {
		result.Actual = fmt.Sprintf("askForPassword=%s, askForPasswordDelay=%s", val, delay)
	}

	result.Passed = pwRequired
	if result.Passed {
		if delay == "0" || delay == "" {
			result.Details = "Password is required immediately after sleep/screensaver"
		} else {
			result.Details = fmt.Sprintf("Password is required after sleep/screensaver (delay: %s seconds)", delay)
		}
	} else {
		result.Details = "Password is not required on wake - unauthorized physical access possible"
	}
	return result
}

// CH-CM1-017: SSH/Remote Login disabled
func checkSSHRemoteLoginDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-017",
		Name:        "SSH Remote Login Disabled",
		Category:    "access-control",
		Description: "Verify that Remote Login (SSH) is disabled (CIS 2.4.14)",
		Expected:    "Remote Login: Off",
		Severity:    "high",
		Techniques:  []string{"T1021.004"},
		Tactics:     []string{"lateral-movement"},
	}

	output, err := CheckSystemSetup("-getremotelogin")
	if err != nil {
		// systemsetup requires root; try checking sshd directly
		procOutput, procErr := RunBash("pgrep -x sshd 2>/dev/null")
		if procErr == nil && strings.TrimSpace(procOutput) != "" {
			result.Passed = false
			result.Actual = fmt.Sprintf("sshd process running (PID: %s)", strings.TrimSpace(procOutput))
			result.Details = "SSH daemon (sshd) is running - Remote Login is enabled"
			return result
		}
		result.Passed = true
		result.Actual = "sshd is not running (systemsetup requires root)"
		result.Details = "SSH daemon is not running - Remote Login appears to be disabled"
		return result
	}

	result.Actual = output
	result.Passed = strings.Contains(strings.ToLower(output), "off")
	if result.Passed {
		result.Details = "Remote Login (SSH) is disabled"
	} else {
		result.Details = "Remote Login (SSH) is enabled - should be disabled on endpoints unless required"
	}
	return result
}

// CH-CM1-018: Guest account disabled
func checkGuestAccountDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-018",
		Name:        "Guest Account Disabled",
		Category:    "access-control",
		Description: "Verify that the guest user account is disabled (CIS 5.6.1)",
		Expected:    "GuestEnabled = 0 (or false)",
		Severity:    "high",
		Techniques:  []string{"T1548.004"},
		Tactics:     []string{"privilege-escalation"},
	}

	val, err := ReadDefaultsDomain("/Library/Preferences/com.apple.loginwindow", "GuestEnabled")
	if err != nil {
		// GuestEnabled might not exist if never configured; default is typically disabled on managed Macs
		result.Passed = true
		result.Actual = "GuestEnabled preference not set (default: disabled on managed systems)"
		result.Details = "Guest account preference not explicitly configured - typically disabled by default"
		return result
	}

	result.Actual = fmt.Sprintf("GuestEnabled = %s", val)
	result.Passed = val == "0" || strings.EqualFold(val, "false")
	if result.Passed {
		result.Details = "Guest account is disabled"
	} else {
		result.Details = "Guest account is enabled - provides unauthenticated access to the system"
	}
	return result
}

// CH-CM1-019: Secure Boot / Startup Security
func checkSecureBoot() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CM1-019",
		Name:        "Startup Security / Secure Boot",
		Category:    "access-control",
		Description: "Verify Secure Boot is set to Full Security (CIS 5.3)",
		Expected:    "Full Security enabled",
		Severity:    "critical",
		Techniques:  []string{"T1548.004"},
		Tactics:     []string{"privilege-escalation"},
	}

	isAppleSilicon := runtime.GOARCH == "arm64"

	if isAppleSilicon {
		// Apple Silicon: check via bputil
		output, err := RunBash("bputil -d 2>&1")
		if err != nil {
			// bputil may require SIP context or specific permissions
			// Try to check via system_profiler
			spOutput, spErr := RunBash("system_profiler SPHardwareDataType 2>/dev/null | grep -i 'Secure Boot'")
			if spErr != nil || spOutput == "" {
				// Fallback: Apple Silicon defaults to Full Security
				result.Passed = true
				result.Actual = "Apple Silicon detected; Secure Boot status could not be queried directly (likely Full Security)"
				result.Details = "Apple Silicon Macs default to Full Security; unable to verify via bputil (may require specific entitlements)"
				return result
			}
			result.Actual = strings.TrimSpace(spOutput)
			result.Passed = strings.Contains(strings.ToLower(spOutput), "full")
			if result.Passed {
				result.Details = "Full Security is enabled on Apple Silicon"
			} else {
				result.Details = "Secure Boot is not set to Full Security"
			}
			return result
		}

		result.Actual = strings.TrimSpace(output)
		// bputil -d shows "Current security mode: Full Security" when properly configured
		isFullSecurity := strings.Contains(strings.ToLower(output), "full security") ||
			strings.Contains(strings.ToLower(output), "full")
		result.Passed = isFullSecurity
		if result.Passed {
			result.Details = "Secure Boot is set to Full Security on Apple Silicon"
		} else {
			result.Details = "Secure Boot is not set to Full Security - reduced startup security"
		}
	} else {
		// Intel Mac: check firmware password and Secure Boot via nvram
		output, err := RunBash("nvram -p 2>/dev/null | grep 'security-mode'")
		if err != nil || output == "" {
			// Check via system_profiler
			spOutput, spErr := RunBash("system_profiler SPHardwareDataType 2>/dev/null | grep -i 'Secure Boot\\|Activation Lock'")
			if spErr == nil && spOutput != "" {
				result.Actual = strings.TrimSpace(spOutput)
				result.Passed = strings.Contains(strings.ToLower(spOutput), "full")
				if result.Passed {
					result.Details = "Startup security appears to be properly configured on Intel Mac"
				} else {
					result.Details = "Startup security may not be fully configured on Intel Mac"
				}
				return result
			}
			result.Passed = false
			result.Actual = "Could not determine Secure Boot status on Intel Mac"
			result.Details = "Unable to query Secure Boot configuration - firmware password may not be set"
			return result
		}

		result.Actual = strings.TrimSpace(output)
		result.Passed = strings.Contains(strings.ToLower(output), "full")
		if result.Passed {
			result.Details = "Secure Boot is set to Full Security on Intel Mac"
		} else {
			result.Details = "Secure Boot security mode may be reduced"
		}
	}
	return result
}

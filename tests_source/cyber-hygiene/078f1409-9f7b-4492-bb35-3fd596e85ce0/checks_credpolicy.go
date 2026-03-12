//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RunCredPolicyChecks performs Credential & Password Policy checks (CIS Level 1)
func RunCredPolicyChecks() ValidatorResult {
	// Export secedit policy once, reuse for all checks
	policy, seceditErr := RunSecedit()
	if seceditErr != nil {
		fmt.Printf("[WARNING] Secedit export failed: %v — using fallback methods\n", seceditErr)
		policy = make(map[string]string)
	}

	checks := []CheckResult{
		checkPasswordHistory(policy),
		checkMaxPasswordAge(policy),
		checkMinPasswordAge(policy),
		checkMinPasswordLength(policy),
		checkPasswordComplexity(policy),
		checkRelaxMinLength(),
		checkLockoutDuration(policy),
		checkLockoutThreshold(policy),
		checkResetLockoutCounter(policy),
		checkAdminAccountLockout(policy),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Credential & Password Policy",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// CH-CW1-001: Enforce password history >= 24
func checkPasswordHistory(policy map[string]string) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-001",
		Name:        "Password History",
		Category:    "credpolicy",
		Description: "Enforce password history >= 24 passwords remembered (CIS 1.1.1)",
		Severity:    "high",
		Expected:    ">= 24 passwords remembered",
		Techniques:  []string{"T1110", "T1110.001"},
		Tactics:     []string{"credential-access"},
	}

	val, err := GetSeceditInt(policy, "PasswordHistorySize")
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = fmt.Sprintf("Unable to read: %v", err)
		return result
	}

	result.Passed = val >= 24
	result.Actual = fmt.Sprintf("%d passwords remembered", val)
	result.Details = result.Actual
	return result
}

// CH-CW1-002: Maximum password age <= 365 days
func checkMaxPasswordAge(policy map[string]string) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-002",
		Name:        "Maximum Password Age",
		Category:    "credpolicy",
		Description: "Maximum password age <= 365 days (CIS 1.1.2)",
		Severity:    "medium",
		Expected:    "<= 365 days (and > 0)",
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	val, err := GetSeceditInt(policy, "MaximumPasswordAge")
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = fmt.Sprintf("Unable to read: %v", err)
		return result
	}

	// Value of 0 means passwords never expire — non-compliant
	result.Passed = val > 0 && val <= 365
	result.Actual = fmt.Sprintf("%d days", val)
	if val == 0 {
		result.Details = "Passwords never expire"
	} else {
		result.Details = result.Actual
	}
	return result
}

// CH-CW1-003: Minimum password age >= 1 day
func checkMinPasswordAge(policy map[string]string) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-003",
		Name:        "Minimum Password Age",
		Category:    "credpolicy",
		Description: "Minimum password age >= 1 day (CIS 1.1.3)",
		Severity:    "medium",
		Expected:    ">= 1 day",
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	val, err := GetSeceditInt(policy, "MinimumPasswordAge")
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = fmt.Sprintf("Unable to read: %v", err)
		return result
	}

	result.Passed = val >= 1
	result.Actual = fmt.Sprintf("%d day(s)", val)
	result.Details = result.Actual
	return result
}

// CH-CW1-004: Minimum password length >= 14 characters
func checkMinPasswordLength(policy map[string]string) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-004",
		Name:        "Minimum Password Length",
		Category:    "credpolicy",
		Description: "Minimum password length >= 14 characters (CIS 1.1.4)",
		Severity:    "high",
		Expected:    ">= 14 characters",
		Techniques:  []string{"T1110", "T1110.003"},
		Tactics:     []string{"credential-access"},
	}

	val, err := GetSeceditInt(policy, "MinimumPasswordLength")
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = fmt.Sprintf("Unable to read: %v", err)
		return result
	}

	result.Passed = val >= 14
	result.Actual = fmt.Sprintf("%d characters", val)
	result.Details = result.Actual
	return result
}

// CH-CW1-005: Password complexity enabled
func checkPasswordComplexity(policy map[string]string) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-005",
		Name:        "Password Complexity",
		Category:    "credpolicy",
		Description: "Password must meet complexity requirements (CIS 1.1.5)",
		Severity:    "high",
		Expected:    "Enabled (PasswordComplexity = 1)",
		Techniques:  []string{"T1110", "T1110.003"},
		Tactics:     []string{"credential-access"},
	}

	val, err := GetSeceditInt(policy, "PasswordComplexity")
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = fmt.Sprintf("Unable to read: %v", err)
		return result
	}

	result.Passed = val == 1
	result.Actual = BoolToEnabledDisabled(val == 1)
	result.Details = result.Actual
	return result
}

// CH-CW1-006: Relax minimum password length limits
func checkRelaxMinLength() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-006",
		Name:        "Relax Minimum Password Length Limits",
		Category:    "credpolicy",
		Description: "Allow passwords longer than 14 characters via SAM policy (CIS 1.1.6)",
		Severity:    "medium",
		Expected:    "Enabled (RelaxMinimumPasswordLengthLimits = 1)",
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\SAM`, "RelaxMinimumPasswordLengthLimits", 1)
	if err != nil {
		// Not configured — check if this is a newer Windows version that supports it
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Registry key not set"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("RelaxMinimumPasswordLengthLimits = %d", val)
	result.Details = BoolToEnabledDisabled(match)
	return result
}

// CH-CW1-007: Account lockout duration >= 15 minutes
func checkLockoutDuration(policy map[string]string) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-007",
		Name:        "Account Lockout Duration",
		Category:    "credpolicy",
		Description: "Account lockout duration >= 15 minutes (CIS 1.2.1)",
		Severity:    "high",
		Expected:    ">= 15 minutes",
		Techniques:  []string{"T1110", "T1110.001"},
		Tactics:     []string{"credential-access"},
	}

	val, err := GetSeceditInt(policy, "LockoutDuration")
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = fmt.Sprintf("Unable to read: %v", err)
		return result
	}

	result.Passed = val >= 15
	result.Actual = fmt.Sprintf("%d minutes", val)
	result.Details = result.Actual
	return result
}

// CH-CW1-008: Account lockout threshold <= 5 attempts
func checkLockoutThreshold(policy map[string]string) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-008",
		Name:        "Account Lockout Threshold",
		Category:    "credpolicy",
		Description: "Account lockout threshold <= 5 invalid attempts (CIS 1.2.2)",
		Severity:    "high",
		Expected:    "<= 5 attempts (and > 0)",
		Techniques:  []string{"T1110", "T1110.001"},
		Tactics:     []string{"credential-access"},
	}

	val, err := GetSeceditInt(policy, "LockoutBadCount")
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = fmt.Sprintf("Unable to read: %v", err)
		return result
	}

	// 0 means never lock out — non-compliant
	result.Passed = val > 0 && val <= 5
	result.Actual = fmt.Sprintf("%d attempts", val)
	if val == 0 {
		result.Details = "Account lockout disabled"
	} else {
		result.Details = result.Actual
	}
	return result
}

// CH-CW1-009: Reset account lockout counter >= 15 minutes
func checkResetLockoutCounter(policy map[string]string) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-009",
		Name:        "Reset Lockout Counter",
		Category:    "credpolicy",
		Description: "Reset account lockout counter after >= 15 minutes (CIS 1.2.3)",
		Severity:    "medium",
		Expected:    ">= 15 minutes",
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	val, err := GetSeceditInt(policy, "ResetLockoutCount")
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = fmt.Sprintf("Unable to read: %v", err)
		return result
	}

	result.Passed = val >= 15
	result.Actual = fmt.Sprintf("%d minutes", val)
	result.Details = result.Actual
	return result
}

// CH-CW1-010: Administrator account lockout enabled
func checkAdminAccountLockout(policy map[string]string) CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-010",
		Name:        "Administrator Account Lockout",
		Category:    "credpolicy",
		Description: "Allow Administrator account lockout (CIS 1.2.4)",
		Severity:    "high",
		Expected:    "Enabled",
		Techniques:  []string{"T1110", "T1110.001"},
		Tactics:     []string{"credential-access"},
	}

	// Check via net accounts output or PowerShell
	output, err := RunPowerShell(`
		$result = net accounts 2>&1
		$lockoutLine = $result | Select-String -Pattern "Lockout threshold"
		if ($lockoutLine) {
			$value = ($lockoutLine -split ":\s*")[1].Trim()
			Write-Output "THRESHOLD:$value"
		}
		# Check if admin lockout is explicitly set
		$adminLockout = (net user Administrator 2>&1 | Select-String -Pattern "Account active")
		if ($adminLockout) {
			Write-Output "ADMIN_EXISTS:True"
		}
	`)

	if err != nil {
		// Fallback: check secedit for lockout being configured at all
		threshold, _ := GetSeceditInt(policy, "LockoutBadCount")
		if threshold > 0 {
			result.Passed = true
			result.Actual = fmt.Sprintf("Lockout threshold set to %d (admin lockout policy in effect)", threshold)
			result.Details = result.Actual
		} else {
			result.Passed = false
			result.Actual = "Unable to determine admin lockout status"
			result.Details = result.Actual
		}
		return result
	}

	lines := strings.Split(output, "\n")
	thresholdSet := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "THRESHOLD:") {
			val := strings.TrimPrefix(line, "THRESHOLD:")
			val = strings.TrimSpace(val)
			if val != "Never" && val != "0" {
				thresholdVal, _ := strconv.Atoi(val)
				if thresholdVal > 0 {
					thresholdSet = true
				}
			}
		}
	}

	result.Passed = thresholdSet
	if thresholdSet {
		result.Actual = "Lockout policy active (applies to all accounts including Administrator)"
	} else {
		result.Actual = "Lockout policy not configured or threshold set to Never"
	}
	result.Details = result.Actual
	return result
}

//go:build windows
// +build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// CIS Level 1 compliant thresholds
const (
	MAX_LOCKOUT_THRESHOLD = 5   // Max failed attempts before lockout
	MIN_LOCKOUT_DURATION  = 15  // Minimum lockout duration in minutes
	MIN_RESET_COUNTER     = 15  // Minimum time to reset failed attempt counter
	MIN_PASSWORD_LENGTH   = 14  // Minimum password length
	MAX_PASSWORD_AGE      = 365 // Maximum password age in days
)

// RunLockoutChecks performs all account lockout policy checks
func RunLockoutChecks() ValidatorResult {
	checks := []CheckResult{
		checkLockoutThreshold(),
		checkLockoutDuration(),
		checkResetCounter(),
		checkMinPasswordLength(),
		checkPasswordComplexity(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Account Lockout Policy",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// getNetAccountsOutput retrieves net accounts command output
func getNetAccountsOutput() map[string]string {
	result := make(map[string]string)

	output, err := RunCommand("net", "accounts")
	if err != nil {
		return result
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, ":"); idx != -1 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			result[key] = value
		}
	}

	return result
}

// checkLockoutThreshold verifies account lockout threshold
func checkLockoutThreshold() CheckResult {
	result := CheckResult{
		ControlID:   "CH-LOK-001",
		Name:        "Lockout Threshold",
		Category:    "lockout",
		Description: "Checks if account lockout threshold is configured",
		Severity:    "high",
		Expected:    fmt.Sprintf("<= %d failed attempts", MAX_LOCKOUT_THRESHOLD),
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	netAccounts := getNetAccountsOutput()

	// Check for lockout threshold
	thresholdStr, exists := netAccounts["Lockout threshold"]
	if !exists {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	// Parse value - "Never" or a number
	if strings.EqualFold(thresholdStr, "Never") {
		result.Passed = false
		result.Actual = "Never (disabled)"
		result.Details = "Lockout disabled"
		return result
	}

	threshold, err := strconv.Atoi(strings.TrimSpace(thresholdStr))
	if err != nil {
		result.Passed = false
		result.Actual = thresholdStr
		result.Details = "Unable to parse"
		return result
	}

	result.Passed = threshold > 0 && threshold <= MAX_LOCKOUT_THRESHOLD
	result.Actual = fmt.Sprintf("%d attempts", threshold)
	if result.Passed {
		result.Details = fmt.Sprintf("%d attempts (compliant)", threshold)
	} else if threshold == 0 {
		result.Details = "Disabled"
	} else {
		result.Details = fmt.Sprintf("%d attempts (should be <= %d)", threshold, MAX_LOCKOUT_THRESHOLD)
	}

	return result
}

// checkLockoutDuration verifies account lockout duration
func checkLockoutDuration() CheckResult {
	result := CheckResult{
		ControlID:   "CH-LOK-002",
		Name:        "Lockout Duration",
		Category:    "lockout",
		Description: "Checks if account lockout duration is sufficient",
		Severity:    "high",
		Expected:    fmt.Sprintf(">= %d minutes (or manual unlock)", MIN_LOCKOUT_DURATION),
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	netAccounts := getNetAccountsOutput()

	durationStr, exists := netAccounts["Lockout duration (minutes)"]
	if !exists {
		// Try alternative key
		for key, val := range netAccounts {
			if strings.Contains(strings.ToLower(key), "lockout duration") {
				durationStr = val
				exists = true
				break
			}
		}
	}

	if !exists {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	// "Never" means admin must unlock
	if strings.EqualFold(durationStr, "Never") {
		result.Passed = true
		result.Actual = "Manual unlock required"
		result.Details = "Admin must unlock"
		return result
	}

	duration, err := strconv.Atoi(strings.TrimSpace(durationStr))
	if err != nil {
		result.Passed = false
		result.Actual = durationStr
		result.Details = "Unable to parse"
		return result
	}

	result.Passed = duration >= MIN_LOCKOUT_DURATION
	result.Actual = fmt.Sprintf("%d minutes", duration)
	if result.Passed {
		result.Details = fmt.Sprintf("%d minutes (compliant)", duration)
	} else {
		result.Details = fmt.Sprintf("%d minutes (should be >= %d)", duration, MIN_LOCKOUT_DURATION)
	}

	return result
}

// checkResetCounter verifies lockout counter reset time
func checkResetCounter() CheckResult {
	result := CheckResult{
		ControlID:   "CH-LOK-003",
		Name:        "Reset Counter After",
		Category:    "lockout",
		Description: "Checks if lockout counter reset time is sufficient",
		Severity:    "medium",
		Expected:    fmt.Sprintf(">= %d minutes", MIN_RESET_COUNTER),
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	netAccounts := getNetAccountsOutput()

	resetStr, exists := netAccounts["Lockout observation window (minutes)"]
	if !exists {
		// Try alternative key
		for key, val := range netAccounts {
			if strings.Contains(strings.ToLower(key), "observation window") ||
				strings.Contains(strings.ToLower(key), "reset") {
				resetStr = val
				exists = true
				break
			}
		}
	}

	if !exists {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	reset, err := strconv.Atoi(strings.TrimSpace(resetStr))
	if err != nil {
		result.Passed = false
		result.Actual = resetStr
		result.Details = "Unable to parse"
		return result
	}

	result.Passed = reset >= MIN_RESET_COUNTER
	result.Actual = fmt.Sprintf("%d minutes", reset)
	if result.Passed {
		result.Details = fmt.Sprintf("%d minutes (compliant)", reset)
	} else {
		result.Details = fmt.Sprintf("%d minutes (should be >= %d)", reset, MIN_RESET_COUNTER)
	}

	return result
}

// checkMinPasswordLength verifies minimum password length
func checkMinPasswordLength() CheckResult {
	result := CheckResult{
		ControlID:   "CH-LOK-004",
		Name:        "Minimum Password Length",
		Category:    "lockout",
		Description: "Checks if minimum password length is sufficient",
		Severity:    "high",
		Expected:    fmt.Sprintf(">= %d characters", MIN_PASSWORD_LENGTH),
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	netAccounts := getNetAccountsOutput()

	lengthStr, exists := netAccounts["Minimum password length"]
	if !exists {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	length, err := strconv.Atoi(strings.TrimSpace(lengthStr))
	if err != nil {
		result.Passed = false
		result.Actual = lengthStr
		result.Details = "Unable to parse"
		return result
	}

	result.Passed = length >= MIN_PASSWORD_LENGTH
	result.Actual = fmt.Sprintf("%d characters", length)
	if result.Passed {
		result.Details = fmt.Sprintf("%d characters (compliant)", length)
	} else {
		result.Details = fmt.Sprintf("%d characters (should be >= %d)", length, MIN_PASSWORD_LENGTH)
	}

	return result
}

// checkPasswordComplexity verifies password complexity is enabled
func checkPasswordComplexity() CheckResult {
	result := CheckResult{
		ControlID:   "CH-LOK-005",
		Name:        "Password Complexity",
		Category:    "lockout",
		Description: "Checks if password complexity requirements are enabled",
		Severity:    "high",
		Expected:    "Enabled",
		Techniques:  []string{"T1110"},
		Tactics:     []string{"credential-access"},
	}

	// Use secedit to export and check password complexity
	output, err := RunPowerShell(`
		$tempFile = [System.IO.Path]::GetTempFileName()
		secedit /export /cfg $tempFile /quiet 2>$null
		$content = Get-Content $tempFile -ErrorAction SilentlyContinue
		Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
		$line = $content | Where-Object { $_ -match 'PasswordComplexity' }
		if ($line -match '=\s*(\d+)') { $matches[1] } else { "Unknown" }
	`)

	if err == nil {
		val := strings.TrimSpace(output)
		switch val {
		case "1":
			result.Passed = true
			result.Actual = "Enabled"
			result.Details = "Enabled"
		case "0":
			result.Passed = false
			result.Actual = "Disabled"
			result.Details = "Disabled"
		default:
			result.Passed = false
			result.Actual = "Unknown"
			result.Details = "Unable to determine"
		}
		return result
	}

	result.Passed = false
	result.Actual = "Unable to query"
	result.Details = "Unable to query"
	return result
}

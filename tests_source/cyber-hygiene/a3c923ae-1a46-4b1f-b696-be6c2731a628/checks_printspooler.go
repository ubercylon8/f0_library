//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Print Spooler registry paths
const (
	PrinterPolicyPath     = `SOFTWARE\Policies\Microsoft\Windows NT\Printers`
	PointAndPrintPath     = `SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint`
	PrintSpoolerServicePath = `SYSTEM\CurrentControlSet\Services\Spooler`
)

// Service start types
const (
	SERVICE_START_DISABLED = 4
	SERVICE_START_MANUAL   = 3
	SERVICE_START_AUTO     = 2
)

// RunPrintSpoolerChecks performs all Print Spooler hardening checks
func RunPrintSpoolerChecks() ValidatorResult {
	checks := []CheckResult{
		checkPrintSpoolerStatus(),
		checkPointAndPrintRestrictions(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:         "Print Spooler Hardening (PrintNightmare)",
		Checks:       checks,
		PassedCount:  passed,
		FailedCount:  failed,
		TotalChecks:  len(checks),
		IsCompliant:  failed == 0,
	}
}

// checkPrintSpoolerStatus verifies Print Spooler service status
func checkPrintSpoolerStatus() CheckResult {
	result := CheckResult{
		ControlID:   "CH-PRT-001",
		Name:        "Print Spooler Service",
		Category:    "printspooler",
		Description: "Checks if Print Spooler service is disabled (if not needed)",
		Severity:    "high",
		Expected:    "Disabled (or Point and Print properly restricted)",
		Techniques:  []string{"T1569.002"},
		Tactics:     []string{"execution"},
	}

	// Check service status
	exists, running, startType, err := CheckServiceStatus("Spooler")
	if err != nil {
		result.Passed = false
		result.Actual = "Unable to query"
		result.Details = "Unable to query"
		return result
	}

	if !exists {
		result.Passed = true
		result.Actual = "Service not installed"
		result.Details = "Not installed"
		return result
	}

	// If disabled, that's the most secure option
	if startType == SERVICE_START_DISABLED {
		result.Passed = true
		result.Actual = "Disabled"
		result.Details = "Disabled"
		return result
	}

	// If running, check if Point and Print is restricted (will be checked separately)
	if running {
		result.Passed = false
		result.Actual = "Running"
		result.Details = "Running (check Point and Print restrictions)"
		return result
	}

	// Manual or Auto but not running
	switch startType {
	case SERVICE_START_MANUAL:
		result.Passed = false
		result.Actual = "Manual (not running)"
		result.Details = "Manual start"
	case SERVICE_START_AUTO:
		result.Passed = false
		result.Actual = "Auto (not running)"
		result.Details = "Auto start"
	default:
		result.Passed = false
		result.Actual = fmt.Sprintf("Start type: %d", startType)
		result.Details = "Check configuration"
	}

	return result
}

// checkPointAndPrintRestrictions verifies Point and Print restrictions (CVE-2021-34527)
func checkPointAndPrintRestrictions() CheckResult {
	result := CheckResult{
		ControlID:   "CH-PRT-002",
		Name:        "Point and Print Restrictions",
		Category:    "printspooler",
		Description: "Checks PrintNightmare mitigations (CVE-2021-34527)",
		Severity:    "critical",
		Expected:    "RestrictDriverInstallationToAdministrators = 1 and NoWarningNoElevationOnInstall = 0",
		Techniques:  []string{"T1547.012"},
		Tactics:     []string{"persistence", "privilege-escalation"},
	}

	// Check via PowerShell for comprehensive check
	output, err := RunPowerShell(`
		$results = @()

		# Check RestrictDriverInstallationToAdministrators
		$restrict = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'RestrictDriverInstallationToAdministrators' -ErrorAction SilentlyContinue
		if ($restrict.RestrictDriverInstallationToAdministrators -eq 1) {
			$results += "RestrictDrivers:PASS"
		} else {
			$results += "RestrictDrivers:FAIL"
		}

		# Check NoWarningNoElevationOnInstall (should be 0 or not exist)
		$noWarning = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'NoWarningNoElevationOnInstall' -ErrorAction SilentlyContinue
		if ($noWarning -eq $null -or $noWarning.NoWarningNoElevationOnInstall -eq 0) {
			$results += "NoWarning:PASS"
		} else {
			$results += "NoWarning:FAIL"
		}

		# Check UpdatePromptSettings (should be 0 or not exist)
		$updatePrompt = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'UpdatePromptSettings' -ErrorAction SilentlyContinue
		if ($updatePrompt -eq $null -or $updatePrompt.UpdatePromptSettings -eq 0) {
			$results += "UpdatePrompt:PASS"
		} else {
			$results += "UpdatePrompt:FAIL"
		}

		$results -join ','
	`)

	if err == nil {
		output = strings.TrimSpace(output)
		parts := strings.Split(output, ",")

		passed := 0
		failed := 0
		issues := []string{}

		for _, part := range parts {
			if strings.HasSuffix(part, ":PASS") {
				passed++
			} else if strings.HasSuffix(part, ":FAIL") {
				failed++
				name := strings.TrimSuffix(part, ":FAIL")
				issues = append(issues, name)
			}
		}

		result.Passed = failed == 0
		if result.Passed {
			result.Actual = "All mitigations enabled"
			result.Details = fmt.Sprintf("%d/3 checks passed", passed)
		} else {
			result.Actual = fmt.Sprintf("Issues: %s", strings.Join(issues, ", "))
			result.Details = fmt.Sprintf("%d/3 checks passed", passed)
		}
		return result
	}

	// Fallback to registry checks
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, PointAndPrintPath, registry.QUERY_VALUE)
	if err != nil {
		result.Passed = false
		result.Actual = "Point and Print not configured"
		result.Details = "GPO not configured"
		return result
	}
	defer key.Close()

	// Check RestrictDriverInstallationToAdministrators
	restrictVal, _, err := key.GetIntegerValue("RestrictDriverInstallationToAdministrators")
	restrictOK := err == nil && restrictVal == 1

	// Check NoWarningNoElevationOnInstall (should be 0 or not exist)
	noWarningVal, _, err := key.GetIntegerValue("NoWarningNoElevationOnInstall")
	noWarningOK := err != nil || noWarningVal == 0

	result.Passed = restrictOK && noWarningOK

	if result.Passed {
		result.Actual = "Properly configured"
		result.Details = "PrintNightmare mitigations active"
	} else {
		issues := []string{}
		if !restrictOK {
			issues = append(issues, "RestrictDrivers not set")
		}
		if !noWarningOK {
			issues = append(issues, "NoWarning elevation enabled")
		}
		result.Actual = strings.Join(issues, ", ")
		result.Details = result.Actual
	}

	return result
}

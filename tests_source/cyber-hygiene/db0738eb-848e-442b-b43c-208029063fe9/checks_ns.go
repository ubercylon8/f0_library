//go:build ignore
// +build ignore

// checks_ns.go — ISACA ITGC Network Security control checks (NS-001/002/004).
// Phase-2 milestone: NS-004 WinRM service exposure check.

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func RunNSChecks() ValidatorResult {
	result := ValidatorResult{Name: "Network Security"}
	result.Checks = []CheckResult{
		checkWinRMExposureISACA(),
	}
	for _, c := range result.Checks {
		result.TotalChecks++
		if c.Passed {
			result.PassedCount++
		} else {
			result.FailedCount++
		}
	}
	result.IsCompliant = result.FailedCount == 0
	return result
}

// ITGC-NS-004 — WinRM/Remote Management Exposure.
// Compliant if WinRM is disabled OR WinRM is HTTPS-only with restricted trusted hosts.
func checkWinRMExposureISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-NS-004",
		Name:           "WinRM/Remote Management Exposure",
		Category:       "network-security",
		Description:    "WinRM disabled, or HTTPS-only with restricted trusted hosts.",
		Severity:       "medium",
		Techniques:     []string{"T1021.006"},
		Tactics:        []string{"lateral-movement"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.02 Manage Network and Connectivity Security",
		CisV8Mapping:   "CIS 4.8 Uninstall or Disable Unnecessary Services",
		ManualResidual: "Auditor verifies WinRM trusted host list is approved and minimal.",
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$svc = Get-Service WinRM -ErrorAction SilentlyContinue; `+
			`if ($svc -and $svc.Status -eq 'Running') { `+
			`  $listeners = winrm enumerate winrm/config/listener 2>$null; `+
			`  $trusted = (winrm get winrm/config/client 2>$null) -match 'TrustedHosts'; `+
			`  Write-Output ('STATUS=Running'); `+
			`  Write-Output ('LISTENERS:' + $listeners); `+
			`  Write-Output ('TRUSTED:' + $trusted) `+
			`} elseif ($svc) { Write-Output ('STATUS=' + $svc.Status) } `+
			`else { Write-Output 'STATUS=NotInstalled' }`)
	out, err := cmd.Output()
	c.Expected = "WinRM stopped, or HTTPS-only with restricted TrustedHosts"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("WinRM query failed: %v", err)
		c.Details = "Could not query WinRM service state."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := strings.TrimSpace(string(out))
	c.Evidence = map[string]interface{}{"winrm_query_output": output}

	if strings.Contains(output, "STATUS=NotInstalled") || strings.Contains(output, "STATUS=Stopped") || strings.Contains(output, "STATUS=Disabled") {
		c.Passed = true
		c.Actual = "WinRM not running"
		c.Details = "WinRM service is not active — minimal lateral-movement exposure."
		return c
	}

	// WinRM running — check for HTTP listeners
	hasHTTPListener := strings.Contains(output, "Transport = HTTP") && !strings.Contains(output, "Transport = HTTPS")
	if hasHTTPListener {
		c.Passed = false
		c.Actual = "WinRM running with HTTP listener"
		c.Details = "WinRM active over HTTP — credentials transmitted unencrypted on the wire. Configure HTTPS-only listener."
		return c
	}
	c.Passed = true
	c.Actual = "WinRM running with HTTPS listener(s)"
	c.Details = "WinRM active with encrypted listener. Auditor verifies TrustedHosts list against approved baseline (manual residual)."
	return c
}

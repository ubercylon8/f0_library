//go:build ignore
// +build ignore

// checks_ns.go — ISACA ITGC Network Security control checks (NS-001/002/004).
// NS-003 LAPS deployment is in the AD Identity companion bundle.

package main

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func RunNSChecks() ValidatorResult {
	result := ValidatorResult{Name: "Network Security"}
	result.Checks = []CheckResult{
		checkOpenPortInventoryISACA(), // NS-001
		checkRDPSecurityISACA(),       // NS-002
		checkWinRMExposureISACA(),     // NS-004
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

// ITGC-NS-001 — Open Port Inventory (Get-NetTCPConnection -State Listen).
// Captures listening ports + owning processes for auditor review against approved-services baseline.
func checkOpenPortInventoryISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-NS-001",
		Name:           "Open Port Inventory",
		Category:       "network-security",
		Description:    "Enumerate listening TCP/UDP ports + owning processes for auditor baseline comparison.",
		Severity:       "high",
		Techniques:     []string{"T1046"},
		Tactics:        []string{"discovery"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.02 Manage Network and Connectivity Security",
		CisV8Mapping:   "CIS 4.4 Implement and Manage Firewall on Servers",
		ManualResidual: "Auditor compares evidence.listening_ports against approved-services baseline; flags unexpected listeners.",
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | `+
			`ForEach-Object { `+
			`  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; `+
			`  [PSCustomObject]@{ `+
			`    LocalAddress = $_.LocalAddress; `+
			`    LocalPort    = $_.LocalPort; `+
			`    Process      = if ($proc) { $proc.ProcessName } else { 'unknown' } `+
			`  } `+
			`} | Sort-Object LocalPort; `+
			`$tcp | ConvertTo-Json -Compress -Depth 3`)
	out, err := cmd.Output()
	c.Expected = "Listening port inventory enumerated"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("Get-NetTCPConnection failed: %v", err)
		c.Details = "Could not enumerate listening ports."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := strings.TrimSpace(string(out))
	listenerCount := strings.Count(output, `"LocalPort"`)

	c.Passed = listenerCount > 0
	c.Actual = fmt.Sprintf("%d TCP listeners enumerated", listenerCount)
	if c.Passed {
		c.Details = fmt.Sprintf("Successfully captured %d listening TCP endpoints. Auditor reviews evidence.listening_ports against approved-services baseline.", listenerCount)
	} else {
		c.Details = "No listening TCP endpoints — query parse failure or unusual configuration. Review evidence."
	}
	c.Evidence = map[string]interface{}{
		"listener_count":  listenerCount,
		"listening_ports": output,
	}
	return c
}

// ITGC-NS-002 — RDP security: NLA on, encryption High (>=3), or RDP disabled altogether.
func checkRDPSecurityISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-NS-002",
		Name:           "RDP Security Configuration",
		Category:       "network-security",
		Description:    "RDP either disabled, or NLA enforced with MinEncryptionLevel ≥ 3.",
		Severity:       "critical",
		Techniques:     []string{"T1021.001"},
		Tactics:        []string{"lateral-movement"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.02 Manage Network and Connectivity Security",
		CisV8Mapping:   "CIS 4.3 Configure Data Access Control Lists",
		ManualResidual: "Auditor verifies RDP-enabled hosts are restricted to approved admin groups.",
	}

	denyMatched, denyVal, denyErr := CheckRegistryDWORD(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server`,
		"fDenyTSConnections", 1)

	c.Expected = "RDP disabled OR (NLA=1 AND MinEncryptionLevel>=3)"
	c.Evidence = map[string]interface{}{}

	if denyErr == nil && denyMatched {
		c.Passed = true
		c.Actual = "RDP disabled (fDenyTSConnections=1)"
		c.Details = "RDP listening service disabled — no remote desktop attack surface."
		c.Evidence["rdp_enabled"] = false
		c.Evidence["fDenyTSConnections"] = denyVal
		return c
	}
	c.Evidence["rdp_enabled"] = true
	c.Evidence["fDenyTSConnections"] = denyVal

	nlaMatched, nlaVal, _ := CheckRegistryDWORD(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
		"UserAuthentication", 1)

	encMatched, encVal, _ := CheckRegistryDWORDMinimum(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
		"MinEncryptionLevel", 3)

	c.Evidence["nla_enforced"] = nlaMatched
	c.Evidence["nla_value"] = nlaVal
	c.Evidence["min_encryption_level"] = encVal
	c.Evidence["min_encryption_compliant"] = encMatched

	c.Passed = nlaMatched && encMatched
	if c.Passed {
		c.Actual = fmt.Sprintf("RDP enabled with NLA=1, MinEncryption=%d (High+)", encVal)
		c.Details = "RDP active with strong-auth + High encryption. Auditor verifies group restrictions (manual residual)."
	} else {
		fails := []string{}
		if !nlaMatched {
			fails = append(fails, fmt.Sprintf("NLA=%d (need 1)", nlaVal))
		}
		if !encMatched {
			fails = append(fails, fmt.Sprintf("MinEncryptionLevel=%d (need >=3)", encVal))
		}
		c.Actual = strings.Join(fails, "; ")
		c.Details = "RDP security gaps: " + c.Actual
	}
	return c
}

// ITGC-NS-004 — WinRM/Remote Management Exposure.
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

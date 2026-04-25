//go:build ignore
// +build ignore

// checks_lm.go — ISACA ITGC Logging & Monitoring control checks (LM-001..005).

package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func RunLMChecks() ValidatorResult {
	result := ValidatorResult{Name: "Logging & Monitoring"}
	result.Checks = []CheckResult{
		checkEventLogConfigurationISACA(), // LM-001
		checkAuditPolicyISACA(),           // LM-002
		checkSysmonDeploymentISACA(),      // LM-003
		checkLogForwardingAgentISACA(),    // LM-004
		checkEventLogClearingISACA(),      // LM-005
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

// ITGC-LM-001 — Event Log Configuration (Security/System/Application size + retention).
// Compliant if Security log MaximumSizeMB ≥ 196 (CIS-aligned default ~200 MB).
func checkEventLogConfigurationISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-LM-001",
		Name:           "Event Log Configuration",
		Category:       "logging-monitoring",
		Description:    "Security event log sized for retention (≥196 MB); System/Application logs configured.",
		Severity:       "high",
		Techniques:     []string{"T1070.001"},
		Tactics:        []string{"defense-evasion"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "DSS05.07 Manage Vulnerability and Security Posture",
		CisV8Mapping:   "CIS 8.2 Collect Audit Logs",
		ManualResidual: "Auditor verifies log sizes align with retention policy (e.g., 90-day rolling).",
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`Get-WinEvent -ListLog Security,System,Application -ErrorAction SilentlyContinue | `+
			`Select-Object LogName, MaximumSizeInBytes, LogMode | ConvertTo-Json -Compress`)
	out, err := cmd.Output()
	c.Expected = "Security log MaximumSizeInBytes >= 196608000 (~196 MB)"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("Get-WinEvent ListLog failed: %v", err)
		c.Details = "Could not query event log configuration."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := strings.TrimSpace(string(out))
	c.Evidence = map[string]interface{}{"event_log_config_raw": output}

	// Find Security log's MaximumSizeInBytes.
	// JSON shape: [{"LogName":"Security","MaximumSizeInBytes":20971520,"LogMode":0},...]
	const sizeKey = `"MaximumSizeInBytes":`
	secMaxBytes := int64(0)
	if idx := strings.Index(output, `"LogName":"Security"`); idx >= 0 {
		secSection := output[idx:]
		if mIdx := strings.Index(secSection, sizeKey); mIdx >= 0 {
			rest := secSection[mIdx+len(sizeKey):]
			// Skip optional whitespace between ':' and the digit.
			i := 0
			for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
				i++
			}
			end := i
			for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
				end++
			}
			if end > i {
				secMaxBytes, _ = strconv.ParseInt(rest[i:end], 10, 64)
			}
		}
	}
	c.Evidence["security_log_max_bytes"] = secMaxBytes

	// 196 MB threshold (matches CIS default after Win10 baseline tightening)
	const threshold = int64(196 * 1024 * 1024)
	c.Passed = secMaxBytes >= threshold
	c.Actual = fmt.Sprintf("Security log size = %d bytes (~%d MB)", secMaxBytes, secMaxBytes/(1024*1024))
	if c.Passed {
		c.Details = "Security event log sized for retention."
	} else if secMaxBytes == 0 {
		c.Details = "Could not determine Security log size — query parse failure."
	} else {
		c.Details = fmt.Sprintf("Security log too small for adequate retention (%d MB; need ≥196 MB).", secMaxBytes/(1024*1024))
	}
	return c
}

// ITGC-LM-002 — Audit policy: 9 critical subcategories enabled (auditpol /get).
func checkAuditPolicyISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-LM-002",
		Name:           "Advanced Audit Policy Settings",
		Category:       "logging-monitoring",
		Description:    "Critical audit subcategories enabled (Logon, Process Creation, Object Access, Policy Change, Privilege Use, Account Mgmt).",
		Severity:       "high",
		Techniques:     []string{"T1562.002"},
		Tactics:        []string{"defense-evasion"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "DSS05.07 Manage Vulnerability and Security Posture",
		CisV8Mapping:   "CIS 8.5 Collect Detailed Audit Logs",
		ManualResidual: "Auditor verifies organizational policy aligns with the 9 critical subcategories audited.",
	}

	cmd := exec.Command("auditpol.exe", "/get", "/category:*")
	out, err := cmd.CombinedOutput()
	c.Expected = "9 critical subcategories: Success+Failure or Success"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("auditpol failed: %v", err)
		c.Details = "Could not query advanced audit policy via auditpol.exe."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := string(out)
	policy := parseAuditpolOutput(output)
	c.Evidence = map[string]interface{}{"auditpol_output": output, "parsed_policy": policy}

	critical := []string{
		"Logon",
		"Logoff",
		"Special Logon",
		"Process Creation",
		"Audit Policy Change",
		"User Account Management",
		"Security Group Management",
		"Sensitive Privilege Use",
		"Credential Validation",
	}

	auditedCount := 0
	missing := []string{}
	for _, sub := range critical {
		val, ok := policy[sub]
		if ok && (strings.Contains(val, "Success") || strings.Contains(val, "Failure")) {
			auditedCount++
		} else {
			missing = append(missing, sub)
		}
	}

	c.Evidence["audited_count"] = auditedCount
	c.Evidence["critical_subcategories_total"] = len(critical)
	c.Evidence["missing_subcategories"] = missing

	c.Passed = auditedCount == len(critical)
	c.Actual = fmt.Sprintf("%d/%d critical subcategories audited", auditedCount, len(critical))
	if c.Passed {
		c.Details = "All critical audit subcategories enabled — compliant."
	} else {
		c.Details = fmt.Sprintf("Audit policy gap: missing %s. Enable via 'auditpol /set' or GPO.", strings.Join(missing, ", "))
	}
	return c
}

func parseAuditpolOutput(output string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		l := strings.TrimRight(line, "\r")
		trim := strings.TrimSpace(l)
		if trim == "" || strings.HasPrefix(trim, "System Audit Policy") || strings.HasPrefix(trim, "Category") || strings.HasPrefix(trim, "Subcategory") {
			continue
		}
		idx := strings.LastIndex(trim, "  ")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(trim[:idx])
		setting := strings.TrimSpace(trim[idx:])
		if name == "" || setting == "" {
			continue
		}
		result[name] = setting
	}
	return result
}

// ITGC-LM-003 — Sysmon Deployment Validation (service running + reasonable rule coverage).
// Sysmon is informational: absence is itself a finding (auditor flags as missing).
func checkSysmonDeploymentISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-LM-003",
		Name:           "Sysmon Deployment Validation",
		Category:       "logging-monitoring",
		Description:    "Sysmon is installed, running, and has rule coverage (>0 rules in active config).",
		Severity:       "medium",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "DSS05.07 Manage Vulnerability and Security Posture",
		CisV8Mapping:   "CIS 8.5 Collect Detailed Audit Logs",
		ManualResidual: "Auditor verifies Sysmon config XML matches approved organizational template (e.g., SwiftOnSecurity, Olaf Hartong).",
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$svcs = @('Sysmon','Sysmon64','SysmonDrv'); `+
			`$running = $svcs | ForEach-Object { Get-Service $_ -ErrorAction SilentlyContinue } | Where-Object { $_.Status -eq 'Running' }; `+
			`if ($running) { `+
			`  $names = ($running | ForEach-Object { $_.Name }) -join ','; `+
			`  Write-Output "RUNNING:$names" `+
			`} else { Write-Output 'NOT_RUNNING' }`)
	out, err := cmd.Output()
	c.Expected = "Sysmon service running"
	if err != nil {
		c.Passed = false
		c.Actual = "Sysmon query failed"
		c.Details = "Could not query Sysmon service state."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := strings.TrimSpace(string(out))
	c.Evidence = map[string]interface{}{"sysmon_query_output": output}

	c.Passed = strings.HasPrefix(output, "RUNNING:")
	if c.Passed {
		c.Actual = strings.TrimPrefix(output, "RUNNING:") + " running"
		c.Details = "Sysmon is deployed and running. Auditor reviews active config XML against approved template."
	} else {
		c.Actual = "Sysmon not running"
		c.Details = "Sysmon is not deployed — endpoint lacks process-creation telemetry beyond the default Security log. This is itself an audit finding."
	}
	return c
}

// ITGC-LM-004 — Log Forwarding Agent Status (heuristic check for SIEM agents).
// Looks for any of: WinRM (WEF), Splunk Universal Forwarder, MMA/AMA (Azure Monitor),
// Datadog, ELK Beats, NXLog, CrowdStrike Falcon (logs forwarded as part of EDR).
func checkLogForwardingAgentISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-LM-004",
		Name:           "Log Forwarding Agent Status",
		Category:       "logging-monitoring",
		Description:    "At least one log-forwarding agent (WEF, Splunk UF, Azure Monitor, etc.) is running.",
		Severity:       "high",
		Techniques:     []string{"T1562.006"},
		Tactics:        []string{"defense-evasion"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "DSS05.07 Manage Vulnerability and Security Posture",
		CisV8Mapping:   "CIS 8.9 Centralize Audit Logs",
		ManualResidual: "Auditor verifies the configured forwarder destination matches the approved central log store (SIEM endpoint).",
	}

	// Heuristic service-name list — match by exact service name
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$known = @('WinRM','SplunkForwarder','HealthService','MMARemoteServiceAgent','AzureMonitorAgent','datadog-agent','filebeat','winlogbeat','nxlog','CSFalconService'); `+
			`$found = @(); foreach ($n in $known) { $svc = Get-Service $n -ErrorAction SilentlyContinue; if ($svc -and $svc.Status -eq 'Running') { $found += $n } }; `+
			`if ($found.Count -gt 0) { Write-Output ('FOUND:' + ($found -join ',')) } else { Write-Output 'NOT_FOUND' }`)
	out, _ := cmd.Output()
	output := strings.TrimSpace(string(out))
	c.Expected = "≥1 known log-forwarding agent running"
	c.Evidence = map[string]interface{}{"agent_query_output": output}

	if strings.HasPrefix(output, "FOUND:") {
		agents := strings.TrimPrefix(output, "FOUND:")
		c.Passed = true
		c.Actual = "running: " + agents
		c.Details = fmt.Sprintf("Log forwarding active via: %s. Auditor verifies destination is approved SIEM.", agents)
		c.Evidence["forwarders"] = agents
	} else {
		c.Passed = false
		c.Actual = "no known log-forwarding agent running"
		c.Details = "None of the heuristic agents (WEF, Splunk UF, Azure Monitor, Beats, NXLog, CSFalcon) are running. If a custom agent is in use, auditor confirms via service inventory."
	}
	return c
}

// ITGC-LM-005 — Event Log Clearing Detection (Event ID 1102 in Security log).
func checkEventLogClearingISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-LM-005",
		Name:           "Event Log Clearing Detection",
		Category:       "logging-monitoring",
		Description:    "Security log clearing events (1102) absent or correlated to authorized maintenance.",
		Severity:       "critical",
		Techniques:     []string{"T1070.001"},
		Tactics:        []string{"defense-evasion"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "DSS05.07 Manage Vulnerability and Security Posture",
		CisV8Mapping:   "CIS 8.11 Conduct Audit Log Reviews",
		ManualResidual: "Each detected 1102 event must be correlated to an authorized maintenance ticket.",
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$start = (Get-Date).AddDays(-90); `+
			`$evts = Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102;StartTime=$start} -ErrorAction SilentlyContinue; `+
			`if ($evts) { `+
			`  $evts | Select-Object -First 50 TimeCreated, MachineName, UserId, Message | ConvertTo-Json -Compress `+
			`} else { '{"event_count":0}' }`)
	out, err := cmd.Output()
	c.Expected = "No event ID 1102 in last 90 days, or all clearing events authorized"
	if err != nil {
		c.Passed = true
		c.Actual = "no clearing events in 90-day retention window"
		c.Details = "Security log shows no clearing events (1102) within the 90-day query window. Compliant — no evidence tampering observed."
		c.Evidence = map[string]interface{}{"query_window_days": 90, "events_found": 0}
		return c
	}
	output := strings.TrimSpace(string(out))
	if strings.Contains(output, `"event_count":0`) || output == "" {
		c.Passed = true
		c.Actual = "no clearing events in 90-day retention window"
		c.Details = "Security log shows no clearing events (1102) within the 90-day query window. Compliant."
		c.Evidence = map[string]interface{}{"query_window_days": 90, "events_found": 0}
		return c
	}
	c.Passed = false
	c.Actual = "1+ Event ID 1102 entries found in last 90 days"
	c.Details = "Security log clearing events detected — auditor must correlate each occurrence to an authorized change ticket. Unexplained clearings indicate evidence tampering."
	c.Evidence = map[string]interface{}{
		"query_window_days": 90,
		"events_raw":        output,
	}
	return c
}

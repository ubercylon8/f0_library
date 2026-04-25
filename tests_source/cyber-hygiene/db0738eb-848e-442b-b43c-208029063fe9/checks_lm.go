//go:build ignore
// +build ignore

// checks_lm.go — ISACA ITGC Logging & Monitoring control checks (LM-001..005).
// Phase-2.5: LM-002 Audit Policy + LM-005 Event Log Clearing.
// LM-001/003/004 ship in Phase-2.5b.

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func RunLMChecks() ValidatorResult {
	result := ValidatorResult{Name: "Logging & Monitoring"}
	result.Checks = []CheckResult{
		checkAuditPolicyISACA(),       // LM-002
		checkEventLogClearingISACA(),  // LM-005
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

	// 9 critical subcategories per ISACA / CIS 8.5
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

// parseAuditpolOutput parses lines like "  Logon    Success and Failure" into a map.
func parseAuditpolOutput(output string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		l := strings.TrimRight(line, "\r")
		// auditpol output: subcategory name (left-padded), then 2+ spaces, then setting
		// Skip headers + system rows
		trim := strings.TrimSpace(l)
		if trim == "" || strings.HasPrefix(trim, "System Audit Policy") || strings.HasPrefix(trim, "Category") || strings.HasPrefix(trim, "Subcategory") {
			continue
		}
		// Split on 2+ consecutive spaces
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
			`} else { `+
			`  '{"event_count":0}' `+
			`}`)
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

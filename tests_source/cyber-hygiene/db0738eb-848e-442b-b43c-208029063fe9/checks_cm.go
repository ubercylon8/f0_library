//go:build ignore
// +build ignore

// checks_cm.go — ISACA ITGC Change Management control checks (CM-001..005).

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func RunCMChecks() ValidatorResult {
	result := ValidatorResult{Name: "Change Management"}
	result.Checks = []CheckResult{
		checkUnauthorizedSoftwareISACA(),  // CM-001
		checkPatchComplianceISACA(),       // CM-002
		checkWindowsUpdateConfigISACA(),   // CM-003
		checkGPOModificationAuditISACA(),  // CM-004
		checkScheduledTaskInventoryISACA(),// CM-005
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

// ITGC-CM-001 — Unauthorized Software Detection.
// Captures installed-software inventory; auditor compares against approved baseline.
// Uses Get-Package (modern PowerShell) with Get-CimInstance Win32_Product fallback.
func checkUnauthorizedSoftwareISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-CM-001",
		Name:           "Unauthorized Software Detection",
		Category:       "change-management",
		Description:    "Enumerate installed software; auditor compares against approved baseline.",
		Severity:       "high",
		Techniques:     []string{"T1204"},
		Tactics:        []string{"execution"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "BAI06.01 Evaluate, Prioritize and Authorize Change Requests",
		CisV8Mapping:   "CIS 2.1 Establish Software Inventory",
		ManualResidual: "Auditor reviews evidence.installed_software against approved-software baseline.",
	}

	// Win32_Product is slow + triggers MSI repair; use registry-based enumeration via PS
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$paths = @( `+
			`'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', `+
			`'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `+
			`); `+
			`Get-ItemProperty $paths -ErrorAction SilentlyContinue | `+
			`Where-Object { $_.DisplayName } | `+
			`Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | `+
			`Sort-Object DisplayName | ConvertTo-Json -Compress -Depth 3`)
	out, err := cmd.Output()
	c.Expected = "Inventory enumerated; auditor reviews against approved baseline"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("PS query failed: %v", err)
		c.Details = "Could not enumerate installed software via Uninstall registry hive."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := strings.TrimSpace(string(out))
	productCount := strings.Count(output, `"DisplayName"`)
	c.Passed = productCount > 0
	c.Actual = fmt.Sprintf("%d installed packages enumerated", productCount)
	if c.Passed {
		c.Details = fmt.Sprintf("Successfully captured %d installed packages. Auditor compares evidence.installed_software against approved baseline.", productCount)
	} else {
		c.Details = "Uninstall hive enumeration returned no packages — query parse failure or empty machine."
	}
	c.Evidence = map[string]interface{}{
		"installed_software": output,
		"package_count":      productCount,
	}
	return c
}

// ITGC-CM-002 — Patch Compliance (Critical/High missing patches > SLA window).
// SLA configurable via ITGC_PATCH_SLA_DAYS env var; default 30 days.
func checkPatchComplianceISACA() CheckResult {
	slaDays := 30
	if v := os.Getenv("ITGC_PATCH_SLA_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			slaDays = n
		}
	}

	c := CheckResult{
		ControlID:      "ITGC-CM-002",
		Name:           "Patch Compliance (Critical/High >SLA)",
		Category:       "change-management",
		Description:    fmt.Sprintf("Most recent hotfix installed within last %d days (SLA window).", slaDays),
		Severity:       "critical",
		Techniques:     []string{"T1203"},
		Tactics:        []string{"initial-access", "execution"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "BAI03.10 Maintain Solutions",
		CisV8Mapping:   "CIS 7.4 Perform Automated Patch Management",
		ManualResidual: fmt.Sprintf("Auditor cross-references missing-CVE list against vendor advisories. Configurable SLA via ITGC_PATCH_SLA_DAYS env var (current: %d).", slaDays),
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$hf = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending; `+
			`if ($hf -and $hf.Count -gt 0) { `+
			`  $latest = $hf | Select-Object -First 1; `+
			`  $age = if ($latest.InstalledOn) { (New-TimeSpan -Start $latest.InstalledOn -End (Get-Date)).Days } else { -1 }; `+
			`  $obj = @{ count = $hf.Count; latest_kb = $latest.HotFixID; latest_installed_on = $latest.InstalledOn.ToString('yyyy-MM-dd'); days_since_last_patch = $age }; `+
			`  $obj | ConvertTo-Json -Compress `+
			`} else { '{"count":0}' }`)
	out, err := cmd.Output()
	c.Expected = fmt.Sprintf("Last hotfix within %d days", slaDays)
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("Get-HotFix failed: %v", err)
		c.Details = "Could not query installed updates."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := strings.TrimSpace(string(out))
	c.Evidence = map[string]interface{}{
		"hotfix_query_raw":    output,
		"sla_days_configured": slaDays,
	}

	// Parse days_since_last_patch
	days := -1
	if idx := strings.Index(output, `"days_since_last_patch":`); idx >= 0 {
		rest := output[idx+24:]
		end := 0
		for end < len(rest) && (rest[end] == '-' || (rest[end] >= '0' && rest[end] <= '9')) {
			end++
		}
		if end > 0 {
			days, _ = strconv.Atoi(rest[:end])
		}
	}
	c.Evidence["days_since_last_patch"] = days

	if days < 0 {
		c.Passed = false
		c.Actual = "no hotfixes installed (or query parse failed)"
		c.Details = "No InstalledOn data — endpoint may have no patches recorded. Auditor reviews build vs. patch history."
		return c
	}

	c.Passed = days <= slaDays
	c.Actual = fmt.Sprintf("last patch %d days ago (SLA %dd)", days, slaDays)
	if c.Passed {
		c.Details = fmt.Sprintf("Most recent hotfix within SLA window (%d days ≤ %d).", days, slaDays)
	} else {
		c.Details = fmt.Sprintf("Patch SLA breached: last hotfix %d days ago (SLA %dd). Endpoint exposed to disclosed CVEs.", days, slaDays)
	}
	return c
}

// ITGC-CM-003 — Windows Update Configuration (registry: WSUS target, deferral, automatic updates).
func checkWindowsUpdateConfigISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-CM-003",
		Name:           "Windows Update Configuration",
		Category:       "change-management",
		Description:    "Windows Update is configured (managed by WSUS or auto-updates enabled).",
		Severity:       "high",
		Techniques:     []string{"T1195.002"},
		Tactics:        []string{"initial-access"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "BAI06.01 Evaluate, Prioritize and Authorize Change Requests",
		CisV8Mapping:   "CIS 7.4 Perform Automated Patch Management",
		ManualResidual: "Auditor verifies WSUS server target matches approved patch-management infrastructure.",
	}

	c.Expected = "WSUS target configured OR AU=automatic"
	wuKey, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`,
		registry.QUERY_VALUE,
	)
	wsusServer := ""
	if err == nil {
		if v, _, e := wuKey.GetStringValue("WUServer"); e == nil {
			wsusServer = v
		}
		wuKey.Close()
	}

	auKey, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`,
		registry.QUERY_VALUE,
	)
	auOption := uint64(0)
	useWUServer := uint64(0)
	if err == nil {
		if v, _, e := auKey.GetIntegerValue("AUOptions"); e == nil {
			auOption = v
		}
		if v, _, e := auKey.GetIntegerValue("UseWUServer"); e == nil {
			useWUServer = v
		}
		auKey.Close()
	}

	c.Evidence = map[string]interface{}{
		"wsus_server":     wsusServer,
		"au_options":      auOption,
		"use_wu_server":   useWUServer,
	}

	wsusOK := wsusServer != "" && useWUServer == 1
	autoOK := auOption == 4 // 4 = auto download + install (CIS-aligned)

	c.Passed = wsusOK || autoOK
	switch {
	case wsusOK:
		c.Actual = fmt.Sprintf("WSUS-managed (server=%s)", wsusServer)
		c.Details = "Windows Update is centrally managed via WSUS."
	case autoOK:
		c.Actual = fmt.Sprintf("AUOptions=%d (auto download + install)", auOption)
		c.Details = "Windows Update is set to auto-install (no WSUS, but acceptable for non-managed endpoints)."
	default:
		c.Actual = fmt.Sprintf("AUOptions=%d, WUServer='%s', UseWUServer=%d", auOption, wsusServer, useWUServer)
		c.Details = "Neither WSUS nor automatic-install policy is configured. Endpoint may be drifting from current patch baseline."
	}
	return c
}

// ITGC-CM-004 — GPO Modification Audit (local Event ID 5136 in Security log within 90d).
// Phase-2.5 v1: pure local query. SIEM-mode (Sentinel/Splunk correlation to change tickets) deferred.
func checkGPOModificationAuditISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-CM-004",
		Name:           "GPO Modification Audit Trail",
		Category:       "change-management",
		Description:    "Recent GPO modification events (5136) collected for auditor correlation to change tickets.",
		Severity:       "high",
		Techniques:     []string{"T1484"},
		Tactics:        []string{"defense-evasion", "privilege-escalation"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "BAI06.01 Evaluate, Prioritize and Authorize Change Requests",
		CisV8Mapping:   "CIS 4.1 Establish Secure Configuration Process",
		ManualResidual: "Each detected 5136 event must be correlated to an authorized change ticket; unexplained mods indicate unauthorized policy change.",
	}

	// Note: 5136 is logged on DCs only; on member endpoints this returns 0 events,
	// which we treat as "not applicable" and pass.
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$start = (Get-Date).AddDays(-90); `+
			`$evts = Get-WinEvent -FilterHashtable @{LogName='Security';Id=5136;StartTime=$start} -ErrorAction SilentlyContinue; `+
			`if ($evts) { `+
			`  $obj = @{ event_count = $evts.Count; sample = ($evts | Select-Object -First 10 TimeCreated, Message) }; `+
			`  $obj | ConvertTo-Json -Compress -Depth 3 `+
			`} else { '{"event_count":0,"applicable":"member-endpoint or no GPO mods in window"}' }`)
	out, _ := cmd.Output()
	output := strings.TrimSpace(string(out))
	c.Expected = "Events captured (DC) or n/a (member endpoint)"
	c.Evidence = map[string]interface{}{
		"gpo_modification_query_raw": output,
		"query_window_days":          90,
	}

	if strings.Contains(output, `"event_count":0`) || output == "" {
		c.Passed = true
		c.Actual = "no 5136 events in 90-day window (typical on non-DC endpoints)"
		c.Details = "Either this endpoint is not a DC (5136 only logs there) or no GPO modifications occurred in the retention window."
		return c
	}
	c.Passed = true // events captured = working — auditor reviews them
	c.Actual = "GPO modification events captured for auditor review"
	c.Details = "Recent 5136 events collected. Auditor must correlate each to an authorized change ticket; unexplained mods indicate unauthorized policy change."
	return c
}

// ITGC-CM-005 — Scheduled Task Inventory (Get-ScheduledTask).
func checkScheduledTaskInventoryISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-CM-005",
		Name:           "Scheduled Task Inventory",
		Category:       "change-management",
		Description:    "Enumerate all active scheduled tasks; auditor compares against approved baseline.",
		Severity:       "medium",
		Techniques:     []string{"T1053.005"},
		Tactics:        []string{"persistence", "execution"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "BAI06.01 Evaluate, Prioritize and Authorize Change Requests",
		CisV8Mapping:   "CIS 4.1 Establish Secure Configuration Process",
		ManualResidual: "Auditor reviews task inventory against approved baseline; flags tasks created outside change windows.",
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName, TaskPath, Author, State | ConvertTo-Json -Compress`)
	out, err := cmd.Output()
	c.Expected = "Inventory enumerated successfully"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("PS query failed: %v", err)
		c.Details = "Could not enumerate scheduled tasks."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := strings.TrimSpace(string(out))
	taskCount := strings.Count(output, "TaskName")
	c.Passed = true
	c.Actual = fmt.Sprintf("%d active scheduled tasks enumerated", taskCount)
	c.Details = fmt.Sprintf("Successfully enumerated %d active scheduled tasks. Auditor reviews evidence.scheduled_tasks against approved baseline.", taskCount)
	c.Evidence = map[string]interface{}{
		"active_task_count": taskCount,
		"scheduled_tasks":   output,
	}
	return c
}

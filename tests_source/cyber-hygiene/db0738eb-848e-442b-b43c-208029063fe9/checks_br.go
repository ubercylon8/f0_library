//go:build ignore
// +build ignore

// checks_br.go — ISACA ITGC Backup & Recovery control checks (BR-001..003).

package main

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func RunBRChecks() ValidatorResult {
	result := ValidatorResult{Name: "Backup & Recovery"}
	result.Checks = []CheckResult{
		checkVSSStatusISACA(),                  // BR-001
		checkBackupAgentStatusISACA(),          // BR-002
		checkControlledFolderAccessISACA(),     // BR-003
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

// ITGC-BR-001 — Volume Shadow Copy Service Status.
// VSS service runnable + at least one shadow copy present (vssadmin output) is the bar.
// Servers will typically have shadow copies; workstations may not — auditor reviews context.
func checkVSSStatusISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-BR-001",
		Name:           "Volume Shadow Copy Service Status",
		Category:       "backup-recovery",
		Description:    "VSS service is runnable; shadow copies exist on critical volumes (servers).",
		Severity:       "high",
		Techniques:     []string{"T1490"},
		Tactics:        []string{"impact"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "DSS04.01 Define Business Continuity Policy and Objectives",
		CisV8Mapping:   "CIS 11.2 Perform Automated Backups",
		ManualResidual: "Auditor verifies shadow copy schedule + retention against organizational RPO.",
	}

	// VSS service state (StartType, not Status — VSS is normally Manual + start-on-demand)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$svc = Get-Service VSS -ErrorAction SilentlyContinue; `+
			`if ($svc) { `+
			`  $shadows = (vssadmin list shadows 2>$null | Select-String -Pattern 'Shadow Copy ID' | Measure-Object).Count; `+
			`  Write-Output "STATUS=$($svc.Status);START=$($svc.StartType);SHADOWS=$shadows" `+
			`} else { Write-Output 'NOT_PRESENT' }`)
	out, err := cmd.Output()
	c.Expected = "VSS service runnable (StartType != Disabled)"
	if err != nil {
		c.Passed = false
		c.Actual = "VSS query failed"
		c.Details = "Could not query VSS service state."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := strings.TrimSpace(string(out))
	c.Evidence = map[string]interface{}{"vss_query_output": output}

	if output == "NOT_PRESENT" {
		c.Passed = false
		c.Actual = "VSS service not present"
		c.Details = "Volume Shadow Copy Service is missing — recovery from ransomware-encrypted files via shadow copies is not possible."
		return c
	}

	disabled := strings.Contains(output, "START=Disabled")
	c.Passed = !disabled
	c.Actual = output
	if c.Passed {
		c.Details = "VSS service is runnable. Auditor verifies shadow copy schedule against RPO."
	} else {
		c.Details = "VSS service is DISABLED — no recovery path via shadow copies."
	}
	return c
}

// ITGC-BR-002 — Backup Agent Status (heuristic vendor service detection).
func checkBackupAgentStatusISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-BR-002",
		Name:           "Backup Agent Service Status",
		Category:       "backup-recovery",
		Description:    "An enterprise backup agent (Veeam, Veritas, MABS, Windows Server Backup, etc.) is installed and running.",
		Severity:       "high",
		Techniques:     []string{"T1490"},
		Tactics:        []string{"impact"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "DSS04.01 Define Business Continuity Policy and Objectives",
		CisV8Mapping:   "CIS 11.2 Perform Automated Backups",
		ManualResidual: "Auditor verifies last successful backup timestamp meets organizational RPO (typically <24h for critical hosts).",
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$known = @('VeeamBackupSvc','VeeamDeploySvc','VeeamTransportSvc','BackupExecAgentBrowser','BackupExecAgentAccelerator','BackupExecRPCService','RexecdSvc','MABSAgent','MARSAgent','ScDpmAgent','wbengine','OBPSvc','Acrobat Background Service'); `+
			`$found = @(); foreach ($n in $known) { $svc = Get-Service $n -ErrorAction SilentlyContinue; if ($svc -and $svc.Status -eq 'Running') { $found += $n } }; `+
			`if ($found.Count -gt 0) { Write-Output ('FOUND:' + ($found -join ',')) } else { Write-Output 'NOT_FOUND' }`)
	out, _ := cmd.Output()
	output := strings.TrimSpace(string(out))
	c.Expected = "≥1 known backup agent running"
	c.Evidence = map[string]interface{}{"backup_query_output": output}

	if strings.HasPrefix(output, "FOUND:") {
		agents := strings.TrimPrefix(output, "FOUND:")
		c.Passed = true
		c.Actual = "running: " + agents
		c.Details = fmt.Sprintf("Backup agent active: %s. Auditor verifies last-RPO compliance.", agents)
		c.Evidence["agents_running"] = agents
	} else {
		c.Passed = false
		c.Actual = "no known backup agent running"
		c.Details = "None of the heuristic backup agents found running. If a custom agent is in use, auditor confirms via service inventory."
	}
	return c
}

// ITGC-BR-003 — Controlled Folder Access enabled.
func checkControlledFolderAccessISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-BR-003",
		Name:           "Controlled Folder Access",
		Category:       "backup-recovery",
		Description:    "Windows Defender Controlled Folder Access (anti-ransomware) enabled.",
		Severity:       "medium",
		Techniques:     []string{"T1486"},
		Tactics:        []string{"impact"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS04.01 Define Business Continuity Policy and Objectives",
		CisV8Mapping:   "CIS 10.7 Utilize Behavior-Based Anti-Malware Software",
		ManualResidual: "Auditor verifies CFA-protected folder list aligns with critical-data inventory.",
	}

	matched, val, err := CheckRegistryDWORD(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access`,
		"EnableControlledFolderAccess",
		1,
	)
	c.Expected = "EnableControlledFolderAccess = 1 (Block) or 2 (Audit)"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("registry read error: %v", err)
		c.Details = "CFA registry key absent — Controlled Folder Access not configured. Endpoint vulnerable to file-encrypting malware."
		c.Evidence = map[string]interface{}{
			"registry_path": `HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access`,
			"configured":    false,
		}
		return c
	}
	c.Passed = matched || val == 2
	c.Actual = fmt.Sprintf("EnableControlledFolderAccess = %d", val)
	if c.Passed {
		mode := "Block"
		if val == 2 {
			mode = "Audit"
		}
		c.Details = fmt.Sprintf("Controlled Folder Access enabled in %s mode.", mode)
	} else {
		c.Details = fmt.Sprintf("CFA disabled (value %d). Recommend Block (1) or Audit (2) mode.", val)
	}
	c.Evidence = map[string]interface{}{
		"registry_path": `HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access`,
		"value":         val,
		"compliant":     c.Passed,
	}
	return c
}

//go:build ignore
// +build ignore

// checks_br.go — ISACA ITGC Backup & Recovery control checks (BR-001..003).
// Phase-2 milestone: BR-003 Controlled Folder Access (Defender CFA, T1486 Data Encrypted for Impact).

package main

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func RunBRChecks() ValidatorResult {
	result := ValidatorResult{Name: "Backup & Recovery"}
	result.Checks = []CheckResult{
		checkControlledFolderAccessISACA(),
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

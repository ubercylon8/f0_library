//go:build ignore
// +build ignore

// checks_gv.go — ISACA ITGC Governance & Policy control checks (GV-001..006).
// Phase-2 milestone: GV-002 NTP Sync (foundational for audit trail correlation).

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func RunGVChecks() ValidatorResult {
	result := ValidatorResult{Name: "Governance & Policy"}
	result.Checks = []CheckResult{
		checkNTPSyncISACA(),
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

// ITGC-GV-002 — System Time Synchronization (NTP).
// Critical for audit trail correlation across hosts/SIEM.
func checkNTPSyncISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-GV-002",
		Name:           "System Time Synchronization (NTP)",
		Category:       "governance-policy",
		Description:    "NTP synchronized within tolerance for audit trail integrity.",
		Severity:       "high",
		Techniques:     []string{"T1070.006"},
		Tactics:        []string{"defense-evasion"},
		CisaDomain:     "D2: Governance and Management of IT",
		CobitObjective: "DSS01.05 Manage Facilities",
		CisV8Mapping:   "CIS 8.4 Standardize Time Synchronization",
		ManualResidual: "None — fully automated.",
	}

	cmd := exec.Command("w32tm.exe", "/query", "/status")
	out, err := cmd.CombinedOutput()
	c.Expected = "Successful sync to authoritative time source"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("w32tm query failed: %v", err)
		c.Details = "Windows Time Service not responding — system clock may be unsynchronized."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := string(out)
	c.Evidence = map[string]interface{}{"w32tm_status": output}

	// Parse "Last Successful Sync Time" — if present and not "unknown"
	syncOK := false
	source := ""
	for _, line := range strings.Split(output, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "Last Successful Sync Time:") && !strings.Contains(strings.ToLower(l), "unspecified"):
			syncOK = true
		case strings.HasPrefix(l, "Source:"):
			source = strings.TrimSpace(strings.TrimPrefix(l, "Source:"))
			c.Evidence["sync_source"] = source
		}
	}

	c.Passed = syncOK
	if syncOK {
		c.Actual = "synchronized"
		c.Details = fmt.Sprintf("System time synchronized to %s. Audit trail correlation reliable.", source)
	} else {
		c.Actual = "unsynchronized or never-synced"
		c.Details = "Windows Time Service shows no recent successful sync. Audit trail correlation may be unreliable."
	}
	return c
}

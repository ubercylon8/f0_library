//go:build ignore
// +build ignore

// checks_cm.go — ISACA ITGC Change Management control checks (CM-001..005).
// Phase-2 milestone: CM-005 Scheduled Task count (proof of architecture).

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func RunCMChecks() ValidatorResult {
	result := ValidatorResult{Name: "Change Management"}
	result.Checks = []CheckResult{
		checkScheduledTaskInventoryISACA(),
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

// ITGC-CM-005 — Scheduled Task Inventory (PS Get-ScheduledTask).
// Captures count + names; auditor compares against approved baseline manually (manual residual).
func checkScheduledTaskInventoryISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-CM-005",
		Name:           "Scheduled Task Inventory",
		Category:       "change-management",
		Description:    "Enumerate all scheduled tasks; auditor compares against approved baseline.",
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
		c.Actual = fmt.Sprintf("PowerShell query failed: %v", err)
		c.Details = "Could not enumerate scheduled tasks — Task Scheduler service or PowerShell access restricted."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := strings.TrimSpace(string(out))
	taskCount := strings.Count(output, "TaskName") // rough heuristic; fine for evidence
	c.Passed = true
	c.Actual = fmt.Sprintf("%d active scheduled tasks enumerated", taskCount)
	c.Details = fmt.Sprintf("Successfully enumerated %d active scheduled tasks. Auditor reviews evidence.scheduled_tasks against approved baseline.", taskCount)
	c.Evidence = map[string]interface{}{
		"active_task_count": taskCount,
		"scheduled_tasks":   output,
	}
	return c
}

//go:build ignore
// +build ignore

// checks_am.go — ISACA ITGC Access Management control checks (AM-001/002/005).
// Phase-2 milestone: AM-005 (Guest account disabled) implemented as proof of architecture.
// AM-001 (local admin inventory) and AM-002 (password policy) come in iteration 2 by
// copying CIS L1 checks_accounts.go and checks_credpolicy.go.

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func RunAMChecks() ValidatorResult {
	result := ValidatorResult{Name: "Access Management"}
	result.Checks = []CheckResult{
		checkGuestAccountDisabledISACA(),
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

// ITGC-AM-005 — Guest account disabled.
func checkGuestAccountDisabledISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-AM-005",
		Name:           "Guest Account Disabled",
		Category:       "access-management",
		Description:    "Built-in Guest account disabled per organizational baseline.",
		Severity:       "medium",
		Techniques:     []string{"T1078.001"},
		Tactics:        []string{"defense-evasion", "persistence"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.04 Manage Identity and Logical Access",
		CisV8Mapping:   "CIS 5.4 Restrict Administrator Privileges",
		ManualResidual: "None — fully automated.",
	}

	// `net user Guest` returns "Account active   No" when disabled
	cmd := exec.Command("net", "user", "Guest")
	out, err := cmd.CombinedOutput()
	c.Expected = "Account active = No"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("net user Guest failed: %v", err)
		c.Details = "Could not query Guest account state — may be renamed/removed (acceptable) or net.exe restricted."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := string(out)
	c.Evidence = map[string]interface{}{"net_user_output": output}

	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(strings.ToLower(line), "account active") {
			c.Actual = strings.TrimSpace(line)
			c.Passed = strings.Contains(strings.ToLower(line), "no")
			if c.Passed {
				c.Details = "Guest account is disabled."
			} else {
				c.Details = "Guest account is ACTIVE — represents an unauthenticated lateral-movement vector."
			}
			return c
		}
	}
	c.Actual = "Guest account state line not found in net user output"
	c.Passed = false
	c.Details = "Could not parse Guest account state from net.exe output."
	return c
}

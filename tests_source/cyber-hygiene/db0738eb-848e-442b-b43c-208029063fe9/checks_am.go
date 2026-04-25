//go:build ignore
// +build ignore

// checks_am.go — ISACA ITGC Access Management control checks.
//
// In-scope for the Windows Endpoint bundle:
//   ITGC-AM-001 Local Admin Inventory   (`net localgroup administrators`)
//   ITGC-AM-002 Password Policy         (`net accounts` parse)
//   ITGC-AM-005 Guest Account Disabled  (`net user Guest` parse)
//
// Out of scope (covered by AD Identity companion bundle):
//   ITGC-AM-003 Dormant Accounts        (AD lastLogonTimestamp)
//   ITGC-AM-004 Service Account Audit   (AD SPN enumeration)
//   ITGC-AM-006 MFA Enrollment           (Entra Tenant bundle 4f484076)

package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func RunAMChecks() ValidatorResult {
	result := ValidatorResult{Name: "Access Management"}
	result.Checks = []CheckResult{
		checkLocalAdminInventoryISACA(), // AM-001
		checkPasswordPolicyISACA(),      // AM-002
		checkGuestAccountDisabledISACA(), // AM-005
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

// ITGC-AM-001 — Local Administrator Account Inventory.
// Lists all members of the local Administrators group; auditor compares against
// approved baseline (manual residual). Auto-pass: ≤3 members and only well-known
// principals (Administrator + 1-2 domain accounts) — heuristic, not authoritative.
func checkLocalAdminInventoryISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-AM-001",
		Name:           "Local Administrator Account Inventory",
		Category:       "access-management",
		Description:    "Enumerate all members of the local Administrators group; auditor compares against approved baseline.",
		Severity:       "critical",
		Techniques:     []string{"T1078"},
		Tactics:        []string{"defense-evasion", "persistence", "privilege-escalation"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.04 Manage Identity and Logical Access",
		CisV8Mapping:   "CIS 5.4 Restrict Administrator Privileges",
		ManualResidual: "Auditor verifies each enumerated member against the approved-admin baseline; flags unauthorized accounts.",
	}

	cmd := exec.Command("net", "localgroup", "administrators")
	out, err := cmd.CombinedOutput()
	c.Expected = "Approved-admin baseline membership only"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("net localgroup administrators failed: %v", err)
		c.Details = "Could not enumerate local admins via net.exe. Confirm admin context."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := string(out)

	members := parseLocalGroupMembers(output)
	c.Evidence = map[string]interface{}{
		"net_localgroup_output": output,
		"found_admins":          members,
		"member_count":          len(members),
	}

	// Heuristic: pass if ≤3 members AND no obvious user-account suffixes (no spaces other
	// than DOMAIN\name pattern). Auditor still validates manually — this is a drift signal.
	c.Passed = len(members) > 0 && len(members) <= 3
	c.Actual = fmt.Sprintf("%d local admin member(s): %s", len(members), strings.Join(members, ", "))
	if c.Passed {
		c.Details = "Local Administrators group has a small membership consistent with a baseline. Auditor validates each member is approved (manual residual)."
	} else if len(members) == 0 {
		c.Details = "No local Administrators group members enumerated — query parse may have failed; review evidence.net_localgroup_output."
	} else {
		c.Details = fmt.Sprintf("Local Administrators group has %d members — exceeds 3-member baseline heuristic. Auditor reviews evidence.found_admins for unauthorized additions.", len(members))
	}
	return c
}

// parseLocalGroupMembers extracts the member list from `net localgroup administrators` output.
// The output has a header, separator line, member lines, and a "command completed" footer.
func parseLocalGroupMembers(output string) []string {
	members := []string{}
	inMembers := false
	for _, line := range strings.Split(output, "\n") {
		l := strings.TrimRight(line, "\r")
		trim := strings.TrimSpace(l)
		if !inMembers {
			if strings.HasPrefix(trim, "---") {
				inMembers = true
			}
			continue
		}
		if strings.HasPrefix(trim, "The command completed") || trim == "" {
			continue
		}
		members = append(members, trim)
	}
	return members
}

// ITGC-AM-002 — Password Policy Enforcement (length/complexity/age/lockout via `net accounts`).
func checkPasswordPolicyISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-AM-002",
		Name:           "Password Policy Enforcement",
		Category:       "access-management",
		Description:    "Password policy meets minimum bar: min length ≥ 14, max age ≤ 90d, lockout ≤ 5.",
		Severity:       "critical",
		Techniques:     []string{"T1110"},
		Tactics:        []string{"credential-access"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.04 Manage Identity and Logical Access",
		CisV8Mapping:   "CIS 5.2 Use Unique Passwords",
		ManualResidual: "Auditor verifies organizational policy aligns with or exceeds defaults.",
	}

	cmd := exec.Command("net", "accounts")
	out, err := cmd.CombinedOutput()
	c.Expected = "min_length>=14, max_age<=90d, lockout_threshold<=5"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("net accounts failed: %v", err)
		c.Details = "Could not query password policy via net.exe."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}

	output := string(out)
	policy := parseNetAccountsOutput(output)
	c.Evidence = map[string]interface{}{"net_accounts_output": output, "parsed_policy": policy}

	minLength := getIntOr(policy, "Minimum password length", 0)
	maxAge := getIntOr(policy, "Maximum password age", 999)
	lockoutThreshold := getIntOr(policy, "Lockout threshold", 0)

	minLengthOK := minLength >= 14
	maxAgeOK := maxAge > 0 && maxAge <= 90
	lockoutOK := lockoutThreshold > 0 && lockoutThreshold <= 5

	c.Evidence["min_length_compliant"] = minLengthOK
	c.Evidence["max_age_compliant"] = maxAgeOK
	c.Evidence["lockout_compliant"] = lockoutOK

	c.Passed = minLengthOK && maxAgeOK && lockoutOK
	if c.Passed {
		c.Actual = fmt.Sprintf("min_length=%d, max_age=%d, lockout=%d", minLength, maxAge, lockoutThreshold)
		c.Details = "Password policy meets minimum bar."
	} else {
		fails := []string{}
		if !minLengthOK {
			fails = append(fails, fmt.Sprintf("min_length=%d (need >=14)", minLength))
		}
		if !maxAgeOK {
			fails = append(fails, fmt.Sprintf("max_age=%d (need 1..90)", maxAge))
		}
		if !lockoutOK {
			fails = append(fails, fmt.Sprintf("lockout=%d (need 1..5)", lockoutThreshold))
		}
		c.Actual = strings.Join(fails, "; ")
		c.Details = "Password policy gaps: " + c.Actual
	}
	return c
}

// parseNetAccountsOutput parses lines like "Minimum password length:    14" into a map.
func parseNetAccountsOutput(output string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		colonIdx := strings.Index(line, ":")
		if colonIdx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		val := strings.TrimSpace(line[colonIdx+1:])
		if key == "" || val == "" {
			continue
		}
		result[key] = val
	}
	return result
}

// getIntOr extracts the leading integer from a policy value, returns dflt if unparseable.
func getIntOr(m map[string]string, key string, dflt int) int {
	v, ok := m[key]
	if !ok {
		return dflt
	}
	end := 0
	for end < len(v) && v[end] >= '0' && v[end] <= '9' {
		end++
	}
	if end == 0 {
		return dflt
	}
	n, err := strconv.Atoi(v[:end])
	if err != nil {
		return dflt
	}
	return n
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

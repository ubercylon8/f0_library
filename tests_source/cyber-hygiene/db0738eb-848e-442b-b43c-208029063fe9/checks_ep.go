//go:build ignore
// +build ignore

// checks_ep.go — ISACA ITGC Endpoint Protection control checks (EP-001..006).
//
// Phase-2 milestone: 2 controls implemented as proof of architecture.
//   - ITGC-EP-004 SMBv1 Disabled (registry)
//   - ITGC-EP-006 ASR (one rule — LSASS credential stealing) as a representative ASR check
//
// Remaining EP-001/002/003/005 will be filled in by copying CIS L1 / baseline
// validators (RunDefenderChecks, checkBitLocker, checkConstrainedLanguageMode,
// checks_firewall.go) and re-tagging with ITGC IDs in the next iteration.

package main

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func RunEPChecks() ValidatorResult {
	result := ValidatorResult{Name: "Endpoint Protection"}
	result.Checks = []CheckResult{
		checkSMBv1DisabledISACA(),
		checkASRLSASSCredStealingISACA(),
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

// ITGC-EP-004 — SMBv1 disabled (registry, T1210 Exploitation of Remote Services).
func checkSMBv1DisabledISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-EP-004",
		Name:           "SMBv1 Disabled",
		Category:       "endpoint-protection",
		Description:    "SMBv1 protocol disabled to prevent EternalBlue/WannaCry-class exploitation (CIS 4.8 / ITGC-EP-004).",
		Severity:       "critical",
		Techniques:     []string{"T1210"},
		Tactics:        []string{"lateral-movement"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.02 Manage Network and Connectivity Security",
		CisV8Mapping:   "CIS 4.8 Uninstall or Disable Unnecessary Services",
		ManualResidual: "None — fully automated.",
	}

	matched, val, err := CheckRegistryDWORD(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\mrxsmb10`,
		"Start",
		4, // 4 = Disabled
	)
	c.Expected = "Start = 4 (Disabled)"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("registry read error: %v", err)
		c.Details = "Could not read mrxsmb10 service Start value — service may be absent (acceptable on modern Windows where SMBv1 is uninstalled)."
		c.Evidence = map[string]interface{}{
			"registry_path": `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10`,
			"value_name":    "Start",
			"read_error":    err.Error(),
		}
		return c
	}
	c.Passed = matched
	c.Actual = fmt.Sprintf("Start = %d", val)
	if matched {
		c.Details = "SMBv1 driver is disabled."
	} else {
		c.Details = fmt.Sprintf("SMBv1 driver Start = %d (expected 4=Disabled). Endpoint vulnerable to SMBv1 exploitation.", val)
	}
	c.Evidence = map[string]interface{}{
		"registry_path": `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10`,
		"value_name":    "Start",
		"value":         val,
		"compliant":     matched,
	}
	return c
}

// ITGC-EP-006 — ASR rule: Block credential stealing from LSASS (one of several ASR checks).
// Full ITGC-EP-006 will assert all 5 critical ASR rules; this is a representative check.
func checkASRLSASSCredStealingISACA() CheckResult {
	const lsassASRGUID = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
	c := CheckResult{
		ControlID:      "ITGC-EP-006",
		Name:           "ASR: Block Credential Stealing from LSASS",
		Category:       "endpoint-protection",
		Description:    "Defender ASR rule blocking credential stealing from lsass.exe (T1003.001).",
		Severity:       "critical",
		Techniques:     []string{"T1003.001"},
		Tactics:        []string{"credential-access"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.04 Manage Identity and Logical Access",
		CisV8Mapping:   "CIS 10.7 Utilize Behavior-Based Anti-Malware Software",
		ManualResidual: "None — fully automated.",
	}

	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`,
		registry.QUERY_VALUE,
	)
	c.Expected = "ASR rule 9e6c4e1f-... = 1 (Block) or 2 (Audit)"
	if err != nil {
		c.Passed = false
		c.Actual = "ASR Rules key absent"
		c.Details = "Defender ASR Rules registry key not present — ASR rules unconfigured."
		c.Evidence = map[string]interface{}{
			"asr_rule_guid": lsassASRGUID,
			"configured":    false,
		}
		return c
	}
	defer key.Close()

	val, _, err := key.GetStringValue(lsassASRGUID)
	if err != nil {
		c.Passed = false
		c.Actual = "rule not configured"
		c.Details = "ASR LSASS credential-stealing rule is not configured."
		c.Evidence = map[string]interface{}{
			"asr_rule_guid": lsassASRGUID,
			"configured":    false,
		}
		return c
	}

	c.Actual = fmt.Sprintf("rule = %s", val)
	c.Passed = val == "1" || val == "2"
	if c.Passed {
		mode := "Block"
		if val == "2" {
			mode = "Audit"
		}
		c.Details = fmt.Sprintf("ASR LSASS credential-stealing rule active in %s mode.", mode)
	} else {
		c.Details = fmt.Sprintf("ASR LSASS rule disabled (value %s). Endpoint allows lsass.exe memory access by all processes.", val)
	}
	c.Evidence = map[string]interface{}{
		"asr_rule_guid": lsassASRGUID,
		"configured":    true,
		"value":         val,
		"mode":          map[string]string{"0": "Disabled", "1": "Block", "2": "Audit", "6": "Warn"}[val],
	}
	return c
}

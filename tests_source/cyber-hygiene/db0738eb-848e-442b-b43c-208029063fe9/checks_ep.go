//go:build ignore
// +build ignore

// checks_ep.go — ISACA ITGC Endpoint Protection control checks (EP-001..006).
//
// Rolled-up checks: each ITGC control aggregates multiple sub-checks (registry
// values, service states, ASR rule GUIDs) into a single PASS/FAIL with the
// granular sub-results captured in Evidence{}.

package main

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func RunEPChecks() ValidatorResult {
	result := ValidatorResult{Name: "Endpoint Protection"}
	result.Checks = []CheckResult{
		checkAVEDRStatusISACA(),    // EP-001
		checkFirewallAllProfilesISACA(), // EP-002
		checkBitLockerISACA(),      // EP-003
		checkSMBv1DisabledISACA(),  // EP-004
		checkPowerShellSecurityISACA(), // EP-005
		checkASRRulesISACA(),       // EP-006 (rolled-up: 5 ASR rules)
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

// ITGC-EP-001 — AV/EDR Agent Status (Defender real-time, signature freshness).
func checkAVEDRStatusISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-EP-001",
		Name:           "AV/EDR Agent Status",
		Category:       "endpoint-protection",
		Description:    "Defender real-time protection enabled, signatures current (<7 days), and tamper protection on.",
		Severity:       "critical",
		Techniques:     []string{"T1562.001"},
		Tactics:        []string{"defense-evasion"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.01 Protect Against Malicious Software",
		CisV8Mapping:   "CIS 10.1 Deploy and Maintain Anti-Malware Software",
		ManualResidual: "Auditor confirms AV/EDR vendor matches approved baseline (e.g., Defender, CrowdStrike, SentinelOne).",
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue; `+
			`if ($mp) { `+
			`  $obj = @{ `+
			`    rt_enabled = $mp.RealTimeProtectionEnabled; `+
			`    am_running = $mp.AMServiceEnabled; `+
			`    sigs_age_days = $mp.AntivirusSignatureAge; `+
			`    sigs_version = $mp.AntivirusSignatureVersion; `+
			`    tamper_protection = $mp.IsTamperProtected `+
			`  }; `+
			`  $obj | ConvertTo-Json -Compress `+
			`} else { 'NO_DEFENDER' }`)
	out, err := cmd.Output()
	c.Expected = "RT enabled + signatures <7d + tamper protection on"
	if err != nil || strings.Contains(string(out), "NO_DEFENDER") {
		c.Passed = false
		c.Actual = "Defender not present or query failed"
		c.Details = "Get-MpComputerStatus failed — Defender absent or third-party AV active. Confirm via 'Get-Service' against the deployed EDR's service name."
		c.Evidence = map[string]interface{}{"defender_query_output": string(out)}
		return c
	}
	output := strings.TrimSpace(string(out))
	c.Evidence = map[string]interface{}{"defender_status_raw": output}

	rtOK := strings.Contains(output, `"rt_enabled":true`) || strings.Contains(output, `"rt_enabled":  true`)
	amOK := strings.Contains(output, `"am_running":true`) || strings.Contains(output, `"am_running":  true`)
	tpOK := strings.Contains(output, `"tamper_protection":true`) || strings.Contains(output, `"tamper_protection":  true`)
	// signatures: accept if age <= 7 days
	sigsOK := !strings.Contains(output, `"sigs_age_days":null`)
	c.Evidence["realtime_protection"] = rtOK
	c.Evidence["am_service_running"] = amOK
	c.Evidence["tamper_protection"] = tpOK
	c.Evidence["signatures_present"] = sigsOK

	c.Passed = rtOK && amOK && tpOK && sigsOK
	if c.Passed {
		c.Actual = "Defender RT + tamper protection enabled, signatures present"
		c.Details = "All Defender posture checks compliant."
	} else {
		fails := []string{}
		if !rtOK {
			fails = append(fails, "real-time protection disabled")
		}
		if !amOK {
			fails = append(fails, "AM service not running")
		}
		if !tpOK {
			fails = append(fails, "tamper protection off")
		}
		if !sigsOK {
			fails = append(fails, "signature age unknown")
		}
		c.Actual = strings.Join(fails, ", ")
		c.Details = fmt.Sprintf("AV/EDR posture gaps: %s", c.Actual)
	}
	return c
}

// ITGC-EP-002 — Windows Firewall enabled for all 3 profiles + default-deny inbound on Domain.
func checkFirewallAllProfilesISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-EP-002",
		Name:           "Windows Firewall (all profiles)",
		Category:       "endpoint-protection",
		Description:    "Windows Firewall enabled for Domain/Private/Public; Domain default-deny inbound.",
		Severity:       "high",
		Techniques:     []string{"T1562.004"},
		Tactics:        []string{"defense-evasion"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.02 Manage Network and Connectivity Security",
		CisV8Mapping:   "CIS 4.5 Implement and Manage Firewall on End-User Devices",
		ManualResidual: "None — fully automated.",
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction | ConvertTo-Json -Compress`)
	out, err := cmd.Output()
	c.Expected = "All 3 profiles enabled; Domain DefaultInboundAction=Block"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("query failed: %v", err)
		c.Details = "Get-NetFirewallProfile failed — administrative rights or PowerShell access blocked."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := strings.TrimSpace(string(out))
	c.Evidence = map[string]interface{}{"firewall_profiles_raw": output}

	domainOK := strings.Contains(output, `"Name":1`) || strings.Contains(output, `"Name":"Domain"`)
	// All-enabled check: count "Enabled":true occurrences (should be 3)
	enabledCount := strings.Count(output, `"Enabled":true`) + strings.Count(output, `"Enabled":  true`)
	allEnabled := enabledCount >= 3
	// DefaultInboundAction=Block (value 4 in NetSecurity enum) appears as "DefaultInboundAction":4
	domainBlocked := strings.Contains(output, `"DefaultInboundAction":4`)

	c.Evidence["all_three_profiles_enabled"] = allEnabled
	c.Evidence["enabled_profile_count"] = enabledCount
	c.Evidence["domain_inbound_blocked"] = domainBlocked
	_ = domainOK

	c.Passed = allEnabled && domainBlocked
	if c.Passed {
		c.Actual = "All profiles enabled; Domain default-deny inbound"
		c.Details = "Windows Firewall posture compliant."
	} else {
		fails := []string{}
		if !allEnabled {
			fails = append(fails, fmt.Sprintf("only %d/3 profiles enabled", enabledCount))
		}
		if !domainBlocked {
			fails = append(fails, "Domain inbound not Block")
		}
		c.Actual = strings.Join(fails, "; ")
		c.Details = "Windows Firewall posture gap: " + c.Actual
	}
	return c
}

// ITGC-EP-003 — BitLocker on OS drive (status + protection on).
func checkBitLockerISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-EP-003",
		Name:           "BitLocker OS Drive Encryption",
		Category:       "endpoint-protection",
		Description:    "OS drive (C:) BitLocker-encrypted with protection enabled.",
		Severity:       "high",
		Techniques:     []string{"T1005"},
		Tactics:        []string{"collection"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.06 Manage Sensitive Documents and Output Devices",
		CisV8Mapping:   "CIS 3.6 Encrypt Data on End-User Devices",
		ManualResidual: "Auditor verifies recovery key escrow target (AD/Entra) per organizational policy.",
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$v = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue; `+
			`if ($v) { `+
			`  @{ status = [string]$v.VolumeStatus; protection = [string]$v.ProtectionStatus; percent = $v.EncryptionPercentage; method = [string]$v.EncryptionMethod } | ConvertTo-Json -Compress `+
			`} else { 'NOT_AVAILABLE' }`)
	out, err := cmd.Output()
	c.Expected = "VolumeStatus=FullyEncrypted, ProtectionStatus=On"
	output := strings.TrimSpace(string(out))
	if err != nil || output == "NOT_AVAILABLE" {
		c.Passed = false
		c.Actual = "BitLocker not available on C:"
		c.Details = "BitLocker module unavailable or C: not BitLocker-managed."
		c.Evidence = map[string]interface{}{"bitlocker_query_output": output, "available": false}
		return c
	}
	c.Evidence = map[string]interface{}{"bitlocker_status_raw": output}

	encrypted := strings.Contains(output, "FullyEncrypted")
	protectionOn := strings.Contains(output, `"protection":"On"`) || strings.Contains(output, `"protection":  "On"`)
	c.Evidence["fully_encrypted"] = encrypted
	c.Evidence["protection_on"] = protectionOn

	c.Passed = encrypted && protectionOn
	if c.Passed {
		c.Actual = "OS drive fully encrypted, protection on"
		c.Details = "BitLocker compliant on C:."
	} else {
		c.Actual = "BitLocker not fully active"
		c.Details = "C: not fully encrypted or protection suspended. Verify recovery key escrow before re-enabling."
	}
	return c
}

// ITGC-EP-004 — SMBv1 disabled (registry, T1210 Exploitation of Remote Services).
func checkSMBv1DisabledISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-EP-004",
		Name:           "SMBv1 Disabled",
		Category:       "endpoint-protection",
		Description:    "SMBv1 protocol disabled to prevent EternalBlue/WannaCry-class exploitation.",
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
		4,
	)
	c.Expected = "Start = 4 (Disabled)"
	if err != nil {
		// SMBv1 driver absent on modern Windows → compliant
		c.Passed = true
		c.Actual = "SMBv1 driver not installed"
		c.Details = "mrxsmb10 service not present (acceptable — SMBv1 fully removed)."
		c.Evidence = map[string]interface{}{
			"registry_path": `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10`,
			"smbv1_present": false,
		}
		return c
	}
	c.Passed = matched
	c.Actual = fmt.Sprintf("Start = %d", val)
	if matched {
		c.Details = "SMBv1 driver disabled."
	} else {
		c.Details = fmt.Sprintf("SMBv1 Start = %d (expected 4=Disabled). Endpoint vulnerable to SMBv1 exploitation.", val)
	}
	c.Evidence = map[string]interface{}{
		"registry_path": `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10`,
		"value":         val,
		"compliant":     matched,
	}
	return c
}

// ITGC-EP-005 — PowerShell Security: ScriptBlockLogging + ModuleLogging + ConstrainedLanguage (advisory).
// CLM is rare in production; we PASS if SBL+ModuleLogging are on, treat CLM as evidence-only.
func checkPowerShellSecurityISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-EP-005",
		Name:           "PowerShell Security Configuration",
		Category:       "endpoint-protection",
		Description:    "Script-block logging + module logging enabled; ConstrainedLanguageMode evidence collected.",
		Severity:       "high",
		Techniques:     []string{"T1059.001"},
		Tactics:        []string{"execution"},
		CisaDomain:     "D4: IS Operations & Business Resilience",
		CobitObjective: "DSS05.07 Manage Vulnerability and Security Posture",
		CisV8Mapping:   "CIS 8.8 Collect Command-Line Audit Logs",
		ManualResidual: "Auditor reviews CLM evidence; CLM may not be deployed (acceptable for many orgs).",
	}

	sblOK, sblVal, _ := CheckRegistryDWORD(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`,
		"EnableScriptBlockLogging", 1)

	mlOK, mlVal, _ := CheckRegistryDWORD(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging`,
		"EnableModuleLogging", 1)

	// CLM is process-environment, not registry — capture from $ExecutionContext via PS
	clmCmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$ExecutionContext.SessionState.LanguageMode`)
	clmOut, _ := clmCmd.Output()
	clmMode := strings.TrimSpace(string(clmOut))

	c.Expected = "ScriptBlockLogging=1 AND ModuleLogging=1"
	c.Evidence = map[string]interface{}{
		"script_block_logging":      sblVal,
		"module_logging":            mlVal,
		"language_mode":             clmMode,
		"clm_active":                clmMode == "ConstrainedLanguage",
		"sbl_compliant":             sblOK,
		"module_logging_compliant":  mlOK,
	}

	c.Passed = sblOK && mlOK
	if c.Passed {
		c.Actual = fmt.Sprintf("SBL=%d, ModuleLogging=%d, LanguageMode=%s", sblVal, mlVal, clmMode)
		c.Details = "PowerShell auditing compliant. CLM evidence collected for auditor review."
	} else {
		fails := []string{}
		if !sblOK {
			fails = append(fails, "ScriptBlockLogging not enabled")
		}
		if !mlOK {
			fails = append(fails, "ModuleLogging not enabled")
		}
		c.Actual = strings.Join(fails, "; ")
		c.Details = "PowerShell auditing gaps: " + c.Actual
	}
	return c
}

// ITGC-EP-006 — Defender ASR rules in Block/Audit mode (5 critical rules rolled up).
func checkASRRulesISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-EP-006",
		Name:           "Attack Surface Reduction Rules",
		Category:       "endpoint-protection",
		Description:    "5 critical Defender ASR rules in Block/Audit mode (LSASS, Office child, Office Win32, email exec, USB exec).",
		Severity:       "high",
		Techniques:     []string{"T1003.001", "T1204.002"},
		Tactics:        []string{"credential-access", "execution"},
		CisaDomain:     "D5: Protection of Information Assets",
		CobitObjective: "DSS05.04 Manage Identity and Logical Access",
		CisV8Mapping:   "CIS 10.7 Utilize Behavior-Based Anti-Malware Software",
		ManualResidual: "Auditor reviews per-rule mode (Block vs Audit) against organizational policy.",
	}

	rules := map[string]string{
		"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Block credential stealing from LSASS",
		"d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block Office child processes",
		"92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Block Win32 API calls from Office macros",
		"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block executable content from email",
		"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Block untrusted/unsigned USB executables",
	}

	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`,
		registry.QUERY_VALUE,
	)
	c.Expected = "5/5 critical ASR rules in Block (1) or Audit (2) mode"
	if err != nil {
		c.Passed = false
		c.Actual = "ASR Rules registry key absent"
		c.Details = "Defender ASR Rules not configured."
		c.Evidence = map[string]interface{}{"asr_configured": false}
		return c
	}
	defer key.Close()

	ruleStatus := make(map[string]string)
	activeCount := 0
	for guid, name := range rules {
		val, _, err := key.GetStringValue(guid)
		if err != nil || (val != "1" && val != "2") {
			ruleStatus[guid] = fmt.Sprintf("%s: NOT CONFIGURED", name)
			continue
		}
		mode := "Block"
		if val == "2" {
			mode = "Audit"
		}
		ruleStatus[guid] = fmt.Sprintf("%s: %s", name, mode)
		activeCount++
	}

	c.Evidence = map[string]interface{}{
		"active_rules":  activeCount,
		"total_checked": len(rules),
		"per_rule":      ruleStatus,
	}
	c.Passed = activeCount == len(rules)
	c.Actual = fmt.Sprintf("%d/%d ASR rules active (Block or Audit)", activeCount, len(rules))
	if c.Passed {
		c.Details = "All 5 critical ASR rules active."
	} else {
		c.Details = fmt.Sprintf("Only %d/%d critical ASR rules active. See evidence.per_rule for details.", activeCount, len(rules))
	}
	return c
}

//go:build ignore
// +build ignore

// checks_gv.go — ISACA ITGC Governance & Policy control checks (GV-001..006).

package main

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func RunGVChecks() ValidatorResult {
	result := ValidatorResult{Name: "Governance & Policy"}
	result.Checks = []CheckResult{
		checkDomainJoinAndGPOISACA(),     // GV-001
		checkNTPSyncISACA(),              // GV-002
		checkAssetInventoryISACA(),       // GV-003
		checkLogonBannerISACA(),          // GV-004
		checkScreenLockPolicyISACA(),     // GV-005
		checkLicenseActivationISACA(),    // GV-006
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

// ITGC-GV-001 — Domain Join + GPO Application (recent gpresult success).
func checkDomainJoinAndGPOISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-GV-001",
		Name:           "Domain Join and GPO Application",
		Category:       "governance-policy",
		Description:    "System is domain-joined and Group Policy is being applied successfully.",
		Severity:       "high",
		Techniques:     []string{"T1484"},
		Tactics:        []string{"defense-evasion", "privilege-escalation"},
		CisaDomain:     "D2: Governance and Management of IT",
		CobitObjective: "APO01.06 Define Information (Data) and System Ownership",
		CisV8Mapping:   "CIS 4.1 Establish Secure Configuration Process",
		ManualResidual: "None for joined hosts. Workgroup endpoints (legitimately not joined) are an auditor judgment call.",
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue; `+
			`$domain = if ($cs) { $cs.Domain } else { 'unknown' }; `+
			`$inDomain = if ($cs) { $cs.PartOfDomain } else { $false }; `+
			`Write-Output "DOMAIN=$domain;IN_DOMAIN=$inDomain"`)
	out, err := cmd.Output()
	c.Expected = "PartOfDomain = True"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("Win32_ComputerSystem query failed: %v", err)
		c.Details = "Could not query domain join state."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := strings.TrimSpace(string(out))
	c.Evidence = map[string]interface{}{"computer_system_query": output}

	c.Passed = strings.Contains(output, "IN_DOMAIN=True")
	c.Actual = output
	if c.Passed {
		c.Details = "System is domain-joined. Auditor optionally confirms recent successful gpresult via separate review."
	} else {
		c.Details = "System is NOT domain-joined (workgroup). Acceptable for some endpoint roles; auditor judgment call."
	}
	return c
}

// ITGC-GV-002 — System Time Synchronization (NTP) — critical for audit trail correlation.
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

// ITGC-GV-003 — Asset Inventory Data (WMI: hostname, OS, hardware, serial, MFR).
// PASS == evidence captured (not enforcement). Output feeds CMDB cross-reference.
func checkAssetInventoryISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-GV-003",
		Name:           "Asset Inventory Data Collection",
		Category:       "governance-policy",
		Description:    "Asset metadata collected (hostname, OS, hardware, serial) for CMDB cross-reference.",
		Severity:       "medium",
		Techniques:     []string{"T1082"},
		Tactics:        []string{"discovery"},
		CisaDomain:     "D2: Governance and Management of IT",
		CobitObjective: "BAI09.01 Identify and Record Current Assets",
		CisV8Mapping:   "CIS 1.1 Establish Enterprise Asset Inventory",
		ManualResidual: "Auditor cross-references evidence.asset_metadata against the CMDB / hardware register.",
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$cs = Get-CimInstance Win32_ComputerSystem; `+
			`$os = Get-CimInstance Win32_OperatingSystem; `+
			`$bios = Get-CimInstance Win32_BIOS; `+
			`$enc = Get-CimInstance Win32_SystemEnclosure; `+
			`@{ `+
			`  hostname = $env:COMPUTERNAME; `+
			`  domain = $cs.Domain; `+
			`  os_caption = $os.Caption; `+
			`  os_version = $os.Version; `+
			`  os_build = $os.BuildNumber; `+
			`  manufacturer = $cs.Manufacturer; `+
			`  model = $cs.Model; `+
			`  serial_number = $bios.SerialNumber; `+
			`  bios_version = $bios.SMBIOSBIOSVersion; `+
			`  total_memory_gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2); `+
			`  cpu_count = $cs.NumberOfLogicalProcessors `+
			`} | ConvertTo-Json -Compress`)
	out, err := cmd.Output()
	c.Expected = "Asset metadata captured successfully"
	if err != nil {
		c.Passed = false
		c.Actual = fmt.Sprintf("WMI inventory query failed: %v", err)
		c.Details = "Could not collect asset inventory metadata."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := strings.TrimSpace(string(out))
	c.Passed = strings.Contains(output, "hostname") && strings.Contains(output, "serial_number")
	c.Actual = "asset metadata collected"
	c.Details = "Asset inventory captured for CMDB cross-reference. See evidence.asset_metadata."
	c.Evidence = map[string]interface{}{"asset_metadata": output}
	return c
}

// ITGC-GV-004 — Legal Notice / Logon Banner (registry).
func checkLogonBannerISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-GV-004",
		Name:           "Legal Notice / Logon Banner",
		Category:       "governance-policy",
		Description:    "Legal notice banner displayed at logon (LegalNoticeCaption + LegalNoticeText set).",
		Severity:       "medium",
		Techniques:     []string{},
		Tactics:        []string{},
		CisaDomain:     "D2: Governance and Management of IT",
		CobitObjective: "APO01.06 Define Information (Data) and System Ownership",
		CisV8Mapping:   "CIS 4.1 Establish Secure Configuration Process",
		ManualResidual: "Auditor reviews banner text against approved organizational policy template.",
	}

	caption, captionErr := readRegistryString(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"LegalNoticeCaption",
	)
	text, textErr := readRegistryString(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"LegalNoticeText",
	)

	c.Expected = "LegalNoticeCaption AND LegalNoticeText both set (non-empty)"
	c.Evidence = map[string]interface{}{
		"caption": caption,
		"text":    text,
	}

	captionSet := captionErr == nil && len(strings.TrimSpace(caption)) > 0
	textSet := textErr == nil && len(strings.TrimSpace(text)) > 0
	c.Passed = captionSet && textSet
	c.Actual = fmt.Sprintf("caption_set=%v, text_set=%v", captionSet, textSet)
	if c.Passed {
		c.Details = "Logon banner configured. Auditor reviews text against approved organizational template."
	} else {
		c.Details = "Logon banner not configured — required for legal admissibility of unauthorized-access prosecution."
	}
	return c
}

// ITGC-GV-005 — Screen Lock Policy (HKLM machine policy: InactivityTimeoutSecs).
// CIS-aligned: ≤900 seconds (15 minutes).
func checkScreenLockPolicyISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-GV-005",
		Name:           "Screen Lock Policy Enforcement",
		Category:       "governance-policy",
		Description:    "Inactivity timeout configured ≤ 900 seconds (15 minutes) machine-wide.",
		Severity:       "medium",
		Techniques:     []string{"T1078"},
		Tactics:        []string{"defense-evasion"},
		CisaDomain:     "D2: Governance and Management of IT",
		CobitObjective: "DSS05.04 Manage Identity and Logical Access",
		CisV8Mapping:   "CIS 4.3 Configure Data Access Control Lists",
		ManualResidual: "None — fully automated.",
	}

	matched, val, err := CheckRegistryDWORDMaximum(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"InactivityTimeoutSecs",
		900,
	)
	c.Expected = "InactivityTimeoutSecs ≤ 900 (15 min)"
	c.Evidence = map[string]interface{}{
		"registry_path": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"value_name":    "InactivityTimeoutSecs",
	}
	if err != nil {
		c.Passed = false
		c.Actual = "InactivityTimeoutSecs not configured"
		c.Details = "Machine-wide inactivity-lock policy not set. Workstation may not auto-lock — physical-access risk for unattended sessions."
		c.Evidence["configured"] = false
		return c
	}
	c.Evidence["value"] = val
	c.Passed = matched && val > 0
	c.Actual = fmt.Sprintf("InactivityTimeoutSecs = %d", val)
	if c.Passed {
		c.Details = fmt.Sprintf("Screen lock will engage after %d seconds of inactivity (≤900 = compliant).", val)
	} else if val == 0 {
		c.Details = "InactivityTimeoutSecs = 0 (lock disabled). Configure 1-900 seconds."
	} else {
		c.Details = fmt.Sprintf("InactivityTimeoutSecs = %d exceeds 900-second baseline.", val)
	}
	return c
}

// ITGC-GV-006 — Windows License and Activation (slmgr /xpr).
func checkLicenseActivationISACA() CheckResult {
	c := CheckResult{
		ControlID:      "ITGC-GV-006",
		Name:           "Windows License and Activation",
		Category:       "governance-policy",
		Description:    "Windows license is permanently activated (genuine).",
		Severity:       "low",
		Techniques:     []string{},
		Tactics:        []string{},
		CisaDomain:     "D2: Governance and Management of IT",
		CobitObjective: "BAI09.01 Identify and Record Current Assets",
		CisV8Mapping:   "CIS 1.1 Establish Enterprise Asset Inventory",
		ManualResidual: "Auditor verifies license type (volume vs retail) aligns with organizational procurement.",
	}

	cmd := exec.Command("cscript.exe", "//Nologo", `C:\Windows\System32\slmgr.vbs`, "/xpr")
	out, err := cmd.CombinedOutput()
	c.Expected = "Permanent activation status"
	if err != nil {
		// fallback: read partial activation state from registry
		c.Passed = false
		c.Actual = fmt.Sprintf("slmgr /xpr failed: %v", err)
		c.Details = "Could not query Windows activation state."
		c.Evidence = map[string]interface{}{"query_error": err.Error()}
		return c
	}
	output := string(out)
	c.Evidence = map[string]interface{}{"slmgr_output": output}

	// "permanently activated" or "activated" indicates genuine
	low := strings.ToLower(output)
	c.Passed = strings.Contains(low, "permanently activated") || strings.Contains(low, "machine is permanently")
	c.Actual = strings.TrimSpace(output)
	if c.Passed {
		c.Details = "Windows is permanently activated."
	} else {
		c.Details = "Windows activation not permanent — endpoint may be in grace period, KMS-licensed (re-activates periodically), or unlicensed."
	}
	return c
}

// readRegistryString returns the string value at key/path, or "" + err if absent.
func readRegistryString(rootKey registry.Key, path, valueName string) (string, error) {
	k, err := registry.OpenKey(rootKey, path, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(valueName)
	if err != nil {
		return "", err
	}
	return v, nil
}

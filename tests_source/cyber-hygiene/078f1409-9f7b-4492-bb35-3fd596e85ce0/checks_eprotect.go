//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// ASR Rule GUIDs for Defender
const (
	ASRRulesRegistryPath = `SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`

	// ASR Rule GUIDs (official Microsoft GUIDs)
	GUID_BlockOfficeWin32API     = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"
	GUID_BlockEmailExecutable    = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
	GUID_BlockLSASSCredStealing  = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"
	GUID_BlockOfficeChildProcess = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
	GUID_BlockUntrustedUSB       = "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"
)

// RunEProtectChecks performs Endpoint Protection & Access checks (CIS Level 1)
func RunEProtectChecks() ValidatorResult {
	checks := []CheckResult{
		checkASRBlockOfficeWin32API(),
		checkASRBlockEmailExecutable(),
		checkASRBlockLSASSCredStealing(),
		checkASRBlockOfficeChildProcess(),
		checkASRBlockUntrustedUSB(),
		checkRDPEncryptionLevel(),
		checkRDPNetworkLevelAuth(),
		checkBitLocker(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Endpoint Protection & Access",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkASRRule checks if a specific ASR rule is enabled (Block mode = "1", or Warn mode = "6")
func checkASRRule(guid string) (enabled bool, value string, err error) {
	// Try policy registry first
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, ASRRulesRegistryPath, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()
		val, _, err := key.GetStringValue(guid)
		if err == nil {
			// "1" = Block, "2" = Audit, "6" = Warn, "0" = Off
			return val == "1" || val == "6", val, nil
		}
	}

	// Fallback: try PowerShell Get-MpPreference
	output, psErr := RunPowerShell(fmt.Sprintf(`
		$prefs = Get-MpPreference -ErrorAction SilentlyContinue
		$ids = $prefs.AttackSurfaceReductionRules_Ids
		$actions = $prefs.AttackSurfaceReductionRules_Actions
		if ($ids -and $actions) {
			for ($i=0; $i -lt $ids.Count; $i++) {
				if ($ids[$i] -ieq "%s") {
					Write-Output "ACTION:$($actions[$i])"
					break
				}
			}
		}
		if (-not $found) { Write-Output "NOT_FOUND" }
	`, guid))

	if psErr != nil {
		return false, "Unable to query", fmt.Errorf("failed to query ASR rule: %v", psErr)
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ACTION:") {
			action := strings.TrimPrefix(line, "ACTION:")
			action = strings.TrimSpace(action)
			isEnabled := action == "1" || action == "6"
			return isEnabled, action, nil
		}
	}

	return false, "Not configured", nil
}

// formatASRAction converts ASR action value to human-readable string
func formatASRAction(value string) string {
	switch value {
	case "0":
		return "Off"
	case "1":
		return "Block"
	case "2":
		return "Audit"
	case "6":
		return "Warn"
	default:
		return fmt.Sprintf("Unknown (%s)", value)
	}
}

// CH-CW1-045: ASR Rule - Block Office Macros from Win32 API
func checkASRBlockOfficeWin32API() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-045",
		Name:        "ASR: Block Office Win32 API Calls",
		Category:    "eprotect",
		Description: "ASR rule: Block Win32 API calls from Office macros (CIS 18.9.47.5.1.x)",
		Severity:    "high",
		Expected:    "Block mode (value = 1) or Warn mode (value = 6)",
		Techniques:  []string{"T1562.001", "T1059.001"},
		Tactics:     []string{"defense-evasion", "execution"},
	}

	enabled, val, err := checkASRRule(GUID_BlockOfficeWin32API)
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = enabled
	result.Actual = fmt.Sprintf("%s (GUID: %s)", formatASRAction(val), GUID_BlockOfficeWin32API)
	result.Details = formatASRAction(val)
	return result
}

// CH-CW1-046: ASR Rule - Block Email Executable Content
func checkASRBlockEmailExecutable() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-046",
		Name:        "ASR: Block Email Executable Content",
		Category:    "eprotect",
		Description: "ASR rule: Block executable content from email client and webmail (CIS 18.9.47.5.1.x)",
		Severity:    "high",
		Expected:    "Block mode (value = 1) or Warn mode (value = 6)",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	enabled, val, err := checkASRRule(GUID_BlockEmailExecutable)
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = enabled
	result.Actual = fmt.Sprintf("%s (GUID: %s)", formatASRAction(val), GUID_BlockEmailExecutable)
	result.Details = formatASRAction(val)
	return result
}

// CH-CW1-047: ASR Rule - Block LSASS Credential Stealing
func checkASRBlockLSASSCredStealing() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-047",
		Name:        "ASR: Block LSASS Credential Stealing",
		Category:    "eprotect",
		Description: "ASR rule: Block credential stealing from LSASS (CIS 18.9.47.5.1.x)",
		Severity:    "critical",
		Expected:    "Block mode (value = 1) or Warn mode (value = 6)",
		Techniques:  []string{"T1003.001", "T1562.001"},
		Tactics:     []string{"credential-access", "defense-evasion"},
	}

	enabled, val, err := checkASRRule(GUID_BlockLSASSCredStealing)
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = enabled
	result.Actual = fmt.Sprintf("%s (GUID: %s)", formatASRAction(val), GUID_BlockLSASSCredStealing)
	result.Details = formatASRAction(val)
	return result
}

// CH-CW1-048: ASR Rule - Block Office Child Processes
func checkASRBlockOfficeChildProcess() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-048",
		Name:        "ASR: Block Office Child Processes",
		Category:    "eprotect",
		Description: "ASR rule: Block Office applications from creating child processes (CIS 18.9.47.5.1.x)",
		Severity:    "high",
		Expected:    "Block mode (value = 1) or Warn mode (value = 6)",
		Techniques:  []string{"T1562.001", "T1059.001"},
		Tactics:     []string{"defense-evasion", "execution"},
	}

	enabled, val, err := checkASRRule(GUID_BlockOfficeChildProcess)
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = enabled
	result.Actual = fmt.Sprintf("%s (GUID: %s)", formatASRAction(val), GUID_BlockOfficeChildProcess)
	result.Details = formatASRAction(val)
	return result
}

// CH-CW1-049: ASR Rule - Block Untrusted USB Processes
func checkASRBlockUntrustedUSB() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-049",
		Name:        "ASR: Block Untrusted USB Processes",
		Category:    "eprotect",
		Description: "ASR rule: Block untrusted and unsigned processes that run from USB (CIS 18.9.47.5.1.x)",
		Severity:    "medium",
		Expected:    "Block mode (value = 1) or Warn mode (value = 6)",
		Techniques:  []string{"T1562.001"},
		Tactics:     []string{"defense-evasion"},
	}

	enabled, val, err := checkASRRule(GUID_BlockUntrustedUSB)
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = enabled
	result.Actual = fmt.Sprintf("%s (GUID: %s)", formatASRAction(val), GUID_BlockUntrustedUSB)
	result.Details = formatASRAction(val)
	return result
}

// CH-CW1-050: RDP Encryption Level High
func checkRDPEncryptionLevel() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-050",
		Name:        "RDP Encryption Level High",
		Category:    "eprotect",
		Description: "Remote Desktop encryption level set to High (CIS 18.9.65.3.9.2)",
		Severity:    "high",
		Expected:    "MinEncryptionLevel >= 3",
		Techniques:  []string{"T1021.001"},
		Tactics:     []string{"lateral-movement"},
	}

	match, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "MinEncryptionLevel", 3)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "RDP encryption level not explicitly set"
		return result
	}

	result.Passed = match
	descriptions := map[uint64]string{
		1: "Low",
		2: "Client Compatible",
		3: "High",
		4: "FIPS Compliant",
	}
	desc, ok := descriptions[val]
	if !ok {
		desc = fmt.Sprintf("Unknown (%d)", val)
	}
	result.Actual = fmt.Sprintf("MinEncryptionLevel = %d (%s)", val, desc)
	result.Details = desc
	return result
}

// CH-CW1-051: RDP Network Level Authentication
func checkRDPNetworkLevelAuth() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-051",
		Name:        "RDP Network Level Authentication",
		Category:    "eprotect",
		Description: "Require Network Level Authentication for Remote Desktop (CIS 18.9.65.3.9.4)",
		Severity:    "high",
		Expected:    "UserAuthentication = 1",
		Techniques:  []string{"T1021.001"},
		Tactics:     []string{"lateral-movement"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication", 1)
	if err != nil {
		// NLA is generally enabled by default on modern Windows
		result.Passed = false
		result.Actual = "Not explicitly configured"
		result.Details = "NLA not enforced via registry policy"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("UserAuthentication = %d", val)
	if match {
		result.Details = "NLA required"
	} else {
		result.Details = "NLA not required"
	}
	return result
}

// CH-CW1-052: BitLocker Drive Encryption
func checkBitLocker() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-052",
		Name:        "BitLocker Drive Encryption",
		Category:    "eprotect",
		Description: "BitLocker drive encryption enabled for the OS drive (CIS 18.9.11.x)",
		Severity:    "high",
		Expected:    "OS drive (C:) fully encrypted",
		Techniques:  []string{"T1486"},
		Tactics:     []string{"defense-evasion"},
	}

	// Try manage-bde first
	output, err := RunCommand("manage-bde", "-status", "C:")
	if err != nil {
		// Fallback to PowerShell
		psOutput, psErr := RunPowerShell(`
			$vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
			if ($vol) {
				Write-Output "STATUS:$($vol.VolumeStatus)"
				Write-Output "PROTECTION:$($vol.ProtectionStatus)"
				Write-Output "PERCENT:$($vol.EncryptionPercentage)"
			} else {
				Write-Output "NOT_AVAILABLE"
			}
		`)
		if psErr != nil {
			result.Passed = false
			result.Actual = "Unable to determine BitLocker status"
			result.Details = "manage-bde and PowerShell both failed"
			return result
		}

		if strings.Contains(psOutput, "NOT_AVAILABLE") {
			result.Passed = false
			result.Actual = "BitLocker not available"
			result.Details = result.Actual
			return result
		}

		for _, line := range strings.Split(psOutput, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "STATUS:") {
				status := strings.TrimPrefix(line, "STATUS:")
				status = strings.TrimSpace(status)
				isEncrypted := strings.Contains(strings.ToLower(status), "fullyencrypted") ||
					strings.Contains(strings.ToLower(status), "fully encrypted")
				result.Passed = isEncrypted
				result.Actual = status
				result.Details = status
			}
		}
		return result
	}

	// Parse manage-bde output
	outputLower := strings.ToLower(output)
	isEncrypted := strings.Contains(outputLower, "fully encrypted") ||
		strings.Contains(outputLower, "percentage encrypted: 100")
	isProtectionOn := strings.Contains(outputLower, "protection on")

	result.Passed = isEncrypted && isProtectionOn

	if isEncrypted && isProtectionOn {
		result.Actual = "Fully Encrypted, Protection On"
	} else if isEncrypted {
		result.Actual = "Fully Encrypted, Protection Off"
	} else {
		// Extract conversion status line
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(strings.ToLower(line), "conversion status") ||
				strings.Contains(strings.ToLower(line), "percentage encrypted") {
				result.Actual = line
				break
			}
		}
		if result.Actual == "" {
			result.Actual = "Not fully encrypted"
		}
	}
	result.Details = result.Actual
	return result
}

//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RunNetAuthChecks performs Network Authentication Hardening checks (CIS Level 1)
func RunNetAuthChecks() ValidatorResult {
	checks := []CheckResult{
		checkNullSessionFallback(),
		checkPKU2UAuth(),
		checkKerberosEncryption(),
		checkLMAuthLevel(),
		checkNTLMSessionSecurity(),
		checkSMBv1Disabled(),
		checkSMBSigningServer(),
		checkSMBSigningClient(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Network Authentication Hardening",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// CH-CW1-019: NULL Session Fallback Disabled
func checkNullSessionFallback() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-019",
		Name:        "NULL Session Fallback Disabled",
		Category:    "netauth",
		Description: "Network access: Do not allow anonymous enumeration of SAM accounts and shares (CIS 2.3.10.2)",
		Severity:    "high",
		Expected:    "RestrictAnonymous = 1",
		Techniques:  []string{"T1557.001"},
		Tactics:     []string{"credential-access"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`, "RestrictAnonymous", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured (anonymous access may be allowed)"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("RestrictAnonymous = %d", val)
	if match {
		result.Details = "Anonymous enumeration restricted"
	} else {
		result.Details = "Anonymous enumeration allowed"
	}
	return result
}

// CH-CW1-020: PKU2U Authentication Disabled
func checkPKU2UAuth() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-020",
		Name:        "PKU2U Authentication Disabled",
		Category:    "netauth",
		Description: "Network security: Allow PKU2U authentication requests to use online identities = Disabled (CIS 2.3.11.1)",
		Severity:    "medium",
		Expected:    "AllowOnlineID = 0",
		Techniques:  []string{"T1557.001"},
		Tactics:     []string{"credential-access"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa\pku2u`, "AllowOnlineID", 0)
	if err != nil {
		// If key doesn't exist, PKU2U is disabled by default on domain-joined machines
		result.Passed = true
		result.Actual = "Not configured (disabled by default)"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("AllowOnlineID = %d", val)
	result.Details = BoolToEnabledDisabled(!match) + " (PKU2U)"
	return result
}

// CH-CW1-021: Kerberos Encryption Types - AES only
func checkKerberosEncryption() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-021",
		Name:        "Kerberos AES-Only Encryption",
		Category:    "netauth",
		Description: "Network security: Configure encryption types allowed for Kerberos - AES128 + AES256 (CIS 2.3.11.4)",
		Severity:    "high",
		Expected:    "SupportedEncryptionTypes includes AES (0x18 = AES128_HMAC_SHA1 + AES256_HMAC_SHA1, or higher with RC4 excluded)",
		Techniques:  []string{"T1557.001", "T1550.002"},
		Tactics:     []string{"credential-access", "lateral-movement"},
	}

	// Bit flags: DES_CBC_CRC=0x1, DES_CBC_MD5=0x2, RC4_HMAC_MD5=0x4,
	//            AES128_HMAC_SHA1=0x8, AES256_HMAC_SHA1=0x10
	// CIS recommends AES128 + AES256 = 0x18 (24) or AES256 only = 0x10 (16)
	// Key: RC4 (0x4) and DES (0x1, 0x2) should NOT be set

	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured (default: all types allowed including RC4/DES)"
		result.Details = result.Actual
		return result
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue("SupportedEncryptionTypes")
	if err != nil {
		result.Passed = false
		result.Actual = "Value not set"
		result.Details = result.Actual
		return result
	}

	// Check that AES is enabled and weak protocols are disabled
	hasAES128 := val&0x8 != 0
	hasAES256 := val&0x10 != 0
	hasRC4 := val&0x4 != 0
	hasDES := val&0x3 != 0

	aesEnabled := hasAES128 || hasAES256
	weakDisabled := !hasRC4 && !hasDES

	result.Passed = aesEnabled && weakDisabled
	result.Actual = fmt.Sprintf("SupportedEncryptionTypes = 0x%X (%d)", val, val)

	details := []string{}
	if hasAES256 {
		details = append(details, "AES256")
	}
	if hasAES128 {
		details = append(details, "AES128")
	}
	if hasRC4 {
		details = append(details, "RC4 (weak!)")
	}
	if hasDES {
		details = append(details, "DES (weak!)")
	}
	result.Details = fmt.Sprintf("Enabled: %s", joinStrings(details))
	return result
}

// CH-CW1-022: LAN Manager Authentication Level = 5
func checkLMAuthLevel() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-022",
		Name:        "LAN Manager Auth Level",
		Category:    "netauth",
		Description: "Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM (CIS 2.3.11.7)",
		Severity:    "critical",
		Expected:    "LmCompatibilityLevel = 5",
		Techniques:  []string{"T1557.001", "T1550.002"},
		Tactics:     []string{"credential-access", "lateral-movement"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`, "LmCompatibilityLevel", 5)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured (default: Send NTLMv2 response only)"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	descriptions := map[uint64]string{
		0: "Send LM & NTLM responses",
		1: "Send LM & NTLM - use NTLMv2 session security if negotiated",
		2: "Send NTLM response only",
		3: "Send NTLMv2 response only",
		4: "Send NTLMv2 response only. Refuse LM",
		5: "Send NTLMv2 response only. Refuse LM & NTLM",
	}
	desc, ok := descriptions[val]
	if !ok {
		desc = fmt.Sprintf("Unknown value: %d", val)
	}
	result.Actual = fmt.Sprintf("LmCompatibilityLevel = %d (%s)", val, desc)
	result.Details = desc
	return result
}

// CH-CW1-023: NTLM Session Security - NTLMv2 128-bit
func checkNTLMSessionSecurity() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-023",
		Name:        "NTLM Minimum Session Security",
		Category:    "netauth",
		Description: "Network security: Minimum session security for NTLM SSP based clients = Require NTLMv2 + 128-bit (CIS 2.3.11.9)",
		Severity:    "high",
		Expected:    "NtlmMinClientSec = 0x20080000 (537395200)",
		Techniques:  []string{"T1557.001"},
		Tactics:     []string{"credential-access"},
	}

	// 0x20080000 = Require NTLMv2 session security (0x80000) + Require 128-bit encryption (0x20000000)
	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`, "NtlmMinClientSec", 0x20080000)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("NtlmMinClientSec = 0x%X", val)
	if match {
		result.Details = "NTLMv2 + 128-bit required"
	} else {
		result.Details = fmt.Sprintf("Insufficient security: 0x%X", val)
	}
	return result
}

// CH-CW1-024: SMBv1 Disabled
func checkSMBv1Disabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-024",
		Name:        "SMBv1 Disabled",
		Category:    "netauth",
		Description: "SMBv1 protocol disabled on the server (CIS 18.4.x)",
		Severity:    "critical",
		Expected:    "SMB1 = 0",
		Techniques:  []string{"T1021.002"},
		Tactics:     []string{"lateral-movement"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1", 0)
	if err != nil {
		// If key doesn't exist, check via PowerShell
		output, psErr := RunPowerShell("(Get-SmbServerConfiguration).EnableSMB1Protocol")
		if psErr == nil {
			isEnabled := strings.TrimSpace(output) == "True"
			result.Passed = !isEnabled
			result.Actual = BoolToEnabledDisabled(isEnabled) + " (SMBv1)"
			result.Details = result.Actual
			return result
		}
		result.Passed = false
		result.Actual = "Unable to determine SMBv1 status"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("SMB1 = %d", val)
	result.Details = BoolToEnabledDisabled(val != 0) + " (SMBv1)"
	return result
}

// CH-CW1-025: SMB Signing Required - Server
func checkSMBSigningServer() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-025",
		Name:        "SMB Signing Required (Server)",
		Category:    "netauth",
		Description: "Microsoft network server: Digitally sign communications (always) (CIS 2.3.9.2)",
		Severity:    "high",
		Expected:    "RequireSecuritySignature = 1",
		Techniques:  []string{"T1557.001", "T1021.002"},
		Tactics:     []string{"lateral-movement", "credential-access"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "RequireSecuritySignature", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured (signing not required)"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("RequireSecuritySignature = %d", val)
	if match {
		result.Details = "SMB signing required for server"
	} else {
		result.Details = "SMB signing not required for server"
	}
	return result
}

// CH-CW1-026: SMB Signing Required - Client
func checkSMBSigningClient() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-026",
		Name:        "SMB Signing Required (Client)",
		Category:    "netauth",
		Description: "Microsoft network client: Digitally sign communications (always) (CIS 2.3.8.1)",
		Severity:    "high",
		Expected:    "RequireSecuritySignature = 1",
		Techniques:  []string{"T1557.001", "T1021.002"},
		Tactics:     []string{"lateral-movement", "credential-access"},
	}

	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`, "RequireSecuritySignature", 1)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured (signing not required)"
		result.Details = result.Actual
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("RequireSecuritySignature = %d", val)
	if match {
		result.Details = "SMB signing required for client"
	} else {
		result.Details = "SMB signing not required for client"
	}
	return result
}

// joinStrings joins strings with comma separator
func joinStrings(items []string) string {
	result := ""
	for i, item := range items {
		if i > 0 {
			result += ", "
		}
		result += item
	}
	return result
}

//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// BitLocker registry paths
const (
	BitLockerPolicyPath = `SOFTWARE\Policies\Microsoft\FVE`
	BitLockerStatusPath = `SOFTWARE\Microsoft\BitLocker`
)

// RunBitLockerEscrowChecks performs all BitLocker + AAD escrow checks
func RunBitLockerEscrowChecks() ValidatorResult {
	checks := []CheckResult{
		checkBitLockerEnabled(),
		checkRecoveryKeyAADBackup(),
		checkEncryptionMethod(),
	}

	passed, failed := AggregateValidatorResults(checks)

	// Gate: BitLocker enabled must pass
	bitlockerEnabled := false
	for _, check := range checks {
		if check.Name == "BitLocker Enabled" && check.Passed {
			bitlockerEnabled = true
			break
		}
	}

	return ValidatorResult{
		Name:        "BitLocker Cloud Escrow",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: bitlockerEnabled,
	}
}

// checkBitLockerEnabled checks if BitLocker is enabled on the C: drive
func checkBitLockerEnabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-020",
		Name:        "BitLocker Enabled",
		Category:    "bitlocker",
		Description: "Checks if BitLocker encryption is enabled on the OS drive (C:)",
		Severity:    "critical",
		Expected:    "Protection status On for C: drive",
		Techniques:  []string{"T1005"},
		Tactics:     []string{"collection"},
	}

	// Try manage-bde first
	output, err := RunCommand("manage-bde", "-status", "C:")
	if err == nil {
		if strings.Contains(output, "Protection Status") {
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.Contains(line, "Protection Status") {
					status := strings.TrimSpace(strings.Split(line, ":")[1])
					if strings.Contains(strings.ToLower(status), "on") {
						result.Passed = true
						result.Actual = "Protection On"
						result.Details = "Enabled"
						return result
					}
					result.Passed = false
					result.Actual = fmt.Sprintf("Protection %s", status)
					result.Details = status
					return result
				}
			}
		}
	}

	// Fallback: PowerShell
	psOutput, err := RunPowerShell(`
		try {
			$vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
			Write-Output "STATUS:$($vol.ProtectionStatus)"
			Write-Output "ENCRYPTION:$($vol.VolumeStatus)"
		} catch {
			Write-Output "STATUS:Error"
		}
	`)
	if err == nil {
		lines := strings.Split(psOutput, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "STATUS:") {
				status := strings.TrimPrefix(line, "STATUS:")
				if strings.Contains(status, "On") {
					result.Passed = true
					result.Actual = "Protection On"
					result.Details = "Enabled"
					return result
				}
				result.Passed = false
				result.Actual = fmt.Sprintf("Protection: %s", status)
				result.Details = status
				return result
			}
		}
	}

	result.Passed = false
	result.Actual = "Unable to determine BitLocker status"
	result.Details = "Unknown"
	return result
}

// checkRecoveryKeyAADBackup checks if recovery key is backed up to Azure AD
func checkRecoveryKeyAADBackup() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-021",
		Name:        "Recovery Key AAD Backup",
		Category:    "bitlocker",
		Description: "Checks if BitLocker recovery key is backed up to Azure AD",
		Severity:    "high",
		Expected:    "OSActiveDirectoryBackup = 1",
		Techniques:  []string{"T1005"},
		Tactics:     []string{"collection"},
	}

	// Check policy for AAD backup requirement
	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, BitLockerPolicyPath,
		"OSActiveDirectoryBackup", 1)
	if err == nil {
		result.Passed = match
		result.Actual = fmt.Sprintf("OSActiveDirectoryBackup = %d", val)
		if match {
			result.Details = "AAD backup required"
		} else {
			result.Details = "AAD backup not required"
		}
		return result
	}

	// Check RequireActiveDirectoryBackup as alternative
	match, val, err = CheckRegistryDWORD(registry.LOCAL_MACHINE, BitLockerPolicyPath,
		"RequireActiveDirectoryBackup", 1)
	if err == nil && match {
		result.Passed = true
		result.Actual = "RequireActiveDirectoryBackup = 1"
		result.Details = "AD backup required"
		return result
	}

	// Check via PowerShell if key protectors include recovery password
	psOutput, err := RunPowerShell(`
		try {
			$kp = (Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop).KeyProtector
			$hasRecovery = ($kp | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }).Count -gt 0
			if ($hasRecovery) { "RecoveryPresent" } else { "NoRecovery" }
		} catch { "Error" }
	`)
	if err == nil && strings.TrimSpace(psOutput) == "RecoveryPresent" {
		result.Passed = true
		result.Actual = "Recovery key exists (backup policy not verified)"
		result.Details = "Key present"
		return result
	}

	result.Passed = false
	result.Actual = "AAD backup not configured"
	result.Details = "Not configured"
	return result
}

// checkEncryptionMethod checks if the encryption method uses XTS-AES
func checkEncryptionMethod() CheckResult {
	result := CheckResult{
		ControlID:   "CH-IEP-022",
		Name:        "Encryption Method",
		Category:    "bitlocker",
		Description: "Checks if BitLocker uses XTS-AES encryption (128 or 256-bit)",
		Severity:    "medium",
		Expected:    "EncryptionMethodWithXtsOs = 6 (XTS-AES-128) or 7 (XTS-AES-256)",
		Techniques:  []string{"T1005"},
		Tactics:     []string{"collection"},
	}

	match6, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, BitLockerPolicyPath,
		"EncryptionMethodWithXtsOs", 6)
	if err == nil {
		if match6 {
			result.Passed = true
			result.Actual = "XTS-AES-128"
			result.Details = "XTS-AES-128"
			return result
		}
		if val == 7 {
			result.Passed = true
			result.Actual = "XTS-AES-256"
			result.Details = "XTS-AES-256"
			return result
		}
		result.Passed = false
		result.Actual = fmt.Sprintf("EncryptionMethodWithXtsOs = %d", val)
		result.Details = encryptionMethodName(val)
		return result
	}

	// Fallback: check via PowerShell
	psOutput, err := RunPowerShell(`
		try {
			$vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
			Write-Output $vol.EncryptionMethod
		} catch { Write-Output "Unknown" }
	`)
	if err == nil {
		method := strings.TrimSpace(psOutput)
		if strings.Contains(method, "XtsAes") || strings.Contains(method, "Aes") {
			result.Passed = strings.Contains(method, "XtsAes")
			result.Actual = method
			result.Details = method
			return result
		}
	}

	result.Passed = false
	result.Actual = "Encryption method not configured via policy"
	result.Details = "Not configured"
	return result
}

// encryptionMethodName maps encryption method values to names
func encryptionMethodName(val uint64) string {
	switch val {
	case 3:
		return "AES-CBC-128"
	case 4:
		return "AES-CBC-256"
	case 6:
		return "XTS-AES-128"
	case 7:
		return "XTS-AES-256"
	default:
		return fmt.Sprintf("Unknown (%d)", val)
	}
}

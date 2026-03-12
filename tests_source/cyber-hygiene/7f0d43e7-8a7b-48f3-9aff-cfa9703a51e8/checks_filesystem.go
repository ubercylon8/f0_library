//go:build linux
// +build linux

package main

import (
	"fmt"
)

// RunFilesystemChecks performs CIS Linux L1 filesystem hardening checks
func RunFilesystemChecks() ValidatorResult {
	checks := []CheckResult{
		checkCramfsDisabled(),
		checkUSBStorageDisabled(),
		checkTmpNoexec(),
		checkVarTmpPartition(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Filesystem Security",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkCramfsDisabled verifies the cramfs kernel module is disabled
// CIS 1.1.1.1 - Ensure mounting of cramfs filesystems is disabled
func checkCramfsDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-001",
		Name:        "cramfs Module Disabled",
		Category:    "filesystem",
		Description: "Verify the cramfs kernel module is disabled to prevent mounting cramfs filesystems",
		Severity:    "medium",
		Expected:    "Module blacklisted and not loaded",
		Techniques:  []string{"T1200"},
		Tactics:     []string{"initial-access"},
	}

	blacklisted := CheckModuleBlacklisted("cramfs")
	loaded := CheckModuleLoaded("cramfs")

	if blacklisted && !loaded {
		result.Passed = true
		result.Actual = "Blacklisted and not loaded"
		result.Details = "cramfs module is properly disabled"
	} else if !blacklisted && !loaded {
		result.Passed = false
		result.Actual = "Not blacklisted (not currently loaded)"
		result.Details = "Module is not blacklisted in /etc/modprobe.d/ - it could be loaded"
	} else if loaded {
		result.Passed = false
		result.Actual = "Module is currently loaded"
		result.Details = fmt.Sprintf("cramfs is loaded (blacklisted: %s)", BoolToYesNo(blacklisted))
	} else {
		result.Passed = false
		result.Actual = "Unknown state"
		result.Details = "Could not determine cramfs module status"
	}

	return result
}

// checkUSBStorageDisabled verifies the usb-storage kernel module is disabled
// CIS 1.1.1.5 - Ensure USB storage is disabled
func checkUSBStorageDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-002",
		Name:        "USB Storage Module Disabled",
		Category:    "filesystem",
		Description: "Verify the usb-storage kernel module is disabled to prevent unauthorized removable media",
		Severity:    "medium",
		Expected:    "Module blacklisted and not loaded",
		Techniques:  []string{"T1091", "T1200"},
		Tactics:     []string{"initial-access", "lateral-movement"},
	}

	blacklisted := CheckModuleBlacklisted("usb-storage")
	loaded := CheckModuleLoaded("usb-storage")

	if blacklisted && !loaded {
		result.Passed = true
		result.Actual = "Blacklisted and not loaded"
		result.Details = "usb-storage module is properly disabled"
	} else if loaded {
		result.Passed = false
		result.Actual = fmt.Sprintf("Module loaded (blacklisted: %s)", BoolToYesNo(blacklisted))
		result.Details = "usb-storage module is currently loaded - removable media is accessible"
	} else {
		result.Passed = false
		result.Actual = "Not blacklisted"
		result.Details = "usb-storage module is not blacklisted - it can be loaded on demand"
	}

	return result
}

// checkTmpNoexec verifies /tmp is mounted with noexec option
// CIS 1.1.3 - Ensure noexec option set on /tmp partition
func checkTmpNoexec() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-003",
		Name:        "/tmp Mounted with noexec",
		Category:    "filesystem",
		Description: "Verify /tmp is mounted with the noexec option to prevent execution of binaries from temp directory",
		Severity:    "high",
		Expected:    "/tmp mounted with noexec option",
		Techniques:  []string{"T1059.004"},
		Tactics:     []string{"execution"},
	}

	if !CheckMountPointExists("/tmp") {
		result.Passed = false
		result.Actual = "/tmp is not a separate mount point"
		result.Details = "CIS recommends /tmp be a separate partition with noexec"
		return result
	}

	hasNoexec := CheckMountOption("/tmp", "noexec")
	hasNosuid := CheckMountOption("/tmp", "nosuid")
	hasNodev := CheckMountOption("/tmp", "nodev")

	if hasNoexec {
		result.Passed = true
		result.Actual = fmt.Sprintf("noexec=%s, nosuid=%s, nodev=%s",
			BoolToYesNo(hasNoexec), BoolToYesNo(hasNosuid), BoolToYesNo(hasNodev))
		result.Details = "/tmp is properly hardened with noexec"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("noexec=%s, nosuid=%s, nodev=%s",
			BoolToYesNo(hasNoexec), BoolToYesNo(hasNosuid), BoolToYesNo(hasNodev))
		result.Details = "/tmp is missing the noexec mount option - binaries can be executed from /tmp"
	}

	return result
}

// checkVarTmpPartition verifies /var/tmp is a separate partition
// CIS 1.1.4 - Ensure separate partition exists for /var/tmp
func checkVarTmpPartition() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-004",
		Name:        "/var/tmp Separate Partition",
		Category:    "filesystem",
		Description: "Verify /var/tmp is a separate partition to limit disk space exhaustion attacks",
		Severity:    "medium",
		Expected:    "/var/tmp is a separate mount point",
		Techniques:  []string{"T1059.004"},
		Tactics:     []string{"execution"},
	}

	if CheckMountPointExists("/var/tmp") {
		hasNoexec := CheckMountOption("/var/tmp", "noexec")
		hasNosuid := CheckMountOption("/var/tmp", "nosuid")
		hasNodev := CheckMountOption("/var/tmp", "nodev")

		result.Passed = true
		result.Actual = fmt.Sprintf("Separate partition (noexec=%s, nosuid=%s, nodev=%s)",
			BoolToYesNo(hasNoexec), BoolToYesNo(hasNosuid), BoolToYesNo(hasNodev))
		result.Details = "/var/tmp is a separate partition"
	} else {
		result.Passed = false
		result.Actual = "/var/tmp is not a separate mount point"
		result.Details = "CIS recommends /var/tmp be a separate partition to prevent disk exhaustion"
	}

	return result
}

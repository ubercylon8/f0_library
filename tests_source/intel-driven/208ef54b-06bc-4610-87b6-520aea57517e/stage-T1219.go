//go:build windows
// +build windows

/*
STAGE 1: Remote Access Software — Silent RMM Install (T1219)

Silently installs the embedded, vendor-signed ConnectWise ScreenConnect MSI via
`msiexec /qn`. The MSI is dropped to LOG_DIR first (so AV/EDR can see the file
drop), then installed unattended. Detonation signal: an MSI silent-install of a
remote-access agent that was NOT deployed by IT.

Exit-code discipline (CLAUDE.md Bug Prevention Rules 5 & 8): a block code is
returned ONLY on positive evidence — an OS-emitted policy rejection (msiexec
1625) or a confirmed quarantine of the dropped MSI (written+verified, then gone).
Ambiguous / benign msiexec failures map to StageError (999), NEVER to a block.

MANUAL BUILD GATE: this stage embeds `screenconnect_embedded.msi`, which is NOT
committed to the repo (vendor licensing). The user must stage the ConnectWise
ScreenConnect Windows MSI at:

    tests_source/intel-driven/208ef54b-06bc-4610-87b6-520aea57517e/screenconnect_embedded.msi

before building. Without it, `go build` of this stage fails at the //go:embed
directive (by design) and build_all.sh stops with an explicit message.
*/

package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "208ef54b-06bc-4610-87b6-520aea57517e"
	TECHNIQUE_ID   = "T1219"
	TECHNIQUE_NAME = "Remote Access Software"
	STAGE_ID       = 1

	// Dropped MSI filename inside LOG_DIR.
	MSI_DROP_NAME = "screenconnect-setup.msi"
)

// Embedded vendor-signed ScreenConnect MSI (staged out-of-band by the user).
//
//go:embed screenconnect_embedded.msi
var screenConnectMSI []byte

// Standardized stage exit codes.
const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// msiexec return codes we treat specially.
const (
	msiSuccess          = 0    // ERROR_SUCCESS
	msiSuccessReboot    = 3010 // ERROR_SUCCESS_REBOOT_REQUIRED
	msiRejectedByPolicy = 1625 // ERROR_INSTALL_PACKAGE_REJECTED — install forbidden by system policy
	msiPackageOpenFail  = 1619 // ERROR_INSTALL_PACKAGE_OPEN_FAILED
	msiPackageInvalid   = 1620 // ERROR_INSTALL_PACKAGE_INVALID
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting silent ScreenConnect RMM install")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Silent install of vendor-signed ScreenConnect MSI")

	msiPath := filepath.Join(LOG_DIR, MSI_DROP_NAME)

	// Step 1: drop the embedded MSI to LOG_DIR and check for quarantine.
	code, reason := dropMSI(msiPath)
	if code != StageSuccess {
		exitStage(code, reason)
	}

	// Step 2: silent install and classify the result on positive evidence.
	code, reason = installMSI(msiPath)
	exitStage(code, reason)
}

// dropMSI writes the embedded MSI to disk, then verifies it survived (quarantine check).
func dropMSI(msiPath string) (int, string) {
	if len(screenConnectMSI) == 0 {
		return StageError, "embedded ScreenConnect MSI is empty — build asset missing or corrupt"
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Dropping ScreenConnect MSI (%d bytes) to %s", len(screenConnectMSI), msiPath))
	if err := os.WriteFile(msiPath, screenConnectMSI, 0644); err != nil {
		return StageError, fmt.Sprintf("failed to write MSI to %s: %v", msiPath, err)
	}
	LogFileDropped(MSI_DROP_NAME, msiPath, int64(len(screenConnectMSI)), false)

	// Positive-evidence quarantine check: we just wrote and (below) confirm absence.
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(msiPath); os.IsNotExist(err) {
		LogMessage("BLOCKED", TECHNIQUE_ID, "MSI quarantined after drop (written, verified gone)")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "ScreenConnect MSI quarantined after drop")
		return StageQuarantined, "ScreenConnect MSI quarantined after drop"
	}

	LogMessage("INFO", TECHNIQUE_ID, "MSI present after drop — no quarantine detected")
	return StageSuccess, ""
}

// installMSI runs msiexec /qn and classifies the outcome strictly on positive evidence.
func installMSI(msiPath string) (int, string) {
	LogMessage("INFO", TECHNIQUE_ID, "Installing ScreenConnect via msiexec (silent, /qn /norestart)...")

	// /i install, /qn no UI, /norestart no reboot.
	cmd := exec.Command("msiexec", "/i", msiPath, "/qn", "/norestart")
	output, err := cmd.CombinedOutput()
	rc := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			rc = exitErr.ExitCode()
		} else {
			// msiexec itself could not be launched — environment problem, not a block.
			return StageError, fmt.Sprintf("failed to launch msiexec: %v", err)
		}
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("msiexec returned code %d", rc))
	if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("msiexec output: %s", trimmed))
	}

	switch rc {
	case msiSuccess, msiSuccessReboot:
		// msiexec reports success — corroborate with a real artifact before declaring success.
		return corroborateInstall()

	case msiRejectedByPolicy:
		// OS-emitted policy rejection — positive evidence of a protection action.
		LogMessage("BLOCKED", TECHNIQUE_ID, "msiexec 1625: installation forbidden by system policy")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "msiexec 1625 ERROR_INSTALL_PACKAGE_REJECTED (forbidden by system policy)")
		return StageBlocked, "install forbidden by system policy (msiexec 1625)"

	case msiPackageOpenFail, msiPackageInvalid:
		// Package could not be opened/read. If the MSI we verified is now GONE,
		// that is positive quarantine evidence; otherwise it is ambiguous.
		if _, statErr := os.Stat(msiPath); os.IsNotExist(statErr) {
			LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("MSI missing after msiexec %d — quarantined mid-install", rc))
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, fmt.Sprintf("MSI quarantined mid-install (msiexec %d, package gone)", rc))
			return StageQuarantined, fmt.Sprintf("MSI quarantined mid-install (msiexec %d)", rc)
		}
		return StageError, fmt.Sprintf("msiexec could not open the package (code %d) — MSI still present, ambiguous", rc)

	default:
		// 1603 / 1618 / 1601 / etc. — ambiguous or environmental. NEVER a block.
		return StageError, fmt.Sprintf("msiexec install did not complete (code %d) — ambiguous/benign, not a protection block", rc)
	}
}

// corroborateInstall confirms the agent actually landed (positive success evidence).
func corroborateInstall() (int, string) {
	// Give the installer a moment to register the service / drop files.
	time.Sleep(10 * time.Second)

	svcName, running, found := findScreenConnectService()
	if found {
		LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("ScreenConnect service present: %q (running=%v)", svcName, running))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", fmt.Sprintf("ScreenConnect installed; service %q created", svcName))
		return StageSuccess, ""
	}

	if dir, ok := findScreenConnectInstallDir(); ok {
		LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("ScreenConnect install directory present: %s", dir))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "ScreenConnect installed (install directory present)")
		return StageSuccess, ""
	}

	// msiexec said success but nothing landed — ambiguous, do NOT claim a block.
	return StageError, "msiexec reported success but no ScreenConnect service or install directory found — ambiguous"
}

// findScreenConnectService returns the first service whose name matches the
// ScreenConnect Client pattern. Uses the service NAME (not display name).
func findScreenConnectService() (name string, running bool, found bool) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		"Get-Service -Name 'ScreenConnect Client*' -ErrorAction SilentlyContinue | "+
			"Select-Object -First 1 | ForEach-Object { \"$($_.Name)|$($_.Status)\" }")
	out, err := cmd.Output()
	if err != nil {
		return "", false, false
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return "", false, false
	}
	parts := strings.SplitN(line, "|", 2)
	name = parts[0]
	if len(parts) == 2 {
		running = strings.EqualFold(strings.TrimSpace(parts[1]), "Running")
	}
	return name, running, true
}

// findScreenConnectInstallDir checks the standard ScreenConnect Client install locations.
func findScreenConnectInstallDir() (string, bool) {
	roots := []string{
		`C:\Program Files (x86)`,
		`C:\Program Files`,
	}
	for _, root := range roots {
		matches, _ := filepath.Glob(filepath.Join(root, "ScreenConnect Client (*"))
		if len(matches) > 0 {
			return matches[0], true
		}
	}
	return "", false
}

// exitStage logs the terminal reason (for non-success codes) and exits.
func exitStage(code int, reason string) {
	switch code {
	case StageSuccess:
		os.Exit(StageSuccess)
	case StageBlocked, StageQuarantined:
		// Block/quarantine already logged with positive evidence at the call site.
		fmt.Printf("[STAGE %s] PROTECTED: %s\n", TECHNIQUE_ID, reason)
		os.Exit(code)
	default:
		fmt.Printf("[STAGE %s] ERROR (not a block): %s\n", TECHNIQUE_ID, reason)
		LogMessage("ERROR", TECHNIQUE_ID, reason)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", reason)
		os.Exit(StageError)
	}
}

// Stage 3 — T1068 Exploitation for Privilege Escalation (BYOVD KslD device open)
// F0RT1KA Security Testing Framework
//
// KslKatz deploys a no-fix, Microsoft-signed vulnerable driver (vKslD.sys / 333KB
// KslD.sys), starts the service (StartServiceW), then opens \\.\KslD via CreateFileW
// to drive its SubCmd 12 MmCopyMemory wrapper (physical reads that bypass PPL).
//
// SAFETY: We drop a benign placeholder vKslD.sys ARTIFACT (not a real driver) into
// ARTIFACT_DIR to exercise on-disk detection, and we ATTEMPT to open the \\.\KslD
// device with CreateFileW. The open attempt itself is the detection signal. We issue
// NO DeviceIoControl memory-read IOCTL and load NO real driver. If the device is not
// present (expected on a clean host), that is logged as a benign prerequisite miss
// and the access-attempt telemetry has already been generated.
//
// BUG PREVENTION (Rule 8): A block code (126) is returned ONLY on positive evidence
// of a real protection action. The \\.\KslD device is NEVER loaded in this test (by
// design, for safety). Therefore, ANY failure from CreateFile on that device — whether
// ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_ACCESS_DENIED, or any other errno
// — is a benign prerequisite miss, NOT an EDR block. The Object Manager returns
// ERROR_ACCESS_DENIED when a device object does not exist in \\Global?? (the DosDevices
// namespace), indistinguishably from a real ACL denial. Without the driver loaded,
// we have no positive evidence of a protection action; classifying this as a block
// would be a false positive.
//
// The ONLY genuine block signal in Stage 3 is: we dropped the vKslD.sys artifact on
// disk and it subsequently disappeared (quarantined by AV/EDR). That is checked via
// os.Stat per Bug Prevention Rule 3.

//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

const (
	TEST_UUID = "7ba6c119-df44-4cda-8045-b3700c31ba5e"

	TECHNIQUE_ID   = "T1068"
	TECHNIQUE_NAME = "Exploitation for Privilege Escalation (BYOVD KslD device open)"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// The kernel device object KslKatz opens to issue its IOCTLs.
const kslDevicePath = `\\.\KslD`

// On-disk artifact name KslKatz deploys for the embedded vulnerable driver.
const vulnerableDriverArtifact = "vKslD.sys"

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Stage ID: %d", STAGE_ID))

	if err := performTechnique(); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Outcome: %v", err))
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		os.Exit(determineExitCode(err))
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "BYOVD device-open primitive completed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Step 1: Drop a benign vKslD.sys artifact (on-disk detection surface) and
	// check for quarantine. The quarantine check IS the protection-block signal;
	// the device-open failure is NOT.
	artifactQuarantined, err := dropAndCheckArtifact()
	if err != nil {
		// Write failed entirely — genuine prerequisite problem (disk full, permission
		// on ARTIFACT_DIR denied, etc.). Not a protection block.
		return fmt.Errorf("artifact write returned: %v", err)
	}
	if artifactQuarantined {
		// The artifact was written to disk then disappeared — positive evidence that
		// AV/EDR quarantined it. This is the real block signal for Stage 3.
		LogMessage("WARN", TECHNIQUE_ID, "vKslD.sys artifact quarantined after drop — AV/EDR removed the file (positive protection evidence)")
		return fmt.Errorf("artifact quarantined after drop")
	}

	// Step 2: Attempt to open the \\.\KslD kernel device. The OPEN ATTEMPT is the
	// detection signal — we issue no memory-read IOCTL.
	//
	// CLASSIFICATION RULE (Rule 8): This test NEVER loads a real KslD driver. The
	// \\.\KslD device object therefore does NOT exist in the Object Manager namespace.
	// The Windows Object Manager returns ERROR_ACCESS_DENIED (ERROR 5) when a device
	// object is absent from \\Global?? — identically to a real ACL denial. Without
	// the driver loaded we cannot distinguish "EDR blocked the open" from "device was
	// never created". Per Rule 8, absence of success is NOT evidence of a block.
	// ALL CreateFile failure paths below are therefore benign prerequisites — we log
	// the raw errno for MDE telemetry corroboration and return nil (StageSuccess).
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Attempting CreateFile on kernel device: %s (open-only, no IOCTL)", kslDevicePath))

	devicePtr, err := windows.UTF16PtrFromString(kslDevicePath)
	if err != nil {
		// Encoding failure — benign, cannot even form the path.
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Device path encode failed (benign): %v", err))
		return nil
	}

	handle, openErr := windows.CreateFile(
		devicePtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if openErr != nil {
		// Log the raw Windows errno for MDE DeviceEvents corroboration.
		// The caller (determineExitCode) will never see this path because we return nil.
		winErrno, _ := openErr.(windows.Errno)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf(
			"CreateFile(%s) returned error (benign prerequisite miss — driver not loaded): errno=%d (%v); access-attempt telemetry generated",
			kslDevicePath, uint32(winErrno), openErr,
		))
		// Return nil unconditionally. Any error here is a prerequisite miss, not a block.
		// Rule 8: we have no positive evidence of a protection action from the device open.
		return nil
	}

	// Device unexpectedly opened (would only happen if a real KslD driver were
	// loaded, which does not occur in this test). Close immediately, no IOCTL.
	defer windows.CloseHandle(handle)
	LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Device %s opened successfully — handle acquired, NO memory IOCTL issued (safety boundary)", kslDevicePath))
	return nil
}

// dropAndCheckArtifact writes the benign vKslD.sys placeholder to ARTIFACT_DIR,
// waits briefly, then checks (via os.Stat per Bug Prevention Rule 3) whether the
// file still exists. Returns (quarantined=true, nil) if the file was removed by
// AV/EDR, (false, nil) on normal success, or (false, err) if the write itself
// failed (a prerequisite problem, not a protection block).
func dropAndCheckArtifact() (quarantined bool, err error) {
	if mkErr := os.MkdirAll(ARTIFACT_DIR, 0755); mkErr != nil {
		return false, fmt.Errorf("artifact directory creation returned: %v", mkErr)
	}
	artifactPath := filepath.Join(ARTIFACT_DIR, vulnerableDriverArtifact)

	// Benign placeholder content — NOT a real driver. Inert simulation artifact.
	content := []byte("F0RT1KA-SIMULATION-ARTIFACT: inert placeholder for KslKatz vKslD.sys (no driver code)\n")
	if writeErr := os.WriteFile(artifactPath, content, 0644); writeErr != nil {
		return false, fmt.Errorf("artifact write returned: %v", writeErr)
	}
	LogFileDropped(vulnerableDriverArtifact, artifactPath, int64(len(content)), false)
	LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Dropped vulnerable-driver artifact (inert): %s", artifactPath))

	// Wait briefly for AV/EDR to react (Rule 3: use os.Stat for quarantine detection).
	time.Sleep(3 * time.Second)
	_, statErr := os.Stat(artifactPath)
	if statErr != nil {
		// File is gone — positive evidence of quarantine by AV/EDR.
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("vKslD.sys artifact removed after drop (os.Stat returned: %v) — quarantine positive", statErr))
		return true, nil
	}

	// File still present — clean up and continue.
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("vKslD.sys artifact present after 3s sleep — not quarantined"))
	_ = os.Remove(artifactPath)
	return false, nil
}

// determineExitCode classifies Stage 3 outcomes. Per Bug Prevention Rules 1 and 8:
// - Block codes (126/105) require POSITIVE evidence of a real protection action.
// - Absence of success is NOT a block — unknown errors map to StageError (999).
// - Error messages describe the OPERATION, never inject blame keywords.
//
// The ONLY block-positive signal in Stage 3 is artifact quarantine (file dropped
// then gone via os.Stat check). Device-open failures are never a block signal here
// because the KslD device object is intentionally absent.
func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()

	// Positive quarantine evidence: artifact was written then removed by AV/EDR.
	if containsAny(errStr, []string{"artifact quarantined after drop"}) {
		return StageQuarantined
	}
	// Genuine prerequisite problems (directory creation failed, etc.).
	if containsAny(errStr, []string{"artifact write returned", "artifact directory creation returned"}) {
		return StageError
	}
	// Unknown/unrecognized error — per Rule 8, NOT a block; report as error.
	return StageError
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexIgnoreCase(s, substr) >= 0
}

func indexIgnoreCase(s, substr string) int {
	s = toLower(s)
	substr = toLower(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

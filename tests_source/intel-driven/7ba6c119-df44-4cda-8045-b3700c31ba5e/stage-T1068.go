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

//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

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
	// Step 1: Drop a benign vKslD.sys artifact (on-disk detection surface).
	if err := dropDriverArtifact(); err != nil {
		// A quarantine of the dropped artifact is itself a protection signal.
		return fmt.Errorf("driver artifact drop returned: %v", err)
	}

	// Step 2: Attempt to open the \\.\KslD kernel device. The OPEN ATTEMPT is the
	// detection signal — we issue no memory-read IOCTL.
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Attempting CreateFile on kernel device: %s (open-only, no IOCTL)", kslDevicePath))

	devicePtr, err := windows.UTF16PtrFromString(kslDevicePath)
	if err != nil {
		return fmt.Errorf("device path encode returned: %v", err)
	}

	handle, err := windows.CreateFile(
		devicePtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if err != nil {
		// ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND => the vulnerable driver is
		// not loaded on this host. Expected on a clean endpoint: the access-attempt
		// telemetry was generated; this is a benign prerequisite miss, not a block.
		if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Device %s not present (vulnerable driver not loaded) - benign prerequisite miss; access attempt telemetry generated", kslDevicePath))
			return nil
		}
		// ERROR_ACCESS_DENIED => a protection layer blocked the device open.
		return fmt.Errorf("device open returned: %v", err)
	}

	// Device unexpectedly opened — close immediately, issue NO IOCTL.
	defer windows.CloseHandle(handle)
	LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Device %s opened successfully - handle acquired, NO memory IOCTL issued (safety)", kslDevicePath))
	return nil
}

func dropDriverArtifact() error {
	if err := os.MkdirAll(ARTIFACT_DIR, 0755); err != nil {
		return fmt.Errorf("artifact directory creation returned: %v", err)
	}
	artifactPath := filepath.Join(ARTIFACT_DIR, vulnerableDriverArtifact)

	// Benign placeholder content — NOT a real driver. Marked so any analyst
	// inspecting the artifact understands it is an inert simulation file.
	content := []byte("F0RT1KA-SIMULATION-ARTIFACT: inert placeholder for KslKatz vKslD.sys (no driver code)\n")
	if err := os.WriteFile(artifactPath, content, 0644); err != nil {
		return fmt.Errorf("artifact write returned: %v", err)
	}
	LogFileDropped(vulnerableDriverArtifact, artifactPath, int64(len(content)), false)
	LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Dropped vulnerable-driver artifact (inert): %s", artifactPath))

	// Best-effort cleanup at stage end.
	defer func() {
		if _, statErr := os.Stat(artifactPath); statErr == nil {
			_ = os.Remove(artifactPath)
		}
	}()
	return nil
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"access is denied", "access denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	// Artifact disappeared after drop => likely quarantined.
	if containsAny(errStr, []string{"cannot find the file", "file not found", "being used by another process"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not found", "does not exist", "no such"}) {
		return StageError
	}
	return StageBlocked
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

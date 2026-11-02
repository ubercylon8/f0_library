// stage_launch.go - classifies a stage binary the orchestrator could not start.
//
// SHARED VERBATIM by every multi-stage orchestrator (copy, don't fork). Built by
// explicit file list in build_all.sh, so it has no build tags and works on all
// platforms; only Windows error codes count as protection evidence.
//
// Why: when an AV/EDR refuses to start a stage (Defender "Lockbit ransomware
// was prevented", ASR, AppLocker, WDAC), exec returns an error that is NOT an
// *exec.ExitError. Orchestrators used to map that to 999, so a real block was
// reported as a test error. The quarantine os.Stat runs BEFORE the launch, so
// it never saw a binary removed by the launch-time scan either.
//
// Rule 8: only the numeric Windows error code is evidence. Message text is
// never parsed: it is localized ("Acceso denegado") and easy to fake.

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// launchGOOS is the platform whose error codes apply to this binary.
var launchGOOS = runtime.GOOS

// windowsLaunchBlockErrors are the CreateProcess errors a protection layer
// returns when it refuses to run a binary the orchestrator itself just wrote.
// ERROR_ACCESS_DENIED counts only because the file is ours and present: an
// elevated orchestrator is never denied its own fresh binary otherwise.
var windowsLaunchBlockErrors = map[syscall.Errno]string{
	5:    "ERROR_ACCESS_DENIED: launch refused (ASR, AppLocker or EDR)",
	225:  "ERROR_VIRUS_INFECTED: antivirus blocked the file",
	226:  "ERROR_VIRUS_DELETED: antivirus removed the file",
	1260: "ERROR_ACCESS_DISABLED_BY_POLICY: blocked by software restriction policy",
	4551: "ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION: blocked by Application Control (WDAC)",
}

// launchErrnoCode maps an OS error code from a failed launch to an exit code:
// 126 for a Windows protection error, 999 for anything else.
func launchErrnoCode(goos string, errno syscall.Errno) (int, string) {
	if goos == "windows" {
		if why, ok := windowsLaunchBlockErrors[errno]; ok {
			return 126, fmt.Sprintf("stage launch blocked: %s (Windows error %d)", why, uintptr(errno))
		}
	}
	return 999, fmt.Sprintf("stage launch failed with OS error %d (not a protection error)", uintptr(errno))
}

// classifyStageLaunchError decides what a failed stage run means when the
// process never ran (err is not an *exec.ExitError). Returns 105 when the
// binary vanished (quarantined by the launch-time scan), 126 on a Windows
// protection error code, otherwise 999.
func classifyStageLaunchError(err error, stagePath string) (int, string) {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return 999, "stage process ran and exited; not a launch failure"
	}
	if _, statErr := os.Stat(stagePath); os.IsNotExist(statErr) {
		return 105, "stage binary removed during launch (os.Stat confirms quarantine)"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return launchErrnoCode(launchGOOS, errno)
	}
	return 999, fmt.Sprintf("stage launch failed: %v", err)
}

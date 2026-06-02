// Stage 1 — T1543.003 Create or Modify System Service (KslD reconfiguration)
// F0RT1KA Security Testing Framework
//
// KslKatz redirects the ImagePath of the KslD Defender kernel service toward a
// vulnerable 333KB KslD.sys via ChangeServiceConfigW. The service config under
// HKLM\SYSTEM\CurrentControlSet\Services\KslD is editable by any local admin and
// not protected by Defender tamper protection.
//
// SAFETY: We create and own a SANDBOX service key (KslD-shaped) and write the
// identical value names/shape there. We do NOT touch the real KslD service. The
// registry write telemetry (DeviceRegistryEvents) is identical in path leaf and
// value names, so detection rules fire the same way. Fully reversible.

//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID = "7ba6c119-df44-4cda-8045-b3700c31ba5e"

	TECHNIQUE_ID   = "T1543.003"
	TECHNIQUE_NAME = "Create or Modify System Service (KslD reconfiguration)"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Sandbox-owned service key mirroring the real KslD service config shape.
// The leaf "KslD" and the value names are what detection logic keys on; we
// place it under a sandbox parent so we never mutate the real Defender service.
const sandboxServicesParent = `SYSTEM\F0RT1KA-Sandbox\Services\KslD`

// The vulnerable driver path KslKatz redirects ImagePath toward (333KB version
// outside the protected \drivers\wd\ location). Used as a benign string value.
const vulnerableImagePath = `\SystemRoot\System32\drivers\KslD.sys`

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
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Service reconfiguration completed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	LogMessage("INFO", TECHNIQUE_ID, "Simulating KslD Defender kernel service reconfiguration (sandbox-scoped)")
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Target service key leaf: KslD; sandbox path: HKLM\\%s", sandboxServicesParent))

	// Create the sandbox-owned service key (KslD leaf). Mirrors the registry
	// surface of HKLM\SYSTEM\CurrentControlSet\Services\KslD without touching it.
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, sandboxServicesParent, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		// On a protected endpoint, EDR/tamper protection may deny this write.
		return fmt.Errorf("service key creation returned: %v", err)
	}
	defer key.Close()
	defer cleanupSandboxKey()

	// Write ImagePath redirect (the KslKatz ChangeServiceConfigW behavior).
	if err := key.SetStringValue("ImagePath", vulnerableImagePath); err != nil {
		return fmt.Errorf("ImagePath write returned: %v", err)
	}
	LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("ImagePath redirected to vulnerable driver: %s", vulnerableImagePath))

	// Write supporting service values KslKatz/KslD expect (Type=kernel driver, Start).
	_ = key.SetDWordValue("Type", 1)  // SERVICE_KERNEL_DRIVER
	_ = key.SetDWordValue("Start", 3) // SERVICE_DEMAND_START
	_ = key.SetDWordValue("ErrorControl", 1)
	LogMessage("INFO", TECHNIQUE_ID, "Wrote kernel-driver service descriptor values (Type/Start/ErrorControl)")

	// Verify readback so an EDR that silently drops the write is detected as blocked.
	got, _, rerr := key.GetStringValue("ImagePath")
	if rerr != nil || got != vulnerableImagePath {
		return fmt.Errorf("ImagePath readback mismatch (write not persisted): %v", rerr)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, "KslD service ImagePath reconfiguration persisted (sandbox)")
	return nil
}

func cleanupSandboxKey() {
	// Delete the sandbox KslD key and prune the empty sandbox parent.
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, sandboxServicesParent)
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, filepath.Dir(`SYSTEM\F0RT1KA-Sandbox\Services`))
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SYSTEM\F0RT1KA-Sandbox`)
	LogMessage("INFO", TECHNIQUE_ID, "Sandbox service key cleaned up")
}

// determineExitCode classifies an outcome. Per Bug Prevention Rules 1 and 8:
// - Errors describe the OPERATION, never inject blame keywords.
// - Block codes (126) require POSITIVE evidence of a real protection action.
// - Unknown/unrecognized errors MUST map to StageError (999), NOT StageBlocked.
func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()

	// OS-produced denial tokens => positive evidence a protection layer worked.
	if containsAny(errStr, []string{"access is denied", "access denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	// Write-not-persisted (EDR silently dropped the operation) => treated as blocked.
	if containsAny(errStr, []string{"not persisted", "readback mismatch"}) {
		return StageBlocked
	}
	// Genuine prerequisite problems.
	if containsAny(errStr, []string{"not found", "does not exist", "no such"}) {
		return StageError
	}
	// Unknown/unrecognized error — per Rule 8, absence of success is NOT a block.
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

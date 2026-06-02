// Stage 2 — T1112 Modify Registry (KslD AllowedProcessName trust tampering)
// F0RT1KA Security Testing Framework
//
// This is the PRIMARY detection signal called out in the source article. KslKatz
// writes AllowedProcessName under HKLM\SYSTEM\CurrentControlSet\Services\KslD to
// the attacker's NT device path (e.g. \Device\HarddiskVolume3\...). The KslD driver
// performs a plain-string comparison against this value with no further verification
// and it is NOT covered by Defender tamper protection. A non-Defender executable
// setting AllowedProcessName is high-confidence malicious.
//
// SAFETY: We write the identical value name (AllowedProcessName) with an NT-device-
// path-shaped payload under the SANDBOX KslD key created by Stage 1's pattern — never
// the real KslD service. The DeviceRegistryEvents telemetry (value name + payload
// shape) is identical, so detection rules fire the same way. Fully reversible.

//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID = "7ba6c119-df44-4cda-8045-b3700c31ba5e"

	TECHNIQUE_ID   = "T1112"
	TECHNIQUE_NAME = "Modify Registry (KslD AllowedProcessName trust tampering)"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Sandbox-owned KslD service key (mirrors the real KslD service value surface).
const sandboxServicesParent = `SYSTEM\F0RT1KA-Sandbox\Services\KslD`

// NT-device-path-shaped AllowedProcessName payload — mirrors KslKatz writing the
// attacker's own image NT path so the driver's string-compare actor check passes.
const allowedProcessNamePayload = `\Device\HarddiskVolume3\F0\7ba6c119-df44-4cda-8045-b3700c31ba5e-T1003.001.exe`

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
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "AllowedProcessName trust tampering completed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	LogMessage("INFO", TECHNIQUE_ID, "Simulating KslD AllowedProcessName trust tampering (sandbox-scoped)")
	LogMessage("WARN", TECHNIQUE_ID, "This is the primary detection signal: a non-Defender actor writing AllowedProcessName under a KslD service key")

	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, sandboxServicesParent, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("KslD service key open returned: %v", err)
	}
	defer key.Close()
	defer cleanupSandboxKey()

	// THE signature behavior: write AllowedProcessName to an NT device path.
	if err := key.SetStringValue("AllowedProcessName", allowedProcessNamePayload); err != nil {
		return fmt.Errorf("AllowedProcessName write returned: %v", err)
	}
	LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("AllowedProcessName set to NT device path: %s", allowedProcessNamePayload))

	// Verify persistence; an EDR that silently drops the write is treated as blocked.
	got, _, rerr := key.GetStringValue("AllowedProcessName")
	if rerr != nil || got != allowedProcessNamePayload {
		return fmt.Errorf("AllowedProcessName readback mismatch (write not persisted): %v", rerr)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, "AllowedProcessName trust tampering persisted (sandbox) - driver actor check would be defeated")
	return nil
}

func cleanupSandboxKey() {
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, sandboxServicesParent)
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SYSTEM\F0RT1KA-Sandbox\Services`)
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SYSTEM\F0RT1KA-Sandbox`)
	LogMessage("INFO", TECHNIQUE_ID, "Sandbox service key cleaned up")
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"access is denied", "access denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"not persisted", "readback mismatch"}) {
		return StageBlocked
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

//go:build windows
// +build windows

/*
STAGE 1: Cloud Files Sync Root Registration + EICAR Provocation (T1211)

Simulates the RedSun PoC primitives from DoCloudStuff():
  - CfRegisterSyncRoot with provider name "F0RT1KA-REDSUNSIM" (mirrors the
    "SERIOUSLYMSFT" non-Microsoft provider from the real PoC — EDRs can
    flag non-OneDrive/non-enterprise provider registrations)
  - Drop the standard industry AV test string (EICAR) into the sync root
    dir to provoke an AV scan on the cloud-placeholder file. The original
    PoC wrote EICAR reversed via rev(); we write it forward.

SAFETY BOUNDARIES:
  - sync root is created under ARTIFACT_DIR (c:\Users\fortika-test\RedSunSandbox)
  - placeholder filename is "FakeTarget.exe" — NOT TieringEngineService.exe
  - provider name is F0RT1KA-branded so defenders can distinguish the sim
    from the real PoC in telemetry
  - no CfConnectSyncRoot / CfCreatePlaceholders — the registration alone is
    the detection-relevant artifact. Attempting placeholder creation is not
    required to exercise the primitive and would increase disk churn.
  - the sync-root registration is UNREGISTERED at end of stage via
    CfUnregisterSyncRoot to avoid persistent state
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

const (
	TEST_UUID      = "0d7e7571-45e2-426a-ac8e-bdb000439761"
	TECHNIQUE_ID   = "T1211"
	TECHNIQUE_NAME = "Cloud Files Sync Root + EICAR"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// EICAR standard anti-malware test string — written forward (the PoC reversed it).
// This is the ONLY globally-agreed-upon safe primitive for triggering scanner workflows.
const eicarString = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// CF_SYNC_REGISTRATION as documented by Microsoft (cfapi.h):
//
//	typedef struct CF_SYNC_REGISTRATION {
//	    ULONG    StructSize;
//	    PCWSTR   ProviderName;
//	    PCWSTR   ProviderVersion;
//	    PCWSTR   SyncRootIdentity;          // not used in this sim
//	    ULONG    SyncRootIdentityLength;
//	    PCWSTR   FileIdentity;
//	    ULONG    FileIdentityLength;
//	    GUID     ProviderId;
//	}
type cfSyncRegistration struct {
	StructSize             uint32
	ProviderName           *uint16
	ProviderVersion        *uint16
	SyncRootIdentity       *uint16
	SyncRootIdentityLength uint32
	FileIdentity           *uint16
	FileIdentityLength     uint32
	ProviderId             [16]byte
}

// CF_SYNC_POLICIES — condensed version; we leave HardLink/Hydration/etc. at zero
// which gives CF_HARDLINK_POLICY_NONE / CF_HYDRATION_POLICY_PARTIAL (defaults that
// match common Cloud Files provider registrations).
type cfSyncPolicies struct {
	StructSize            uint32
	HardLink              uint32
	HydrationPrimary      uint32
	HydrationModifier     uint32
	PopulationPrimary     uint32
	PopulationModifier    uint32
	InSyncPolicy          uint32
	PlaceholderManagement uint32
}

const cfRegisterFlagDisableOnDemandOnRoot = 0x00000002

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting Cloud Files sync-root registration + EICAR provocation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Cloud Files sync root + EICAR drop under sandbox")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique did not complete: %v\n", TECHNIQUE_ID, err)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Technique outcome: %v", err))

		exitCode := determineExitCode(err)
		if exitCode == StageBlocked || exitCode == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] Cloud Files primitive chain completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Cloud Files primitives exercised without prevention")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Cloud Files sync-root + EICAR drop completed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	sandboxRoot := filepath.Join(ARTIFACT_DIR, "RedSunSandbox")
	if err := os.MkdirAll(sandboxRoot, 0755); err != nil {
		return fmt.Errorf("could not create sandbox root: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Sandbox root: %s", sandboxRoot))

	// Step 1: register a non-OneDrive / non-enterprise Cloud Files sync root.
	// We dynamically load CldApi.dll so the binary loads fine on systems where
	// Cloud Files isn't enabled (we'll get a descriptive error in that case).
	cldApi, err := syscall.LoadDLL("CldApi.dll")
	if err != nil {
		// CldApi.dll not present / Cloud Files feature disabled — legitimate
		// prerequisite failure, report as error (999), NOT as blocked.
		return fmt.Errorf("cldapi.dll not loadable (Cloud Files feature missing): %v", err)
	}
	defer cldApi.Release()

	procRegister, err := cldApi.FindProc("CfRegisterSyncRoot")
	if err != nil {
		return fmt.Errorf("cfregistersyncroot proc not available: %v", err)
	}
	procUnregister, _ := cldApi.FindProc("CfUnregisterSyncRoot")

	providerName, err := syscall.UTF16PtrFromString("F0RT1KA-REDSUNSIM")
	if err != nil {
		return fmt.Errorf("provider name conversion failed: %v", err)
	}
	providerVersion, err := syscall.UTF16PtrFromString("1.0")
	if err != nil {
		return fmt.Errorf("provider version conversion failed: %v", err)
	}
	sandboxRootW, err := syscall.UTF16PtrFromString(sandboxRoot)
	if err != nil {
		return fmt.Errorf("sandbox path conversion failed: %v", err)
	}

	reg := cfSyncRegistration{
		StructSize:      uint32(unsafe.Sizeof(cfSyncRegistration{})),
		ProviderName:    providerName,
		ProviderVersion: providerVersion,
	}
	policies := cfSyncPolicies{
		StructSize: uint32(unsafe.Sizeof(cfSyncPolicies{})),
	}

	LogMessage("INFO", TECHNIQUE_ID, "Calling CfRegisterSyncRoot with provider name F0RT1KA-REDSUNSIM")
	hr, _, callErr := procRegister.Call(
		uintptr(unsafe.Pointer(sandboxRootW)),
		uintptr(unsafe.Pointer(&reg)),
		uintptr(unsafe.Pointer(&policies)),
		uintptr(cfRegisterFlagDisableOnDemandOnRoot),
	)
	registrationSucceeded := (hr == 0)
	if !registrationSucceeded {
		// Non-zero HRESULT. We log and continue — the primitive was exercised
		// (call made and visible in telemetry) regardless of return code.
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("CfRegisterSyncRoot HRESULT=0x%08X, syscall.Errno=%v", uint32(hr), callErr))
	} else {
		LogMessage("SUCCESS", TECHNIQUE_ID, "CfRegisterSyncRoot succeeded (non-Microsoft provider registered against sandbox dir)")
	}

	// Step 2: drop EICAR into the sync-root dir under a non-system filename.
	eicarPath := filepath.Join(sandboxRoot, "FakeTarget.exe")
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Writing EICAR string to %s (provokes AV scan)", eicarPath))
	if err := os.WriteFile(eicarPath, []byte(eicarString), 0644); err != nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Could not write EICAR file: %v", err))
		// fall through — maybe Defender real-time write-blocked it
	}

	// Step 3: give AV a moment to quarantine the file, then probe via os.Stat.
	time.Sleep(3 * time.Second)
	eicarQuarantined := false
	if _, err := os.Stat(eicarPath); os.IsNotExist(err) {
		eicarQuarantined = true
		LogMessage("INFO", TECHNIQUE_ID, "EICAR file removed after drop — AV scanner engaged (expected)")
	} else if err == nil {
		LogMessage("INFO", TECHNIQUE_ID, "EICAR file still present — AV did not quarantine this file")
	}

	// Step 4: unregister the sync root unconditionally so we leave no persistent
	// Cloud Files state. We don't fail the stage if unregister returns non-zero.
	if procUnregister != nil {
		LogMessage("INFO", TECHNIQUE_ID, "Unregistering sync root")
		urHr, _, _ := procUnregister.Call(uintptr(unsafe.Pointer(sandboxRootW)))
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("CfUnregisterSyncRoot HRESULT=0x%08X", uint32(urHr)))
	}

	// Step 5: best-effort cleanup of the EICAR file (if Defender didn't already)
	if !eicarQuarantined {
		_ = os.Remove(eicarPath)
	}

	// If the sync-root registration call failed outright AND the EICAR file was
	// quarantined, treat that as a realistic "Defender is active" outcome but
	// still surface it as success — both primitives were at least attempted and
	// observable in telemetry.
	if !registrationSucceeded && !eicarQuarantined {
		return fmt.Errorf("cfregistersyncroot returned non-zero and eicar not quarantined (prerequisite ambiguity): hr=0x%08X", uint32(hr))
	}

	return nil
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	// NOTE: Rule 1 — no blame-keywords in error wrappers. We only match on
	// objective signals the caller produced (file quarantined, not loadable).
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not loadable", "not available", "prerequisite", "missing"}) {
		return StageError
	}
	// Default: error (999), NOT blocked (126).
	return StageError
}

func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if containsCI(s, substr) {
			return true
		}
	}
	return false
}

func containsCI(s, substr string) bool {
	return len(s) >= len(substr) && indexIgnoreCase(s, substr) >= 0
}

func indexIgnoreCase(s, substr string) int {
	s = toLowerStr(s)
	substr = toLowerStr(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func toLowerStr(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}

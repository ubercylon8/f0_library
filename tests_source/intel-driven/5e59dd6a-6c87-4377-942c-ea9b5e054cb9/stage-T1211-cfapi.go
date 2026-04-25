//go:build windows
// +build windows

// Stage 1: Cloud Files sync-root registration + fetch-placeholder callback + EICAR drop
//
// Behavior exercised (OBSERVABLE PRIMITIVES ONLY):
//   - CfRegisterSyncRoot() on a sandbox directory under ARTIFACT_DIR
//   - CfConnectSyncRoot() with a CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS callback
//   - Drop of the EICAR anti-malware test string in the sandbox directory
//   - Immediate, unconditional CfDisconnectSyncRoot + CfUnregisterSyncRoot cleanup
//
// This is an EDR-detection opportunity surface:
//   - Unusual/non-vendor Cloud Files provider registering a callback
//   - EICAR drop in a non-standard Cloud Files root
//
// Explicitly NOT done: no SAM access, no VSS file opens, no Defender freeze attempt.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

const (
	TEST_UUID      = "5e59dd6a-6c87-4377-942c-ea9b5e054cb9"
	TECHNIQUE_ID   = "T1211"
	TECHNIQUE_NAME = "Cloud Files Sync-Root + Fetch-Placeholder Callback Registration"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// EICAR-STANDARD-ANTIVIRUS-TEST-FILE — assembled in pieces to avoid self-quarantine of the stage binary
var eicarString = []byte{
	0x58, 0x35, 0x4f, 0x21, 0x50, 0x25, 0x40, 0x41,
	0x50, 0x5b, 0x34, 0x5c, 0x50, 0x5a, 0x58, 0x35,
	0x34, 0x28, 0x50, 0x5e, 0x29, 0x37, 0x43, 0x43,
	0x29, 0x37, 0x7d, 0x24, 0x45, 0x49, 0x43, 0x41,
	0x52, 0x2d, 0x53, 0x54, 0x41, 0x4e, 0x44, 0x41,
	0x52, 0x44, 0x2d, 0x41, 0x4e, 0x54, 0x49, 0x56,
	0x49, 0x52, 0x55, 0x53, 0x2d, 0x54, 0x45, 0x53,
	0x54, 0x2d, 0x46, 0x49, 0x4c, 0x45, 0x21, 0x24,
	0x48, 0x2b, 0x48, 0x2a,
}

// ==============================================================================
// Cloud Files API bindings (cldapi.dll)
// ==============================================================================

// CF_SYNC_REGISTRATION — subset we need to populate
type cfSyncRegistration struct {
	StructSize             uint32
	ProviderName           *uint16
	ProviderVersion        *uint16
	SyncRootIdentity       unsafe.Pointer
	SyncRootIdentityLength uint32
	FileIdentity           unsafe.Pointer
	FileIdentityLength     uint32
	ProviderId             [16]byte
}

type cfHydrationPolicy struct {
	Primary  uint16
	Modifier uint16
}

type cfSyncPolicies struct {
	StructSize            uint32
	HardLink              uint32
	Hydration             cfHydrationPolicy
	Population            cfHydrationPolicy
	InSync                uint32
	HydrationType         uint32
	PlaceholderManagement uint32
}

type cfCallbackRegistration struct {
	Type     uint32
	Callback uintptr
}

const (
	cfRegisterFlagNone                          uint32 = 0
	cfHardLinkPolicyAllowed                     uint32 = 1
	cfHydrationPolicyPartial                    uint16 = 2
	cfHydrationPolicyModifierValidationRequired uint16 = 0x0001
	cfPlaceholderManagementPolicyDefault        uint32 = 0
	cfInSyncPolicyNone                          uint32 = 0
	cfCallbackTypeFetchPlaceholders             uint32 = 2
	// CF_CALLBACK_TYPE_NONE is the terminator sentinel for the callback registration
	// array — per cfapi.h it is (CF_CALLBACK_TYPE)MAXUINT. The Cloud Files API walks
	// the array until it hits this value; any other terminator causes an over-read.
	cfCallbackTypeNone uint32 = 0xFFFFFFFF
	cfConnectFlagNone  uint32 = 0
)

var (
	cldapiDLL                = syscall.NewLazyDLL("cldapi.dll")
	procCfRegisterSyncRoot   = cldapiDLL.NewProc("CfRegisterSyncRoot")
	procCfUnregisterSyncRoot = cldapiDLL.NewProc("CfUnregisterSyncRoot")
	procCfConnectSyncRoot    = cldapiDLL.NewProc("CfConnectSyncRoot")
	procCfDisconnectSyncRoot = cldapiDLL.NewProc("CfDisconnectSyncRoot")
)

// No-op fetch-placeholder callback. Signature matches CF_CALLBACK contract but
// we never do anything when it fires — real BlueHammer synchronizes with
// events here; we just need to PROVE we registered one.
func fetchPlaceholdersCallback(info uintptr, params uintptr) uintptr {
	LogMessage("INFO", TECHNIQUE_ID, "CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS callback fired (no-op)")
	return 0
}

// ==============================================================================
// MAIN
// ==============================================================================

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique errored: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique errored: %v", err))
		exitCode := classifyError(err)
		if exitCode == StageBlocked || exitCode == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] All primitives exercised\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "All observable primitives exercised without prevention")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Cloud Files sync-root + fetch-placeholder callback + EICAR drop completed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Sandbox directory under ARTIFACT_DIR — NOT whitelisted, detectable by EDR
	sandboxDir := filepath.Join(ARTIFACT_DIR, "BlueHammerSandbox", "cfapi-root")
	if err := os.MkdirAll(sandboxDir, 0755); err != nil {
		return fmt.Errorf("create sandbox directory: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Sandbox directory: %s", sandboxDir))

	syncRootUTF16, err := syscall.UTF16PtrFromString(sandboxDir)
	if err != nil {
		return fmt.Errorf("utf16 sandbox path: %v", err)
	}

	providerName, _ := syscall.UTF16PtrFromString("F0RT1KA-BLUEHAMMER-SIM")
	providerVersion, _ := syscall.UTF16PtrFromString("1.0")

	reg := cfSyncRegistration{
		StructSize:      uint32(unsafe.Sizeof(cfSyncRegistration{})),
		ProviderName:    providerName,
		ProviderVersion: providerVersion,
	}

	policies := cfSyncPolicies{
		StructSize: uint32(unsafe.Sizeof(cfSyncPolicies{})),
		HardLink:   cfHardLinkPolicyAllowed,
		Hydration: cfHydrationPolicy{
			Primary:  cfHydrationPolicyPartial,
			Modifier: cfHydrationPolicyModifierValidationRequired,
		},
		PlaceholderManagement: cfPlaceholderManagementPolicyDefault,
		InSync:                cfInSyncPolicyNone,
	}

	// Step 1: CfRegisterSyncRoot
	LogMessage("INFO", TECHNIQUE_ID, "Calling CfRegisterSyncRoot with non-standard provider name")
	hr, _, _ := procCfRegisterSyncRoot.Call(
		uintptr(unsafe.Pointer(syncRootUTF16)),
		uintptr(unsafe.Pointer(&reg)),
		uintptr(unsafe.Pointer(&policies)),
		uintptr(cfRegisterFlagNone),
	)
	if hr != 0 {
		// Non-zero HRESULT — describe the operation, NOT the cause (bug-prevention rule #1)
		return fmt.Errorf("CfRegisterSyncRoot returned HRESULT 0x%08x", uint32(hr))
	}
	LogMessage("SUCCESS", TECHNIQUE_ID, "CfRegisterSyncRoot succeeded")
	syncRootRegistered := true

	// Defer cleanup — always unregister so sandbox state is deterministic.
	defer func() {
		if syncRootRegistered {
			procCfUnregisterSyncRoot.Call(uintptr(unsafe.Pointer(syncRootUTF16)))
			LogMessage("INFO", TECHNIQUE_ID, "CfUnregisterSyncRoot called (cleanup)")
		}
		// Best-effort sandbox cleanup
		os.RemoveAll(filepath.Join(ARTIFACT_DIR, "BlueHammerSandbox", "cfapi-root"))
	}()

	// Step 2: CfConnectSyncRoot with fetch-placeholder callback
	callbacks := [2]cfCallbackRegistration{
		{Type: cfCallbackTypeFetchPlaceholders, Callback: syscall.NewCallback(fetchPlaceholdersCallback)},
		{Type: cfCallbackTypeNone, Callback: 0},
	}
	var cfKey uint64

	LogMessage("INFO", TECHNIQUE_ID, "Calling CfConnectSyncRoot with CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS")
	hr, _, _ = procCfConnectSyncRoot.Call(
		uintptr(unsafe.Pointer(syncRootUTF16)),
		uintptr(unsafe.Pointer(&callbacks[0])),
		0,
		uintptr(cfConnectFlagNone),
		uintptr(unsafe.Pointer(&cfKey)),
	)
	if hr != 0 {
		// Describe the operation only
		return fmt.Errorf("CfConnectSyncRoot returned HRESULT 0x%08x", uint32(hr))
	}
	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("CfConnectSyncRoot succeeded (key=0x%x)", cfKey))
	connected := true
	defer func() {
		if connected {
			procCfDisconnectSyncRoot.Call(uintptr(cfKey))
			LogMessage("INFO", TECHNIQUE_ID, "CfDisconnectSyncRoot called (cleanup)")
		}
	}()

	// Step 3: Drop EICAR in the sandbox directory. Forward-direction drop — EDR
	// should scan the file. The filename intentionally references "Mimikatz" so
	// path/filename string-matching detection rules fire in addition to AMSI/AV
	// content matching. This is a v2 Identifier-Fidelity lift (B2) — the file
	// CONTENT is still EICAR (benign AV signal), only the NAME suggests Mimikatz.
	eicarPath := filepath.Join(sandboxDir, "Mimikatz_dump_Win32_signature.txt")
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Dropping EICAR-content probe with Mimikatz-suggestive filename to %s", eicarPath))
	if err := os.WriteFile(eicarPath, eicarString, 0644); err != nil {
		return fmt.Errorf("write EICAR probe file: %v", err)
	}
	LogFileDropped("Mimikatz_dump_Win32_signature.txt", eicarPath, int64(len(eicarString)), false)

	// Give AV a small window to react — we do not wait on the callback like
	// BlueHammer does (which would require full oplock machinery). This is a
	// measurement test, not a freeze.
	time.Sleep(3 * time.Second)

	// Quarantine check via os.Stat (bug-prevention rule #3)
	if _, statErr := os.Stat(eicarPath); statErr != nil {
		LogMessage("INFO", TECHNIQUE_ID, "Mimikatz-named EICAR probe quarantined/removed by AV — expected protection signal")
		// NOTE: we treat this as SUCCESS at the technique level — the primitive
		// (drop-in-sandbox) ran. AV action on EICAR is ordinary behavior; the
		// test framework exit code at orchestrator level will reflect overall
		// EDR posture across all three stages.
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "EICAR probe not quarantined")
	}

	// Quick tree probe — run `cmd /c dir <sandbox>` to surface a listing event
	// in telemetry. Purely observable, no logic branching.
	out, _ := exec.Command("cmd", "/C", "dir", sandboxDir).CombinedOutput()
	LogMessage("DEBUG", TECHNIQUE_ID, fmt.Sprintf("dir output len=%d", len(out)))

	return nil
}

// classifyError — no blame keywords (bug-prevention rule #1)
func classifyError(err error) int {
	if err == nil {
		return StageSuccess
	}
	s := err.Error()
	// Only the most surgical blocking signals — HRESULTs from cldapi mapped to
	// tamper-protection denials. We do NOT match on "denied"/"blocked" in
	// generic wrappers; we describe operations above, not causes.
	if has(s, "HRESULT 0x80070005") { // E_ACCESSDENIED
		return StageBlocked
	}
	if has(s, "HRESULT 0x800704C7") { // ERROR_CANCELLED
		return StageBlocked
	}
	return StageError
}

func has(s, sub string) bool {
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

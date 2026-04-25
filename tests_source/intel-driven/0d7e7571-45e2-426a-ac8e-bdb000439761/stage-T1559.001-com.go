//go:build windows
// +build windows

// Stage 4: COM Activation telemetry against a Cloud Files broker CLSID (T1559.001) — v2 lift R5
//
// Behavior exercised (OBSERVABLE PRIMITIVES ONLY):
//   - sc.exe / Win32_Service query of TieringEngineService state (PRE-CHECK)
//   - CoInitializeEx + CoCreateInstance against the CFAPI namespace broker CLSID
//     {829BD7DA-5F60-4B8B-A82C-C7B4DF0E2DB8} (Cloud Files Sync Root Manager)
//
// SAFETY GUARANTEES (Tier 1 v2 gate):
//   - HARD pre-check: if TieringEngineService is RUNNING, the CoCreateInstance
//     activation is SKIPPED. We refuse to drive service-start behavior against
//     an already-running broker. This prevents inadvertent activation of a
//     production service.
//   - When the service is STOPPED, CoCreateInstance returns CO_E_SERVER_EXEC_FAILURE
//     because there is no active server. The activation event itself is the
//     telemetry we care about — the service does NOT actually start because
//     out-of-process COM activation against a CLSID with no LocalServer32
//     registration in a state where the service is intentionally stopped does
//     not auto-start the service in normal Windows behavior. (We additionally
//     verify the post-activation service state and log a warning if it changed.)
//   - CoUninitialize is called in defer regardless of activation outcome.
//   - No service start/stop is ever attempted by this stage.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	TEST_UUID      = "0d7e7571-45e2-426a-ac8e-bdb000439761"
	TECHNIQUE_ID   = "T1559.001"
	TECHNIQUE_NAME = "COM Activation telemetry vs Cloud Files broker (sandbox-safe)"
	STAGE_ID       = 4
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// CFAPI Cloud Files Sync Root Manager CLSID — well-known broker class registered
// by cldapi. Used by the real RedSun PoC for COM activation telemetry surface.
var clsidSyncRootManager = guid{
	Data1: 0x829BD7DA, Data2: 0x5F60, Data3: 0x4B8B,
	Data4: [8]byte{0xA8, 0x2C, 0xC7, 0xB4, 0xDF, 0x0E, 0x2D, 0xB8},
}

// IID_IUnknown — the most permissive interface request, sufficient for the
// activation telemetry signal.
var iidIUnknown = guid{
	Data1: 0x00000000, Data2: 0x0000, Data3: 0x0000,
	Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
}

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

const (
	clsctxLocalServer   = 0x4
	coinitMultithreaded = 0x0
)

var (
	ole32                = syscall.NewLazyDLL("ole32.dll")
	procCoInitializeEx   = ole32.NewProc("CoInitializeEx")
	procCoUninitialize   = ole32.NewProc("CoUninitialize")
	procCoCreateInstance = ole32.NewProc("CoCreateInstance")
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, "Starting COM activation telemetry stage (TieringEngineService pre-check + CFAPI broker activation)")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Pre-check TieringEngineService state, then CoCreateInstance(CFAPI broker CLSID) — activation telemetry only")

	// SAFETY PRE-CHECK: query TieringEngineService state. If running, abort.
	state, queryErr := queryServiceState("TieringEngineService")
	if queryErr != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("TieringEngineService state query failed: %v — aborting safely (will not activate)", queryErr))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "service state unknown — pre-check guard tripped, activation skipped")
		os.Exit(StageSuccess)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("TieringEngineService state: %s", state))

	if state != "STOPPED" {
		// Pre-check guard. If anything other than STOPPED — RUNNING, START_PENDING,
		// CONTINUE_PENDING, etc. — refuse to activate. Telemetry value of stage
		// is still the pre-check + state query.
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("TieringEngineService is %s (not STOPPED) — pre-check guard tripped, CoCreateInstance SKIPPED", state))
		fmt.Printf("[STAGE %s] Pre-check guard: service state %s — activation skipped\n", TECHNIQUE_ID, state)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", fmt.Sprintf("Pre-check skipped activation (service state: %s)", state))
		os.Exit(StageSuccess)
	}

	// Service is STOPPED — proceed with activation telemetry.
	exitCode := performComActivation()

	// Post-activation safety check: if the service is no longer STOPPED, log a
	// warning. The activation should NOT have started the service.
	if postState, postErr := queryServiceState("TieringEngineService"); postErr == nil && postState != "STOPPED" {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("UNEXPECTED: TieringEngineService state changed to %s after CoCreateInstance — activation triggered service start. This is a safety regression; investigate.", postState))
	}

	switch exitCode {
	case StageBlocked:
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "CoCreateInstance returned ACCESS_DENIED — likely EDR / policy")
	case StageError:
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "COM activation errored — see logs")
	default:
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "COM activation telemetry signal exercised against CFAPI broker CLSID")
	}
	os.Exit(exitCode)
}

// queryServiceState wraps `sc.exe query <name>` and returns the STATE token
// (RUNNING, STOPPED, START_PENDING, etc.) or an error.
func queryServiceState(name string) (string, error) {
	cmd := exec.Command("sc.exe", "query", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// sc.exe returns nonzero if the service doesn't exist. Treat as unknown.
		return "", fmt.Errorf("sc query %s: %v (%s)", name, err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "STATE") {
			continue
		}
		// Format: "STATE              : 1  STOPPED" or "STATE              : 4  RUNNING"
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			return strings.TrimSpace(fields[3]), nil
		}
	}
	return "UNKNOWN", nil
}

// performComActivation executes CoInitializeEx + CoCreateInstance against
// the CFAPI broker CLSID. The activation is the telemetry signal — we don't
// care about the returned interface pointer (we expect failure when the
// broker service is stopped).
func performComActivation() int {
	// CoInitializeEx(NULL, COINIT_MULTITHREADED). Return value S_OK (0) or
	// S_FALSE (1) is fine; anything else is a setup error.
	hr, _, _ := procCoInitializeEx.Call(0, uintptr(coinitMultithreaded))
	if hr != 0 && hr != 1 {
		// 0x80010106 (RPC_E_CHANGED_MODE) is benign — apartment already entered.
		if uint32(hr) != 0x80010106 {
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("CoInitializeEx HRESULT=0x%08X", uint32(hr)))
			return StageError
		}
	}
	defer procCoUninitialize.Call()

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Calling CoCreateInstance(CLSID=%s, CLSCTX_LOCAL_SERVER, IID_IUnknown) — CFAPI broker activation telemetry",
		guidToString(clsidSyncRootManager)))

	var ppv uintptr
	startedAt := time.Now()
	hr, _, _ = procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidSyncRootManager)),
		0, // pUnkOuter
		uintptr(clsctxLocalServer),
		uintptr(unsafe.Pointer(&iidIUnknown)),
		uintptr(unsafe.Pointer(&ppv)),
	)
	elapsed := time.Since(startedAt)

	hrCode := uint32(hr)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("CoCreateInstance returned HRESULT=0x%08X in %v", hrCode, elapsed))

	switch hrCode {
	case 0x00000000: // S_OK — activation actually succeeded (uncommon for a stopped service)
		LogMessage("WARN", TECHNIQUE_ID, "CoCreateInstance succeeded — broker activated. Releasing interface pointer.")
		// Best-effort release: call the IUnknown::Release through the vtable.
		if ppv != 0 {
			vtable := *(**[3]uintptr)(unsafe.Pointer(&ppv))
			if vtable != nil {
				releaseProc := vtable[2] // IUnknown::Release at offset 2
				syscall.SyscallN(releaseProc, ppv)
			}
		}
		return StageSuccess
	case 0x80004005: // E_FAIL
		LogMessage("INFO", TECHNIQUE_ID, "CoCreateInstance returned E_FAIL — expected when broker service is stopped (telemetry recorded)")
		return StageSuccess
	case 0x80080005: // CO_E_SERVER_EXEC_FAILURE
		LogMessage("INFO", TECHNIQUE_ID, "CoCreateInstance returned CO_E_SERVER_EXEC_FAILURE — expected when broker service is stopped (telemetry recorded)")
		return StageSuccess
	case 0x80070005: // E_ACCESSDENIED
		LogMessage("INFO", TECHNIQUE_ID, "CoCreateInstance returned E_ACCESSDENIED — likely blocked by EDR or COM ACL")
		return StageBlocked
	default:
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("CoCreateInstance returned unexpected HRESULT 0x%08X — telemetry recorded", hrCode))
		return StageSuccess
	}
}

func guidToString(g guid) string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

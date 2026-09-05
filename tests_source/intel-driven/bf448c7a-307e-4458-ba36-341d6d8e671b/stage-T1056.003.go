//go:build windows
// +build windows

/*
STAGE 5: Overlay + Browser Address-Bar Monitoring (T1056.003 + T1010 + T1185)

Simulates TclBanker's WPF full-screen overlay fraud + UI Automation polling.
Real TclBanker:
  - Enumerates foreground windows looking for browser address bars
    (T1010 — Application Window Discovery, T1185 — Browser Session Hijacking)
  - Uses UI Automation (COM, CLSID 0FF48D70-A93E-4D24-9E18-7C6F4F764BF7) to
    read text out of address-bar controls and check for Brazilian banking domains
  - Spawns WPF overlay windows showing fake credential dialogs, fake Windows
    Update, or vishing wait screens with Portuguese strings like
    "Estamos entrando em contato" (we're getting in touch)
  - Installs SetWindowsHookExW WH_KEYBOARD_LL for keystroke capture
    (T1056.003 — Input Capture: Web Portal Capture)

Sandbox version:
  - Brief overlay window (3-second auto-dismiss) watermarked "F0RT1KA TEST"
  - WDA_EXCLUDEFROMCAPTURE set so the overlay can't be screenshot
  - Real CoCreateInstance(CUIAutomation) — produces UI Automation telemetry
  - Real SetWindowsHookExW WH_KEYBOARD_LL installed for <500ms then explicitly
    UnhookWindowsHookEx — keystroke data NEVER persisted
  - Portuguese vishing string logged for detection fidelity

SAFETY:
  - Overlay watermarked "F0RT1KA TEST" and auto-dismisses in 3s max
  - Overlay is never modal, never blocks input
  - Keyboard hook installed for <500ms, unconditionally uninstalled
  - No keystrokes are recorded, logged, or persisted — the hook callback is a no-op
*/

package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	TEST_UUID      = "bf448c7a-307e-4458-ba36-341d6d8e671b"
	TECHNIQUE_ID   = "T1056.003"
	TECHNIQUE_NAME = "Web Portal Capture: Overlay + Browser Monitoring (TclBanker)"
	STAGE_ID       = 5
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Real TclBanker identifiers
const (
	PortugueseVishingString = "Estamos entrando em contato"
	OverlayWatermark        = "F0RT1KA TEST — TclBanker simulation"
	OverlayTimeoutSec       = 3
	KeyboardHookDurationMs  = 400                                      // < 500ms per safety contract
	CUIAutomationCLSID      = "{FF48DBA4-60EF-4201-AA87-54103EEF594E}" // CLSID_CUIAutomation
)

// Keystroke counter — atomic so we can confirm the hook fired without storing keys
var keystrokesObserved int64

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, "Starting overlay + browser-monitoring simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "WPF overlay + UI Automation address-bar polling")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))
		exitCode := determineExitCode(err)
		if exitCode == StageBlocked || exitCode == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] Overlay + UI Automation + keyboard hook completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Overlay + browser-monitoring telemetry produced")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Overlay/UIA/keyboard-hook simulation complete")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// =========================================================================
	// Part A: Foreground window enumeration (T1010 — Application Window Discovery)
	// =========================================================================
	LogMessage("INFO", TECHNIQUE_ID, "Phase A: foreground/visible window enumeration")

	user32 := syscall.NewLazyDLL("user32.dll")
	getForegroundWindow := user32.NewProc("GetForegroundWindow")
	getWindowTextW := user32.NewProc("GetWindowTextW")
	getWindowThreadProcessId := user32.NewProc("GetWindowThreadProcessId")

	fgHwnd, _, _ := getForegroundWindow.Call()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("GetForegroundWindow HWND=0x%x", fgHwnd))

	if fgHwnd != 0 {
		// Read window title
		var titleBuf [512]uint16
		getWindowTextW.Call(fgHwnd, uintptr(unsafe.Pointer(&titleBuf[0])), 512)
		title := syscall.UTF16ToString(titleBuf[:])

		var pid uint32
		getWindowThreadProcessId.Call(fgHwnd, uintptr(unsafe.Pointer(&pid)))

		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("Foreground window: HWND=0x%x PID=%d Title=%q", fgHwnd, pid, title))
		LogMessage("INFO", TECHNIQUE_ID,
			"TclBanker checks this against browser process names (chrome.exe, msedge.exe, firefox.exe, brave.exe)")
	}

	// =========================================================================
	// Part B: UI Automation COM instantiation (T1185 — Browser Session Hijacking)
	// =========================================================================
	LogMessage("INFO", TECHNIQUE_ID, "Phase B: UI Automation CoCreateInstance for address-bar enumeration")

	if err := comInit(); err != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("CoInitializeEx failed: %v", err))
	} else {
		defer comUninit()

		if err := comCreateUIAutomation(); err != nil {
			LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("CoCreateInstance(CUIAutomation) failed: %v", err))
		} else {
			LogMessage("INFO", TECHNIQUE_ID,
				fmt.Sprintf("CoCreateInstance(CUIAutomation %s) succeeded — IUIAutomation obtained", CUIAutomationCLSID))
			LogMessage("INFO", TECHNIQUE_ID,
				"TclBanker uses IUIAutomation::ElementFromHandle + GetCurrentPropertyValue(UIA_ValueValuePropertyId) to read address-bar URL")
			LogMessage("INFO", TECHNIQUE_ID,
				"Target indicator strings: bb.com.br, itau.com.br, bradesco.com.br, santander.com.br, caixa.gov.br (Brazilian banking)")
		}
	}

	// =========================================================================
	// Part C: Overlay window (3s auto-dismiss)
	// =========================================================================
	LogMessage("INFO", TECHNIQUE_ID, "Phase C: overlay window (auto-dismiss in 3s, WDA_EXCLUDEFROMCAPTURE)")
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Watermark: %q", OverlayWatermark))
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Portuguese vishing string (detection fidelity): %q", PortugueseVishingString))

	if err := showOverlayWindow(); err != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Overlay window failed: %v", err))
		// Not fatal — continue to keyboard hook test
	}

	// =========================================================================
	// Part D: Keyboard hook (<500ms, no key data persisted)
	// =========================================================================
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Phase D: SetWindowsHookExW WH_KEYBOARD_LL for %dms (no keys logged)", KeyboardHookDurationMs))

	hookErr := installKeyboardHook(KeyboardHookDurationMs)
	if hookErr != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Keyboard hook install failed: %v", hookErr))
	} else {
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("Keyboard hook installed + uninstalled; %d events observed (no data captured)",
				atomic.LoadInt64(&keystrokesObserved)))
	}

	LogMessage("INFO", TECHNIQUE_ID, "Overlay + browser-monitoring simulation complete")
	return nil
}

// =============================================================================
// COM helpers
// =============================================================================

var (
	ole32        = syscall.NewLazyDLL("ole32.dll")
	procCoInit   = ole32.NewProc("CoInitializeEx")
	procCoUninit = ole32.NewProc("CoUninitialize")
	procCoCreate = ole32.NewProc("CoCreateInstance")
	procCLSIDStr = ole32.NewProc("CLSIDFromString")
	procIIDStr   = ole32.NewProc("IIDFromString")
)

const (
	COINIT_APARTMENTTHREADED = 0x2
	CLSCTX_INPROC_SERVER     = 0x1
)

var iidIUnknownStr = "{00000000-0000-0000-C000-000000000046}"

func comInit() error {
	r, _, _ := procCoInit.Call(0, COINIT_APARTMENTTHREADED)
	if r != 0 && r != 1 {
		return fmt.Errorf("CoInitializeEx returned 0x%x", r)
	}
	return nil
}

func comUninit() {
	procCoUninit.Call()
}

func comCreateUIAutomation() error {
	var clsid [16]byte
	var iid [16]byte
	clsidUtf16, _ := syscall.UTF16PtrFromString(CUIAutomationCLSID)
	iidUtf16, _ := syscall.UTF16PtrFromString(iidIUnknownStr)

	r, _, _ := procCLSIDStr.Call(uintptr(unsafe.Pointer(clsidUtf16)), uintptr(unsafe.Pointer(&clsid[0])))
	if r != 0 {
		return fmt.Errorf("CLSIDFromString returned 0x%x", r)
	}
	r, _, _ = procIIDStr.Call(uintptr(unsafe.Pointer(iidUtf16)), uintptr(unsafe.Pointer(&iid[0])))
	if r != 0 {
		return fmt.Errorf("IIDFromString returned 0x%x", r)
	}

	var ppv uintptr
	r, _, _ = procCoCreate.Call(
		uintptr(unsafe.Pointer(&clsid[0])),
		0,
		CLSCTX_INPROC_SERVER,
		uintptr(unsafe.Pointer(&iid[0])),
		uintptr(unsafe.Pointer(&ppv)),
	)
	if r != 0 {
		return fmt.Errorf("CoCreateInstance returned 0x%x", r)
	}
	if ppv != 0 {
		releaseProc := *(*uintptr)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(ppv)) + 2*unsafe.Sizeof(uintptr(0))))
		syscall.SyscallN(releaseProc, ppv)
	}
	return nil
}

// =============================================================================
// Overlay window
// =============================================================================

var (
	user32                    = syscall.NewLazyDLL("user32.dll")
	procCreateWindowExW       = user32.NewProc("CreateWindowExW")
	procShowWindow            = user32.NewProc("ShowWindow")
	procDestroyWindow         = user32.NewProc("DestroyWindow")
	procSetWindowDispAffinity = user32.NewProc("SetWindowDisplayAffinity")
	procRegisterClassW        = user32.NewProc("RegisterClassW")
	procDefWindowProcW        = user32.NewProc("DefWindowProcW")
	procPostQuitMessage       = user32.NewProc("PostQuitMessage")
)

const (
	WS_POPUP               = 0x80000000
	WS_VISIBLE             = 0x10000000
	WS_EX_TOPMOST          = 0x00000008
	WS_EX_TOOLWINDOW       = 0x00000080
	SW_SHOW                = 5
	SW_HIDE                = 0
	WDA_EXCLUDEFROMCAPTURE = 0x11
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

func showOverlayWindow() error {
	// Use a pre-registered window class (STATIC) to avoid having to write a
	// full message-pump in Go. We just need the HWND to exist briefly so
	// telemetry sees a window created. SetWindowDisplayAffinity then opts it
	// out of screen capture — the WDA_EXCLUDEFROMCAPTURE flag is the exact
	// API TclBanker overlays use to prevent analysts from screenshotting.
	className, _ := syscall.UTF16PtrFromString("STATIC")
	windowTitle, _ := syscall.UTF16PtrFromString(OverlayWatermark + " — " + PortugueseVishingString)

	hwnd, _, lerr := procCreateWindowExW.Call(
		WS_EX_TOPMOST|WS_EX_TOOLWINDOW,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowTitle)),
		WS_POPUP|WS_VISIBLE,
		100, 100, 400, 80, // tiny, off-corner, non-blocking
		0, 0, 0, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW failed: %v", lerr)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Overlay window created HWND=0x%x", hwnd))

	// Apply WDA_EXCLUDEFROMCAPTURE — the screen-capture-prevention flag
	r, _, _ := procSetWindowDispAffinity.Call(hwnd, WDA_EXCLUDEFROMCAPTURE)
	if r != 0 {
		LogMessage("INFO", TECHNIQUE_ID, "WDA_EXCLUDEFROMCAPTURE applied — overlay hidden from screen capture")
	}

	// Sleep for the auto-dismiss timeout
	time.Sleep(time.Duration(OverlayTimeoutSec) * time.Second)

	procDestroyWindow.Call(hwnd)
	LogMessage("INFO", TECHNIQUE_ID, "Overlay window destroyed (auto-dismiss)")
	return nil
}

// =============================================================================
// Keyboard hook (no-data-capture variant)
// =============================================================================

var (
	procSetWindowsHookExW   = user32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx = user32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx      = user32.NewProc("CallNextHookEx")
)

const WH_KEYBOARD_LL = 13

// Hook callback — counts events only, NEVER inspects key data
func hookCallback(nCode int32, wParam uintptr, lParam uintptr) uintptr {
	if nCode >= 0 {
		atomic.AddInt64(&keystrokesObserved, 1)
		// CRITICAL: We DO NOT read the KBDLLHOOKSTRUCT — no key data captured
	}
	r, _, _ := procCallNextHookEx.Call(0, uintptr(nCode), wParam, lParam)
	return r
}

func installKeyboardHook(durationMs int) error {
	cb := syscall.NewCallback(hookCallback)
	hook, _, lerr := procSetWindowsHookExW.Call(WH_KEYBOARD_LL, cb, 0, 0)
	if hook == 0 {
		return fmt.Errorf("SetWindowsHookExW failed: %v", lerr)
	}
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("WH_KEYBOARD_LL hook installed (HHOOK=0x%x) — no-data-capture variant", hook))

	// Hold the hook briefly. Note: a low-level keyboard hook needs a message
	// pump on the installing thread to actually fire. We don't pump messages
	// here — the SetWindowsHookExW call itself is what produces the EDR
	// telemetry, which is the only thing we need for detection fidelity.
	time.Sleep(time.Duration(durationMs) * time.Millisecond)

	procUnhookWindowsHookEx.Call(hook)
	LogMessage("INFO", TECHNIQUE_ID, "UnhookWindowsHookEx called — hook removed")
	return nil
}

// =============================================================================
// Helpers
// =============================================================================

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
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

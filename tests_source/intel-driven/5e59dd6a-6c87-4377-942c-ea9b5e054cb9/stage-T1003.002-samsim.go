//go:build windows
// +build windows

// Stage 4: SAM Hive Simulation (T1003.002) — v2 lifts B4 + B5
//
// Behavior exercised (OBSERVABLE PRIMITIVES ONLY):
//   Part A (B4) — Privilege manipulation telemetry:
//     - OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY)
//     - LookupPrivilegeValueW("SeBackupPrivilege")
//     - AdjustTokenPrivileges(SeBackupPrivilege, ENABLED)
//     - LookupPrivilegeValueW("SeRestorePrivilege")
//     - AdjustTokenPrivileges(SeRestorePrivilege, ENABLED)
//   Part B (B5) — RegLoadKey / RegOpenKeyEx on a SYNTHETIC SAM-NAMED hive:
//     - Only proceeds if SeRestorePrivilege was actually enabled (Admin only).
//     - Creates a temporary sandbox key under HKLM\SOFTWARE\F0_BLUEHAMMER_TEMP
//     - RegSaveKey() that key to a sandbox file at ARTIFACT_DIR\sam-sim.hiv
//     - RegLoadKey(HKLM, "F0_BLUEHAMMER_SAMSIM", sandbox-file) — loads the sandbox file
//       AS IF it were a hive. Mount name is intentionally unique to this test
//       and contains "BLUEHAMMER" so it is unmistakably attributable in
//       telemetry.
//     - RegOpenKeyEx(HKLM\F0_BLUEHAMMER_SAMSIM, KEY_READ) — this is the
//       SAM-hive-read API signature that BlueHammer's PoC produces.
//     - RegCloseKey, RegUnLoadKey, cleanup — every step has defer-driven
//       teardown. Watchdog goroutine force-unloads on panic/timeout.
//
// SAFETY GUARANTEES (Tier 1 v2 gate):
//   - NO real SAM hive is ever opened. The hive loaded under
//     HKLM\F0_BLUEHAMMER_SAMSIM is a SYNTHETIC sandbox file we created.
//   - The temp HKLM key (F0_BLUEHAMMER_TEMP) is removed in defer.
//   - The mount name F0_BLUEHAMMER_SAMSIM is unloaded in defer.
//   - A 30-second watchdog goroutine force-unloads the mount if the stage
//     hangs or panics between RegLoadKey and RegUnLoadKey.
//   - Standard-user execution short-circuits at Part A: AdjustTokenPrivileges
//     fails with ERROR_NOT_ALL_ASSIGNED, the privilege-denial signal is
//     logged, and Part B is skipped. The test still scores B4 telemetry.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID      = "5e59dd6a-6c87-4377-942c-ea9b5e054cb9"
	TECHNIQUE_ID   = "T1003.002"
	TECHNIQUE_NAME = "Synthetic SAM Hive Load + Read (sandbox-only)"
	STAGE_ID       = 4
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Mount name and temp key are intentionally unique to this test so they are
// trivially attributable in telemetry and cannot collide with real Windows
// keys. The "F0_BLUEHAMMER" prefix makes incident response easy.
const (
	tempKeyPath        = `SOFTWARE\F0_BLUEHAMMER_SAMSIM_TEMP`
	loadedHiveSubkey   = "F0_BLUEHAMMER_SAMSIM"
	hiveFileName       = "sam-sim.hiv"
	watchdogTimeout    = 30 * time.Second
	stageBudgetTimeout = 60 * time.Second
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	// Stage budget watchdog — independent of the load-key watchdog. Enforces
	// the overall stage time budget; if the stage hangs anywhere it'll exit
	// with an error code rather than block the orchestrator.
	stageDone := make(chan struct{})
	go func() {
		select {
		case <-stageDone:
			return
		case <-time.After(stageBudgetTimeout):
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Stage budget %v exceeded — emergency exit", stageBudgetTimeout))
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "stage budget exceeded")
			os.Exit(StageError)
		}
	}()
	defer close(stageDone)

	// Part A — Privilege manipulation telemetry. Always runs.
	backupEnabled := tryEnablePrivilege("SeBackupPrivilege")
	restoreEnabled := tryEnablePrivilege("SeRestorePrivilege")

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Privilege enable telemetry — SeBackupPrivilege=%v, SeRestorePrivilege=%v", backupEnabled, restoreEnabled))

	if !restoreEnabled {
		// Standard-user / non-admin path. Privilege-denial telemetry recorded.
		// Part B is skipped — we don't have RegLoadKey rights.
		LogMessage("INFO", TECHNIQUE_ID, "SeRestorePrivilege not granted (standard user or denied) — skipping hive-load primitive. Privilege-denial telemetry signal recorded as the value of this stage.")
		fmt.Printf("[STAGE %s] Privilege-enable telemetry recorded; hive-load skipped (no SeRestorePrivilege)\n", TECHNIQUE_ID)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "B4 telemetry recorded; B5 skipped without elevation")
		os.Exit(StageSuccess)
	}

	// Part B — Synthetic hive load + read. Only reached if elevated.
	exitCode := executeHiveSimulation()

	if exitCode == StageBlocked {
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "RegLoadKey or RegOpenKey blocked by EDR")
	} else if exitCode == StageError {
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "hive simulation errored — see logs")
	} else {
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "synthetic SAM-hive load + read primitives exercised")
	}
	os.Exit(exitCode)
}

// tryEnablePrivilege calls AdjustTokenPrivileges to enable a named privilege
// on the current process token. Returns true if the OS reports the privilege
// was successfully enabled. A "false" return is normal for non-admin contexts
// and produces ERROR_NOT_ALL_ASSIGNED — that's the privilege-denial telemetry
// signal we want.
func tryEnablePrivilege(name string) bool {
	var token windows.Token
	hProc, err := windows.GetCurrentProcess()
	if err != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("GetCurrentProcess failed: %v", err))
		return false
	}
	if err := windows.OpenProcessToken(hProc, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("OpenProcessToken failed: %v", err))
		return false
	}
	defer token.Close()

	var luid windows.LUID
	pName, _ := syscall.UTF16PtrFromString(name)
	if err := windows.LookupPrivilegeValue(nil, pName, &luid); err != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("LookupPrivilegeValue(%s) failed: %v", name, err))
		return false
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

	// AdjustTokenPrivileges returns success even when the privilege was not
	// actually enabled — the real signal is GetLastError() == ERROR_NOT_ALL_ASSIGNED.
	err = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	if err == nil {
		// Cleanly enabled.
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("AdjustTokenPrivileges(%s) succeeded — privilege enabled", name))
		return true
	}
	// ERROR_NOT_ALL_ASSIGNED == 1300 — the privilege was not granted. This is
	// the explicit denial telemetry signal.
	if err == windows.ERROR_NOT_ALL_ASSIGNED {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("AdjustTokenPrivileges(%s) reported ERROR_NOT_ALL_ASSIGNED — OS denied privilege (expected for standard user)", name))
		return false
	}
	LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("AdjustTokenPrivileges(%s) failed: %v", name, err))
	return false
}

// executeHiveSimulation builds a synthetic sandbox key, saves it as a hive,
// loads the hive under a unique mount name, and reads from it. Cleanup is
// defer-driven; a watchdog goroutine force-unloads on timeout/panic.
func executeHiveSimulation() int {
	// Step 1: ensure ARTIFACT_DIR exists for the hive file.
	if err := os.MkdirAll(ARTIFACT_DIR, 0755); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("MkdirAll(%s) failed: %v", ARTIFACT_DIR, err))
		return StageError
	}
	hivePath := filepath.Join(ARTIFACT_DIR, hiveFileName)

	// Step 2: create the synthetic sandbox key under HKLM\SOFTWARE.
	tempKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, tempKeyPath, registry.ALL_ACCESS)
	if err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("CreateKey(%s) failed: %v", tempKeyPath, err))
		return StageError
	}
	defer func() {
		_ = tempKey.Close()
		// Best-effort temp-key removal. registry.DeleteKey requires the key
		// to be empty — we only ever wrote to a single value, so this should
		// succeed.
		_ = tempKey.DeleteValue("SAM_SIM_MARKER")
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, tempKeyPath)
		LogMessage("INFO", TECHNIQUE_ID, "Cleanup: temp HKLM key removed")
	}()

	if err := tempKey.SetStringValue("SAM_SIM_MARKER", "F0RT1KA-BlueHammer-SAM-simulation-sandbox-only"); err != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("SetStringValue marker failed (non-fatal): %v", err))
	}

	// Step 3: RegSaveKey() that key to the sandbox hive file. Remove any
	// previous file first because RegSaveKey will not overwrite.
	_ = os.Remove(hivePath)
	if err := saveKeyAsHive(tempKey, hivePath); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("RegSaveKey(%s) failed: %v", hivePath, err))
		return StageError
	}
	LogFileDropped(hiveFileName, hivePath, fileSize(hivePath), false)

	defer func() {
		if err := os.Remove(hivePath); err != nil && !os.IsNotExist(err) {
			LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Cleanup: hive file remove failed: %v", err))
		} else {
			LogMessage("INFO", TECHNIQUE_ID, "Cleanup: sandbox hive file removed")
		}
	}()

	// Step 4: load the sandbox hive under a unique mount name. Watchdog
	// guarantees unload even on panic / hang in the read step.
	pSubkey, _ := syscall.UTF16PtrFromString(loadedHiveSubkey)
	pHive, _ := syscall.UTF16PtrFromString(hivePath)

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("RegLoadKey(HKLM, %s, %s) — loading synthetic sandbox hive (BlueHammer SAM-load signature)", loadedHiveSubkey, hivePath))
	if err := regLoadKey(windows.HKEY_LOCAL_MACHINE, pSubkey, pHive); err != nil {
		// RegLoadKey can be denied by EDR — this is a legitimate detection
		// signal. Treat ACCESS_DENIED as a block, anything else as an error.
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_ACCESS_DENIED {
			LogMessage("INFO", TECHNIQUE_ID, "RegLoadKey blocked: ERROR_ACCESS_DENIED (likely EDR / policy)")
			return StageBlocked
		}
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("RegLoadKey failed: %v", err))
		return StageError
	}

	// Watchdog: force-unloads the hive if Part B's read step hangs or panics.
	loaded := int32(1)
	watchdogStop := make(chan struct{})
	go func() {
		select {
		case <-watchdogStop:
			return
		case <-time.After(watchdogTimeout):
			if atomic.LoadInt32(&loaded) == 1 {
				LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Watchdog (%v) — force-unloading hive %s", watchdogTimeout, loadedHiveSubkey))
				_ = regUnLoadKey(windows.HKEY_LOCAL_MACHINE, pSubkey)
				atomic.StoreInt32(&loaded, 0)
			}
		}
	}()

	// Defer the unload first — runs LIFO, so this fires last (after read).
	defer func() {
		close(watchdogStop)
		if atomic.CompareAndSwapInt32(&loaded, 1, 0) {
			if err := regUnLoadKey(windows.HKEY_LOCAL_MACHINE, pSubkey); err != nil {
				LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("RegUnLoadKey on cleanup failed: %v", err))
			} else {
				LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Cleanup: hive %s unloaded", loadedHiveSubkey))
			}
		}
	}()

	// Step 5: RegOpenKeyEx on the loaded hive — the SAM-read API signature.
	// We open with KEY_READ; we never enumerate any subkeys, just open + close.
	loadedKey, err := registry.OpenKey(registry.LOCAL_MACHINE, loadedHiveSubkey, registry.READ)
	if err != nil {
		// EDR can block this with ERROR_ACCESS_DENIED. registry.OpenKey wraps
		// errors in syscall.Errno.
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_ACCESS_DENIED {
			LogMessage("INFO", TECHNIQUE_ID, "RegOpenKey on loaded hive blocked: ERROR_ACCESS_DENIED")
			return StageBlocked
		}
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("RegOpenKey on loaded hive failed: %v", err))
		return StageError
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("RegOpenKey(HKLM\\%s, KEY_READ) succeeded — SAM-hive-read primitive exercised", loadedHiveSubkey))
	_ = loadedKey.Close()

	fmt.Printf("[STAGE %s] Synthetic SAM-hive load + read primitives exercised (sandbox-only)\n", TECHNIQUE_ID)
	return StageSuccess
}

// advapi32 is loaded once at init for RegSaveKeyW / RegLoadKeyW / RegUnLoadKeyW.
// golang.org/x/sys/windows v0.15.0 doesn't expose these as Go-typed wrappers.
var (
	advapi32        = windows.NewLazySystemDLL("advapi32.dll")
	procRegSaveKey  = advapi32.NewProc("RegSaveKeyW")
	procRegLoadKey  = advapi32.NewProc("RegLoadKeyW")
	procRegUnLoadKy = advapi32.NewProc("RegUnLoadKeyW")
)

// saveKeyAsHive wraps RegSaveKeyW. Returns nil on success.
func saveKeyAsHive(key registry.Key, filePath string) error {
	pPath, _ := syscall.UTF16PtrFromString(filePath)
	r1, _, e1 := procRegSaveKey.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(pPath)),
		0, // LPSECURITY_ATTRIBUTES — null = default
	)
	if r1 != 0 {
		return e1
	}
	return nil
}

// regLoadKey wraps RegLoadKeyW. Returns nil on success.
func regLoadKey(rootKey windows.Handle, subKey, hivePath *uint16) error {
	r1, _, e1 := procRegLoadKey.Call(
		uintptr(rootKey),
		uintptr(unsafe.Pointer(subKey)),
		uintptr(unsafe.Pointer(hivePath)),
	)
	if r1 != 0 {
		return e1
	}
	return nil
}

// regUnLoadKey wraps RegUnLoadKeyW. Returns nil on success.
func regUnLoadKey(rootKey windows.Handle, subKey *uint16) error {
	r1, _, e1 := procRegUnLoadKy.Call(
		uintptr(rootKey),
		uintptr(unsafe.Pointer(subKey)),
	)
	if r1 != 0 {
		return e1
	}
	return nil
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

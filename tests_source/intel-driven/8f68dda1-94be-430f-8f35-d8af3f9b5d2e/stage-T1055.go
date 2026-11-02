//go:build windows
// +build windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	TEST_UUID      = "8f68dda1-94be-430f-8f35-d8af3f9b5d2e"
	TECHNIQUE_ID   = "T1055"
	TECHNIQUE_NAME = "Test-Owned svchost DLL Injection"
	STAGE_ID       = 3
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--injection-target" {
		_ = os.WriteFile(filepath.Join(LOG_DIR, "qilin_svchost_target_started.txt"), []byte(fmt.Sprintf("PID=%d", os.Getpid())), 0644)
		time.Sleep(90 * time.Second)
		return
	}
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)
	code := performInjection()
	switch code {
	case StageSuccess:
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Remote LoadLibraryW thread completed in test-owned svchost.exe")
	case StageBlocked, StageQuarantined:
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Injection primitive positively prevented")
	default:
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Injection primitive inconclusive")
	}
	os.Exit(code)
}

func performInjection() int {
	sandbox := filepath.Join(ARTIFACT_DIR, "Qilin", "injection")
	_ = os.RemoveAll(sandbox)
	if err := os.MkdirAll(sandbox, 0755); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("sandbox creation returned: %v", err))
		return StageError
	}
	targetPath := filepath.Join(sandbox, "svchost.exe")
	dllPath := filepath.Join(sandbox, "pwndll.dll")
	markerPath := filepath.Join(LOG_DIR, "qilin_svchost_target_started.txt")
	_ = os.Remove(markerPath)
	defer func() {
		_ = os.RemoveAll(sandbox)
		_ = os.Remove(markerPath)
	}()

	if err := copyCurrentExecutable(targetPath); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("svchost stand-in copy returned: %v", err))
		return StageError
	}
	if err := copyFile(`C:\Windows\System32\version.dll`, dllPath); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("pwndll stand-in copy returned: %v", err))
		return StageError
	}
	LogFileDropped("svchost.exe", targetPath, injectionFileSize(targetPath), false)
	LogFileDropped("pwndll.dll", dllPath, injectionFileSize(dllPath), false)
	LogMessage("WARN", TECHNIQUE_ID, "Injecting renamed Microsoft version.dll into a test-owned svchost.exe; patched malicious pwndll.dll is not reproduced")
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return StageQuarantined
	}
	if _, err := os.Stat(dllPath); os.IsNotExist(err) {
		return StageQuarantined
	}

	cmd := exec.Command(targetPath, "--injection-target")
	cmd.Dir = sandbox
	var targetOutput bytes.Buffer
	cmd.Stdout = &targetOutput
	cmd.Stderr = &targetOutput
	if err := cmd.Start(); err != nil {
		return classifyInjectionError(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = os.WriteFile(filepath.Join(LOG_DIR, "qilin_svchost_target_output.txt"), targetOutput.Bytes(), 0644)
	}()
	time.Sleep(750 * time.Millisecond)

	access := uint32(windows.PROCESS_CREATE_THREAD | windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_OPERATION | windows.PROCESS_VM_WRITE | windows.PROCESS_VM_READ)
	processHandle, err := windows.OpenProcess(access, false, uint32(cmd.Process.Pid))
	if err != nil {
		return classifyInjectionError(err)
	}
	defer windows.CloseHandle(processHandle)

	kernel32, err := windows.LoadLibrary("kernel32.dll")
	if err != nil {
		return StageError
	}
	loadLibraryAddress, err := windows.GetProcAddress(kernel32, "LoadLibraryW")
	if err != nil {
		return StageError
	}

	pathPtr, err := windows.UTF16FromString(dllPath)
	if err != nil {
		return StageError
	}
	pathBytes := make([]byte, len(pathPtr)*2)
	for i, value := range pathPtr {
		pathBytes[i*2] = byte(value)
		pathBytes[i*2+1] = byte(value >> 8)
	}

	virtualAllocEx := windows.NewLazySystemDLL("kernel32.dll").NewProc("VirtualAllocEx")
	remoteMemory, _, allocErr := virtualAllocEx.Call(uintptr(processHandle), 0, uintptr(len(pathBytes)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if remoteMemory == 0 {
		return classifyInjectionError(allocErr)
	}
	defer windows.NewLazySystemDLL("kernel32.dll").NewProc("VirtualFreeEx").Call(uintptr(processHandle), remoteMemory, 0, windows.MEM_RELEASE)

	var written uintptr
	writeProcessMemory := windows.NewLazySystemDLL("kernel32.dll").NewProc("WriteProcessMemory")
	writeResult, _, writeErr := writeProcessMemory.Call(uintptr(processHandle), remoteMemory, uintptr(unsafe.Pointer(&pathBytes[0])), uintptr(len(pathBytes)), uintptr(unsafe.Pointer(&written)))
	if writeResult == 0 || written != uintptr(len(pathBytes)) {
		return classifyInjectionError(writeErr)
	}
	LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("WriteProcessMemory wrote %d-byte pwndll.dll path into test-owned svchost.exe", written))

	var threadID uint32
	createRemoteThread := windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateRemoteThread")
	threadHandle, _, threadErr := createRemoteThread.Call(uintptr(processHandle), 0, 0, loadLibraryAddress, remoteMemory, 0, uintptr(unsafe.Pointer(&threadID)))
	if threadHandle == 0 {
		return classifyInjectionError(threadErr)
	}
	defer windows.CloseHandle(windows.Handle(threadHandle))
	waitResult, waitErr := windows.WaitForSingleObject(windows.Handle(threadHandle), 10000)
	if waitErr != nil || waitResult != windows.WAIT_OBJECT_0 {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("remote thread wait returned event=%d error=%v", waitResult, waitErr))
		return StageError
	}
	var threadExitCode uint32
	getExitCodeThread := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetExitCodeThread")
	exitResult, _, exitErr := getExitCodeThread.Call(threadHandle, uintptr(unsafe.Pointer(&threadExitCode)))
	if exitResult == 0 {
		return classifyInjectionError(exitErr)
	}
	if threadExitCode == 0 || threadExitCode == 259 {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("remote LoadLibraryW returned exit code %d", threadExitCode))
		return StageError
	}
	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("CreateRemoteThread(LoadLibraryW) completed with module handle evidence 0x%x in test-owned PID %d", threadExitCode, cmd.Process.Pid))
	return StageSuccess
}

func classifyInjectionError(err error) int {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		for _, code := range []syscall.Errno{5, 225, 226, 1260, 4551} {
			if errno == code {
				LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("test-owned injection operation returned Windows error %d", code))
				return StageBlocked
			}
		}
	}
	LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("injection operation returned non-protection error: %v", err))
	return StageError
}

func injectionFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

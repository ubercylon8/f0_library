//go:build windows
// +build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	TEST_UUID      = "8f68dda1-94be-430f-8f35-d8af3f9b5d2e"
	TECHNIQUE_ID   = "T1518.001"
	TECHNIQUE_NAME = "Security Discovery & msimg32 Side-Load"
	STAGE_ID       = 1
)

type discoveryOutput struct {
	SecurityProducts string `json:"securityProducts"`
	Processes        string `json:"processes"`
	Services         string `json:"services"`
	System           string `json:"system"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--sideload-host" {
		runSideloadHost()
		return
	}
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)
	sandbox := filepath.Join(ARTIFACT_DIR, "Qilin", "FoxitPDFReader")
	_ = os.RemoveAll(sandbox)
	code := performDiscoveryAndSideload(sandbox)
	_ = os.RemoveAll(sandbox)
	_ = os.Remove(filepath.Join(LOG_DIR, "qilin_sideload_marker.txt"))
	switch code {
	case StageSuccess:
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Discovery and benign msimg32 image-load telemetry completed")
	case StageBlocked, StageQuarantined:
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Side-load stage positively prevented; see structured messages")
	default:
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Side-load objective inconclusive")
	}
	os.Exit(code)
}

func performDiscoveryAndSideload(sandbox string) int {
	discovery := discoveryOutput{
		SecurityProducts: runDiscoveryCommand("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState,pathToSignedProductExe | ConvertTo-Json -Compress"),
		Processes:        runDiscoveryCommand("tasklist.exe", "/fo", "csv"),
		Services:         runDiscoveryCommand("sc.exe", "query", "type=", "service"),
		System:           runDiscoveryCommand("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture | ConvertTo-Json -Compress"),
	}
	payload, _ := json.MarshalIndent(discovery, "", "  ")
	discoveryPath := filepath.Join(LOG_DIR, "qilin_security_discovery.json")
	if err := os.WriteFile(discoveryPath, payload, 0644); err != nil {
		logStageMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("discovery output write returned: %v", err))
	}
	discoveryCompleted := strings.TrimSpace(discovery.SecurityProducts+discovery.Processes+discovery.Services+discovery.System) != ""
	logStageMessage("INFO", "T1082", fmt.Sprintf("Read-only discovery completed=%v", discoveryCompleted))

	if err := os.MkdirAll(sandbox, 0755); err != nil {
		logStageMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("sandbox creation returned: %v", err))
		return StageError
	}
	hostPath := filepath.Join(sandbox, "FoxitPDFReader.exe")
	dllPath := filepath.Join(sandbox, "msimg32.dll")
	if err := copyCurrentExecutable(hostPath); err != nil {
		logStageMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("host copy returned: %v", err))
		return StageError
	}
	if err := copyFile(`C:\Windows\System32\msimg32.dll`, dllPath); err != nil {
		logStageMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("msimg32 copy returned: %v", err))
		return StageError
	}
	LogFileDropped("FoxitPDFReader.exe", hostPath, fileSize(hostPath), false)
	LogFileDropped("msimg32.dll", dllPath, fileSize(dllPath), false)
	logStageMessage("WARN", "T1574.002", "Test-owned host will LoadLibraryW a renamed Microsoft msimg32.dll; malicious forwarding DLL is not reproduced")
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(hostPath); os.IsNotExist(err) {
		return StageQuarantined
	}
	if _, err := os.Stat(dllPath); os.IsNotExist(err) {
		return StageQuarantined
	}

	cmd := exec.Command(hostPath, "--sideload-host")
	cmd.Dir = sandbox
	var output bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &output)
	cmd.Stderr = io.MultiWriter(os.Stderr, &output)
	runErr := cmd.Run()
	_ = os.WriteFile(filepath.Join(LOG_DIR, "qilin_sideload_output.txt"), output.Bytes(), 0644)
	if runErr != nil {
		if _, statErr := os.Stat(hostPath); os.IsNotExist(statErr) {
			return StageQuarantined
		}
		var errno syscall.Errno
		if errors.As(runErr, &errno) && (errno == 5 || errno == 225 || errno == 226 || errno == 1260 || errno == 4551) {
			logStageMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("fresh test-owned host launch returned Windows error %d", errno))
			return StageBlocked
		}
		logStageMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("host execution returned: %v", runErr))
		return StageError
	}
	marker, markerErr := os.ReadFile(filepath.Join(LOG_DIR, "qilin_sideload_marker.txt"))
	loadSucceeded := markerErr == nil && strings.Contains(string(marker), "LOADLIBRARY_SUCCESS")
	if !loadSucceeded {
		logStageMessage("ERROR", TECHNIQUE_ID, "LoadLibraryW success marker absent")
		return StageError
	}
	if !discoveryCompleted {
		logStageMessage("ERROR", TECHNIQUE_ID, "Discovery commands returned no usable output")
		return StageError
	}
	return StageSuccess
}

func runDiscoveryCommand(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	LogProcessExecution(name, strings.Join(append([]string{name}, args...), " "), 0, err == nil, 0, string(out))
	if err != nil && len(out) == 0 {
		return ""
	}
	return string(out)
}

func runSideloadHost() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	dllPath := filepath.Join(filepath.Dir(exePath), "msimg32.dll")
	marker := filepath.Join(LOG_DIR, "qilin_sideload_marker.txt")
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibrary := kernel32.NewProc("LoadLibraryW")
	freeLibrary := kernel32.NewProc("FreeLibrary")
	pathPtr, err := windows.UTF16PtrFromString(dllPath)
	if err != nil {
		return
	}
	handle, _, callErr := loadLibrary.Call(uintptr(unsafe.Pointer(pathPtr)))
	if handle == 0 {
		_ = os.WriteFile(marker, []byte(fmt.Sprintf("LOADLIBRARY_FAILED: %v", callErr)), 0644)
		return
	}
	_ = os.WriteFile(marker, []byte("LOADLIBRARY_SUCCESS"), 0644)
	time.Sleep(750 * time.Millisecond)
	freeLibrary.Call(handle)
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

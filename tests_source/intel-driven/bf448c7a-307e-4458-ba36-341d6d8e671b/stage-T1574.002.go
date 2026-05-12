//go:build windows
// +build windows

/*
STAGE 2: DLL Side-Loading (T1574.002) — LIFT 1: real LoadLibrary

Simulates TclBanker's signature side-loading pattern where the binary
LogiAiPromptBuilder.exe loads screen_retriever_plugin.dll from its own
directory. The sandbox version drops:

  - LogiAiPromptBuilder.exe (F0RT1KA-signed sandbox host, embedded gzipped)
  - screen_retriever_plugin.dll (renamed copy of C:\Windows\System32\version.dll)

Both files land in ARTIFACT_DIR\LogiAI\ — exactly the install-path shape
%LocalAppData%\LogiAI\ that real TclBanker uses, but routed through the
sandbox directory tree so EDR can observe but no real install happens.

The host EXE then performs a real LoadLibraryW on the renamed DLL,
producing genuine image-load telemetry. The renamed DLL is a real
Microsoft signed binary, so the load itself is benign — what's
suspicious to EDR is the pattern (renamed Microsoft DLL in non-standard
path, renamed host EXE, image load from outside System32).

SAFETY:
  - All artifacts in ARTIFACT_DIR (c:\Users\fortika-test\LogiAI\)
  - Host EXE is F0RT1KA-signed sandbox code; no malicious behavior
  - Renamed DLL is unmodified version.dll from System32
  - All artifacts deleted on stage cleanup
*/

package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "bf448c7a-307e-4458-ba36-341d6d8e671b"
	TECHNIQUE_ID   = "T1574.002"
	TECHNIQUE_NAME = "DLL Side-Loading (TclBanker screen_retriever_plugin)"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Real TclBanker identifiers
const (
	HostExeName    = "LogiAiPromptBuilder.exe"
	SideloadDLL    = "screen_retriever_plugin.dll"
	InstallDirName = "LogiAI" // matches %LocalAppData%\LogiAI\
)

//go:embed LogiAiPromptBuilder.exe.gz
var hostExeGzip []byte

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, "Starting DLL sideloading simulation (LIFT 1: real LoadLibrary)")
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Host: %s | Sideloaded DLL: %s", HostExeName, SideloadDLL))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "TclBanker DLL sideload via LogiAiPromptBuilder.exe")

	// NOTE: os.Exit() bypasses deferred functions, so we cannot rely on
	// `defer cleanup()`. Every exit path below calls cleanup() explicitly
	// before os.Exit. This ensures LogiAiPromptBuilder.exe and the renamed
	// screen_retriever_plugin.dll are removed from ARTIFACT_DIR\LogiAI on
	// every stage termination — error, blocked, or success.
	cleanup, err := performTechnique()
	if err != nil {
		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))
		exitCode := determineExitCode(err)
		if exitCode == StageBlocked || exitCode == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		cleanup()
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] DLL sideload completed (real LoadLibrary on renamed Microsoft DLL)\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Sideload host executed; image load occurred on screen_retriever_plugin.dll")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Real LoadLibrary produced — TclBanker sideload pattern observed")
	cleanup()
	os.Exit(StageSuccess)
}

func performTechnique() (func(), error) {
	noop := func() {}

	// Create the install-path-shape directory inside ARTIFACT_DIR
	sideloadDir := filepath.Join(ARTIFACT_DIR, InstallDirName)
	if err := os.MkdirAll(sideloadDir, 0755); err != nil {
		return noop, fmt.Errorf("create sideload dir: %v", err)
	}

	cleanup := func() {
		// Best-effort artifact cleanup
		os.RemoveAll(sideloadDir)
		LogMessage("INFO", TECHNIQUE_ID, "Cleanup: sideload artifacts removed")
	}

	// Step 1: Extract embedded F0RT1KA-signed host EXE (LogiAiPromptBuilder.exe)
	hostPath := filepath.Join(sideloadDir, HostExeName)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Extracting sandbox host EXE to: %s", hostPath))

	hostBytes, err := decompressGzipStage(hostExeGzip)
	if err != nil {
		return cleanup, fmt.Errorf("decompress host EXE: %v", err)
	}
	if err := os.WriteFile(hostPath, hostBytes, 0755); err != nil {
		return cleanup, fmt.Errorf("write host EXE: %v", err)
	}
	LogFileDropped(HostExeName, hostPath, int64(len(hostBytes)), false)

	// Step 2: Drop the renamed Microsoft signed DLL — copy version.dll from System32
	// and rename it to screen_retriever_plugin.dll. This is what produces the EDR-
	// suspicious "Microsoft DLL in non-standard path" pattern.
	systemDll := `C:\Windows\System32\version.dll`
	sideloadPath := filepath.Join(sideloadDir, SideloadDLL)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Copying %s -> %s (renamed Microsoft DLL)", systemDll, sideloadPath))

	src, err := os.ReadFile(systemDll)
	if err != nil {
		return cleanup, fmt.Errorf("read system DLL %s: %v", systemDll, err)
	}
	if err := os.WriteFile(sideloadPath, src, 0755); err != nil {
		return cleanup, fmt.Errorf("write sideloaded DLL: %v", err)
	}
	LogFileDropped(SideloadDLL, sideloadPath, int64(len(src)), false)

	// Brief settle so EDR can scan both artifacts before we execute
	time.Sleep(2 * time.Second)

	if _, err := os.Stat(hostPath); os.IsNotExist(err) {
		return cleanup, fmt.Errorf("quarantined: %s removed before execution", HostExeName)
	}
	if _, err := os.Stat(sideloadPath); os.IsNotExist(err) {
		return cleanup, fmt.Errorf("quarantined: %s removed before execution", SideloadDLL)
	}

	// Step 3: Execute the host EXE. It calls LoadLibraryW on the renamed DLL
	// from its own directory — this is the actual side-loading event.
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Executing %s (will LoadLibrary %s)", HostExeName, SideloadDLL))
	cmd := exec.Command(hostPath)
	cmd.Dir = sideloadDir

	// Capture stdout/stderr to LOG_DIR per CLAUDE.md mandate
	var outBuf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outBuf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outBuf)

	startTime := time.Now()
	runErr := cmd.Run()
	dur := time.Since(startTime)

	outputFile := filepath.Join(LOG_DIR, "T1574.002_host_output.txt")
	_ = os.WriteFile(outputFile, outBuf.Bytes(), 0644)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Host EXE finished in %v; output saved to %s", dur, outputFile))

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			ec := exitErr.ExitCode()
			LogProcessExecution(HostExeName, hostPath, 0, false, ec, runErr.Error())
			// Non-zero exit from the host is unusual but doesn't necessarily mean
			// EDR blocked. Treat as error so the orchestrator can decide.
			return cleanup, fmt.Errorf("host EXE exited with code %d", ec)
		}
		// Failed to start — could be EDR
		LogProcessExecution(HostExeName, hostPath, 0, false, 999, runErr.Error())
		return cleanup, fmt.Errorf("failed to start host EXE: %v", runErr)
	}
	LogProcessExecution(HostExeName, hostPath, 0, true, 0, "")

	// Step 4: Verify the host's LoadLibrary marker — confirms image load occurred
	hostMarker := `C:\F0\sideload_host_loaded.txt`
	if data, err := os.ReadFile(hostMarker); err == nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Host marker present (%d bytes) — image load confirmed", len(data)))
	} else {
		LogMessage("WARN", TECHNIQUE_ID, "Host marker missing — image load may not have produced telemetry")
	}

	// Confirm artifacts still on disk (not quarantined post-execution)
	if _, err := os.Stat(hostPath); os.IsNotExist(err) {
		return cleanup, fmt.Errorf("quarantined: host EXE removed after execution")
	}
	if _, err := os.Stat(sideloadPath); os.IsNotExist(err) {
		return cleanup, fmt.Errorf("quarantined: sideloaded DLL removed after execution")
	}

	LogMessage("INFO", TECHNIQUE_ID, "DLL sideload simulation produced real LoadLibrary telemetry")
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Detection-fidelity install path string: %%LocalAppData%%\\%s\\", InstallDirName))
	return cleanup, nil
}

// decompressGzipStage decompresses a gzip-compressed byte slice
func decompressGzipStage(compressed []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

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

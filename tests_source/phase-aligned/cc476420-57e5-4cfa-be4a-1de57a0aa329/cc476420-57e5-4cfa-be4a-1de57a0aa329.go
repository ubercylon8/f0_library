//go:build windows
// +build windows

/*
ID: cc476420-57e5-4cfa-be4a-1de57a0aa329
NAME: WinRM Execution Detection Test
TECHNIQUES: T1021.006
TACTICS: lateral-movement
SEVERITY: medium
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: lateral-movement
TAGS: phase-7, tiber-eu, readiness, winrm, remote-execution
PHASE: 7
PHASE_NAME: Lateral Movement
SUITE: lateral-movement-readiness-2026-01
UNIT: response
CREATED: 2026-01-05
AUTHOR: pentest-readiness-builder
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
	TEST_UUID = "cc476420-57e5-4cfa-be4a-1de57a0aa329"
	TEST_NAME = "WinRM Execution Detection Test"
)

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1021.006 - Windows Remote Management")
	Endpoint.Say("Phase: 7 - Lateral Movement")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "lateral_movement",
		Severity:   "medium",
		Techniques: []string{"T1021.006"},
		Tactics:    []string{"lateral-movement"},
		Score:      7.5,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        1.5,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"phase-7", "tiber-eu", "readiness", "winrm", "evil-winrm", "powershell-remoting"},
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
	// Phase 1: Check WinRM Configuration
	// =========================================================================
	LogPhaseStart(0, "WinRM Configuration Check")
	Endpoint.Say("Phase 1: Checking WinRM configuration...")

	winrmCheckScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Checking WinRM service status..."

# Check WinRM service
$winrmSvc = Get-Service WinRM -ErrorAction SilentlyContinue
if ($winrmSvc) {
    Write-Host "[*] WinRM Service Status: $($winrmSvc.Status)"
    if ($winrmSvc.Status -eq "Running") {
        Write-Host "[!] WinRM is RUNNING - remote management possible"
        Write-Host "WINRM_RUNNING"
    } else {
        Write-Host "[+] WinRM is STOPPED"
        Write-Host "WINRM_STOPPED"
    }
} else {
    Write-Host "[*] WinRM service not found"
}

# Check WinRM listener configuration
Write-Host ""
Write-Host "[*] Checking WinRM listeners..."
$listeners = winrm enumerate winrm/config/listener 2>&1

if ($listeners -match "Listener") {
    Write-Host "[!] WinRM listeners configured:"
    Write-Host $listeners
} else {
    Write-Host "[+] No WinRM listeners configured"
}

# Check trusted hosts
Write-Host ""
Write-Host "[*] Checking TrustedHosts configuration..."
$trustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue
if ($trustedHosts.Value) {
    Write-Host "[!] TrustedHosts: $($trustedHosts.Value)"
    if ($trustedHosts.Value -eq "*") {
        Write-Host "[!] WARNING: TrustedHosts set to * - accepts all hosts"
        Write-Host "TRUSTEDHOSTS_OPEN"
    }
} else {
    Write-Host "[+] TrustedHosts is empty (default secure)"
}

# Check PowerShell remoting
Write-Host ""
Write-Host "[*] Checking PowerShell remoting status..."
try {
    $psRemoting = Test-WSMan -ComputerName localhost -ErrorAction Stop
    Write-Host "[!] PowerShell remoting is ENABLED"
    Write-Host "PSREMOTING_ENABLED"
} catch {
    Write-Host "[+] PowerShell remoting test failed (likely disabled)"
    Write-Host "PSREMOTING_DISABLED"
}
`

	winrmScriptPath := filepath.Join(targetDir, "winrm_config_check.ps1")
	if err := os.WriteFile(winrmScriptPath, []byte(winrmCheckScript), 0644); err != nil {
		LogMessage("ERROR", "WinRM Check", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("winrm_config_check.ps1", winrmScriptPath, int64(len(winrmCheckScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", winrmScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)
		cmd.Run()

		outputPath := filepath.Join(targetDir, "winrm_config_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		output := outputBuffer.String()
		if strings.Contains(output, "WINRM_STOPPED") && strings.Contains(output, "PSREMOTING_DISABLED") {
			LogMessage("INFO", "WinRM Check", "WinRM is disabled")
			protectionIndicators++
			LogPhaseEnd(0, "blocked", "WinRM disabled - remote management not possible")
		} else {
			LogPhaseEnd(0, "success", "WinRM configuration checked")
		}
	}

	// =========================================================================
	// Phase 2: Simulate Evil-WinRM Style Connection
	// =========================================================================
	LogPhaseStart(1, "WinRM Connection Simulation")
	Endpoint.Say("")
	Endpoint.Say("Phase 2: Simulating Evil-WinRM style connection patterns...")

	connectionSimScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Simulating Evil-WinRM connection pattern..."

# Evil-WinRM typically uses: Enter-PSSession or Invoke-Command
# We simulate the detection pattern

Write-Host "[*] Testing local WinRM connection..."

try {
    # Try to establish session (this triggers Event ID 91 and 4648)
    $session = New-PSSession -ComputerName localhost -ErrorAction Stop
    Write-Host "[!] WinRM session created successfully"
    Write-Host "[!] Session ID: $($session.Id)"

    # Execute command (simulates Evil-WinRM behavior)
    $result = Invoke-Command -Session $session -ScriptBlock { whoami } -ErrorAction Stop
    Write-Host "[!] Remote execution succeeded: $result"
    Write-Host "WINRM_SESSION_SUCCESS"

    # Cleanup
    Remove-PSSession -Session $session

} catch {
    if ($_.Exception.Message -match "Access denied|blocked|disabled|refused") {
        Write-Host "[+] WinRM session BLOCKED"
        Write-Host "WINRM_SESSION_BLOCKED"
        exit 126
    }
    Write-Host "[*] WinRM session failed: $($_.Exception.Message)"
    Write-Host "WINRM_SESSION_FAILED"
}

# Check for WinRM event logs
Write-Host ""
Write-Host "[*] Checking WinRM event logs..."

$winrmEvents = Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue
if ($winrmEvents) {
    Write-Host "[*] Found $($winrmEvents.Count) recent WinRM events"
}
`

	connScriptPath := filepath.Join(targetDir, "winrm_connection_sim.ps1")
	if err := os.WriteFile(connScriptPath, []byte(connectionSimScript), 0644); err != nil {
		LogMessage("ERROR", "Connection Sim", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("winrm_connection_sim.ps1", connScriptPath, int64(len(connectionSimScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", connScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		}

		outputPath := filepath.Join(targetDir, "winrm_connection_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		output := outputBuffer.String()
		if exitCode == 126 || strings.Contains(output, "WINRM_SESSION_BLOCKED") {
			LogMessage("INFO", "Connection Sim", "WinRM sessions blocked")
			protectionIndicators++
			LogPhaseEnd(1, "blocked", "WinRM sessions blocked")
		} else if strings.Contains(output, "WINRM_SESSION_SUCCESS") {
			LogMessage("WARN", "Connection Sim", "WinRM sessions possible")
			LogPhaseEnd(1, "success", "WinRM sessions possible")
		} else {
			LogPhaseEnd(1, "success", "WinRM simulation completed")
		}
	}

	// =========================================================================
	// Phase 3: Create WinRM Artifacts
	// =========================================================================
	LogPhaseStart(2, "Artifact Creation")
	Endpoint.Say("")
	Endpoint.Say("Phase 3: Creating WinRM detection artifacts...")

	winrmArtifact := fmt.Sprintf(`WinRM Execution Simulation - %s
==============================================
Test ID: %s
Timestamp: %s

Simulated Evil-WinRM Behavior:
------------------------------
1. Connect via: evil-winrm -i TARGET -u USER -p PASS
2. WinRM session established on port 5985/5986
3. PowerShell remoting enabled
4. Command execution via Invoke-Command

Detection Indicators:
- Event ID 91 (WinRM Session Start)
- Event ID 4648 (Explicit credential logon)
- Event ID 4624 Type 3 (Network logon)
- WinRM service start (Event ID 7036)
- PowerShell scriptblock logging (Event ID 4104)
- Network connection to 5985/5986 from unusual source
`, TEST_NAME, TEST_UUID, time.Now().Format(time.RFC3339))

	artifactPath := filepath.Join(targetDir, "winrm_results.txt")
	os.WriteFile(artifactPath, []byte(winrmArtifact), 0644)
	LogFileDropped("winrm_results.txt", artifactPath, int64(len(winrmArtifact)), false)

	LogPhaseEnd(2, "success", "Artifact creation completed")

	// =========================================================================
	// Determine Final Result
	// =========================================================================
	Endpoint.Say("")
	Endpoint.Say("=================================================================")

	if protectionIndicators >= 2 {
		Endpoint.Say("RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("WinRM lateral movement is restricted")
		Endpoint.Say("")
		Endpoint.Say("Active protections:")
		Endpoint.Say("  - WinRM service disabled")
		Endpoint.Say("  - PowerShell remoting disabled")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.ExecutionPrevented, "WinRM protections active")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	} else {
		Endpoint.Say("RESULT: UNPROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("WARNING: WinRM lateral movement is possible")
		Endpoint.Say("")
		Endpoint.Say("Recommendations:")
		Endpoint.Say("  1. Disable WinRM service where not needed")
		Endpoint.Say("  2. Restrict WinRM to specific trusted hosts")
		Endpoint.Say("  3. Enable PowerShell ScriptBlock logging")
		Endpoint.Say("  4. Monitor Event ID 91 and 4648")
		Endpoint.Say("  5. Implement network segmentation for WinRM ports")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.Unprotected, "WinRM lateral movement possible")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.Unprotected)
	}
}

//go:build windows
// +build windows

/*
ID: 06d298bc-9604-4dda-8e04-7609eaf4723f
NAME: SMB Lateral Movement Detection Test
TECHNIQUES: T1021.002
TACTICS: lateral-movement
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: lateral-movement
TAGS: phase-7, tiber-eu, readiness, smb, remote-services
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
	TEST_UUID = "06d298bc-9604-4dda-8e04-7609eaf4723f"
	TEST_NAME = "SMB Lateral Movement Detection Test"
)

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1021.002 - SMB/Windows Admin Shares")
	Endpoint.Say("Phase: 7 - Lateral Movement")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "lateral_movement",
		Severity:   "high",
		Techniques: []string{"T1021.002"},
		Tactics:    []string{"lateral-movement"},
		Score:      7.8,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        1.5,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"phase-7", "tiber-eu", "readiness", "smb", "psexec", "lateral-movement"},
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
	// Phase 1: Check Admin Share Accessibility
	// =========================================================================
	LogPhaseStart(0, "Admin Share Check")
	Endpoint.Say("Phase 1: Checking admin share accessibility...")

	adminShareScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Checking administrative share configuration..."

# Check if admin shares exist locally
$adminShares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Name -match '^(ADMIN\$|C\$|IPC\$)' }

foreach ($share in $adminShares) {
    Write-Host "[*] Found admin share: $($share.Name) -> $($share.Path)"
}

# Check AutoShareWks/AutoShareServer registry
$autoShareWks = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue
$autoShareServer = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -ErrorAction SilentlyContinue

if ($autoShareWks.AutoShareWks -eq 0 -or $autoShareServer.AutoShareServer -eq 0) {
    Write-Host "[+] Administrative shares are DISABLED via registry"
    Write-Host "ADMIN_SHARES_DISABLED"
} else {
    Write-Host "[!] Administrative shares are ENABLED"
}

# Check local access to C$ (PsExec-style)
Write-Host ""
Write-Host "[*] Testing local C$ access pattern..."
$localPath = "\\localhost\C$"

if (Test-Path $localPath) {
    Write-Host "[!] Local C$ access succeeded - lateral movement possible"
    Write-Host "ADMIN_SHARE_ACCESSIBLE"
} else {
    Write-Host "[+] Local C$ access denied"
    Write-Host "ADMIN_SHARE_DENIED"
}
`

	shareScriptPath := filepath.Join(targetDir, "smb_admin_share.ps1")
	if err := os.WriteFile(shareScriptPath, []byte(adminShareScript), 0644); err != nil {
		LogMessage("ERROR", "Share Check", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("smb_admin_share.ps1", shareScriptPath, int64(len(adminShareScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", shareScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)
		cmd.Run()

		outputPath := filepath.Join(targetDir, "smb_share_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		output := outputBuffer.String()
		if strings.Contains(output, "ADMIN_SHARES_DISABLED") || strings.Contains(output, "ADMIN_SHARE_DENIED") {
			LogMessage("INFO", "Share Check", "Admin shares protected")
			protectionIndicators++
			LogPhaseEnd(0, "blocked", "Admin shares inaccessible")
		} else {
			LogPhaseEnd(0, "success", "Admin shares accessible")
		}
	}

	// =========================================================================
	// Phase 2: Simulate PsExec-style Service Creation
	// =========================================================================
	LogPhaseStart(1, "Service Creation Simulation")
	Endpoint.Say("")
	Endpoint.Say("Phase 2: Simulating PsExec-style remote service creation...")

	// Create a harmless batch file that simulates what PsExec deploys
	svcSimScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Simulating PsExec service creation pattern..."

# PsExec creates a service with name PSEXESVC
# We simulate the pattern without actually creating a service

# Check if we can query services (sc.exe behavior)
Write-Host "[*] Checking service control access..."
$services = Get-Service -ErrorAction SilentlyContinue | Select-Object -First 5

if ($services) {
    Write-Host "[*] Service enumeration succeeded"
} else {
    Write-Host "[!] Service enumeration failed"
}

# Check if we can create services (requires admin)
$testSvcName = "F0TESTPSEXEC"

Write-Host ""
Write-Host "[*] Testing service creation capability..."
Write-Host "[*] This simulates: sc \\target create $testSvcName ..."

# Check current user privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "[!] Running as Administrator - service creation would succeed"
    Write-Host "SERVICE_CREATE_POSSIBLE"
} else {
    Write-Host "[+] Not running as Administrator - service creation blocked"
    Write-Host "SERVICE_CREATE_BLOCKED"
}

# Check for service creation events
Write-Host ""
Write-Host "[*] Checking for service creation events (Event ID 7045)..."
$svcEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id = 7045
    StartTime = (Get-Date).AddMinutes(-30)
} -MaxEvents 5 -ErrorAction SilentlyContinue

if ($svcEvents) {
    Write-Host "[*] Found $($svcEvents.Count) recent service creation events"
    foreach ($event in $svcEvents) {
        Write-Host "    - $($event.TimeCreated): $($event.Message.Substring(0, [Math]::Min(80, $event.Message.Length)))..."
    }
}
`

	svcScriptPath := filepath.Join(targetDir, "smb_psexec_sim.ps1")
	if err := os.WriteFile(svcScriptPath, []byte(svcSimScript), 0644); err != nil {
		LogMessage("ERROR", "Service Sim", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("smb_psexec_sim.ps1", svcScriptPath, int64(len(svcSimScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", svcScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)
		cmd.Run()

		outputPath := filepath.Join(targetDir, "smb_psexec_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		output := outputBuffer.String()
		if strings.Contains(output, "SERVICE_CREATE_BLOCKED") {
			LogMessage("INFO", "Service Sim", "Service creation blocked")
			protectionIndicators++
			LogPhaseEnd(1, "blocked", "Service creation blocked")
		} else {
			LogPhaseEnd(1, "success", "Service creation possible")
		}
	}

	// =========================================================================
	// Phase 3: Create SMB Lateral Movement Artifacts
	// =========================================================================
	LogPhaseStart(2, "Artifact Creation")
	Endpoint.Say("")
	Endpoint.Say("Phase 3: Creating SMB lateral movement artifacts...")

	smbArtifact := fmt.Sprintf(`SMB Lateral Movement Simulation - %s
==============================================
Test ID: %s
Timestamp: %s

Simulated PsExec Behavior:
--------------------------
1. Connect to \\TARGET\ADMIN$ share
2. Copy PSEXESVC.exe to \\TARGET\ADMIN$\System32
3. Create service: sc \\TARGET create PSEXESVC binpath=...
4. Start service: sc \\TARGET start PSEXESVC
5. Execute command via named pipe
6. Stop and delete service

Simulated smbexec Behavior:
---------------------------
1. Connect to \\TARGET\C$ share
2. Create batch file in \\TARGET\C$\Windows\Temp
3. Execute via at.exe or schtasks
4. Capture output via SMB share

Detection Indicators:
- Event ID 7045: Service was installed
- Event ID 4624 Type 3: Network logon to admin share
- Event ID 5145: Access to ADMIN$ or C$ share
- Named pipe creation: \pipe\svcctl
- Executable in ADMIN$\System32 from network source
`, TEST_NAME, TEST_UUID, time.Now().Format(time.RFC3339))

	artifactPath := filepath.Join(targetDir, "smb_lateral_results.txt")
	os.WriteFile(artifactPath, []byte(smbArtifact), 0644)
	LogFileDropped("smb_lateral_results.txt", artifactPath, int64(len(smbArtifact)), false)

	LogPhaseEnd(2, "success", "Artifact creation completed")

	// =========================================================================
	// Determine Final Result
	// =========================================================================
	Endpoint.Say("")
	Endpoint.Say("=================================================================")

	if protectionIndicators >= 2 {
		Endpoint.Say("RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("SMB lateral movement is restricted")
		Endpoint.Say("")
		Endpoint.Say("Active protections:")
		Endpoint.Say("  - Admin shares restricted")
		Endpoint.Say("  - Service creation blocked")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.ExecutionPrevented, "SMB lateral movement protections active")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	} else {
		Endpoint.Say("RESULT: UNPROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("WARNING: SMB lateral movement is possible")
		Endpoint.Say("")
		Endpoint.Say("Recommendations:")
		Endpoint.Say("  1. Disable administrative shares via registry")
		Endpoint.Say("  2. Implement host-based firewall rules for SMB")
		Endpoint.Say("  3. Monitor Event ID 7045 (service creation)")
		Endpoint.Say("  4. Monitor Event ID 5145 (admin share access)")
		Endpoint.Say("  5. Implement least privilege for admin accounts")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.Unprotected, "SMB lateral movement possible")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.Unprotected)
	}
}

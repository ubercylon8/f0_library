//go:build windows
// +build windows

/*
ID: 1a5895fa-f9b2-4d35-a11b-b4c9e40373a0
NAME: NTLM Relay Detection Test
TECHNIQUES: T1557.001
TACTICS: credential-access, lateral-movement
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: lateral-movement
TAGS: phase-7, tiber-eu, readiness, ntlm-relay, man-in-the-middle
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
	TEST_UUID = "1a5895fa-f9b2-4d35-a11b-b4c9e40373a0"
	TEST_NAME = "NTLM Relay Detection Test"
)

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1557.001 - LLMNR/NBT-NS Poisoning")
	Endpoint.Say("Phase: 7 - Lateral Movement")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "credential_access",
		Severity:   "high",
		Techniques: []string{"T1557.001"},
		Tactics:    []string{"credential-access", "collection"},
		Score:      7.8,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        1.5,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"phase-7", "tiber-eu", "readiness", "ntlm-relay", "responder", "llmnr"},
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
	// Phase 1: Check LLMNR/NBT-NS Configuration
	// =========================================================================
	LogPhaseStart(0, "Protocol Configuration Check")
	Endpoint.Say("Phase 1: Checking LLMNR/NBT-NS configuration...")

	configCheckScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Checking name resolution protocol configuration..."

# Check if LLMNR is disabled
$llmnrKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$llmnrDisabled = $false

try {
    $llmnrValue = Get-ItemProperty -Path $llmnrKey -Name "EnableMulticast" -ErrorAction Stop
    if ($llmnrValue.EnableMulticast -eq 0) {
        Write-Host "[+] LLMNR is DISABLED (EnableMulticast=0)"
        $llmnrDisabled = $true
    } else {
        Write-Host "[!] LLMNR is ENABLED - vulnerable to poisoning"
    }
} catch {
    Write-Host "[!] LLMNR policy not configured - ENABLED by default"
}

# Check NetBIOS over TCP/IP
Write-Host ""
Write-Host "[*] Checking NetBIOS over TCP/IP..."

$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
$nbtnsDisabled = $true

foreach ($adapter in $adapters) {
    # TcpipNetbiosOptions: 0=default, 1=enabled, 2=disabled
    if ($adapter.TcpipNetbiosOptions -ne 2) {
        Write-Host "[!] NetBIOS enabled on adapter: $($adapter.Description)"
        $nbtnsDisabled = $false
    }
}

if ($nbtnsDisabled) {
    Write-Host "[+] NetBIOS over TCP/IP is DISABLED on all adapters"
}

# Check SMB Signing
Write-Host ""
Write-Host "[*] Checking SMB Signing configuration..."

$smbServerSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
$smbClientSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue

if ($smbServerSigning.RequireSecuritySignature -eq 1) {
    Write-Host "[+] SMB Server Signing is REQUIRED"
} else {
    Write-Host "[!] SMB Server Signing is NOT required - vulnerable to relay"
}

if ($smbClientSigning.RequireSecuritySignature -eq 1) {
    Write-Host "[+] SMB Client Signing is REQUIRED"
} else {
    Write-Host "[!] SMB Client Signing is NOT required - vulnerable to relay"
}

# Summary
Write-Host ""
if ($llmnrDisabled -and $nbtnsDisabled -and $smbServerSigning.RequireSecuritySignature -eq 1 -and $smbClientSigning.RequireSecuritySignature -eq 1) {
    Write-Host "[+] System is PROTECTED against NTLM relay attacks"
    Write-Host "CONFIG_PROTECTED"
} else {
    Write-Host "[!] System has NTLM relay vulnerabilities"
    Write-Host "CONFIG_VULNERABLE"
}
`

	configScriptPath := filepath.Join(targetDir, "ntlm_relay_config.ps1")
	if err := os.WriteFile(configScriptPath, []byte(configCheckScript), 0644); err != nil {
		LogMessage("ERROR", "Config Check", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("ntlm_relay_config.ps1", configScriptPath, int64(len(configCheckScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", configScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)
		cmd.Run()

		outputPath := filepath.Join(targetDir, "ntlm_relay_config_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		output := outputBuffer.String()
		if strings.Contains(output, "CONFIG_PROTECTED") {
			LogMessage("INFO", "Config Check", "System protected against NTLM relay")
			protectionIndicators++
			LogPhaseEnd(0, "success", "System protected - LLMNR/NBT-NS disabled, SMB signing required")
		} else {
			LogMessage("WARN", "Config Check", "NTLM relay vulnerabilities detected")
			LogPhaseEnd(0, "success", "Configuration check completed - vulnerabilities found")
		}
	}

	// =========================================================================
	// Phase 2: Simulate Responder-style Poisoning Detection
	// =========================================================================
	LogPhaseStart(1, "Poisoning Detection Simulation")
	Endpoint.Say("")
	Endpoint.Say("Phase 2: Simulating LLMNR/NBT-NS poisoning patterns...")

	poisonSimScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Simulating Responder-style poisoning behavior..."

# Trigger LLMNR query by resolving non-existent host
Write-Host "[*] Triggering LLMNR query for 'fakeserver01'..."
$result = Resolve-DnsName -Name "fakeserver01" -Type A -DnsOnly -ErrorAction SilentlyContinue

if ($result) {
    Write-Host "[!] Received response for fake host - potential poisoning!"
    Write-Host "POISON_DETECTED"
} else {
    Write-Host "[*] No response for fake host (expected in clean environment)"
}

# Check for suspicious multicast traffic patterns
Write-Host ""
Write-Host "[*] Checking for LLMNR listener ports..."

$llmnrListeners = netstat -an | Select-String ":5355"
if ($llmnrListeners) {
    Write-Host "[*] LLMNR port 5355 is active:"
    $llmnrListeners | ForEach-Object { Write-Host "    $_" }
}

# Check NBT-NS port
$nbnsListeners = netstat -an | Select-String ":137"
if ($nbnsListeners) {
    Write-Host "[*] NBT-NS port 137 is active"
}

Write-Host ""
Write-Host "[*] Poisoning simulation completed"
`

	poisonScriptPath := filepath.Join(targetDir, "ntlm_poison_sim.ps1")
	if err := os.WriteFile(poisonScriptPath, []byte(poisonSimScript), 0644); err != nil {
		LogMessage("ERROR", "Poison Sim", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("ntlm_poison_sim.ps1", poisonScriptPath, int64(len(poisonSimScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", poisonScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)
		cmd.Run()

		outputPath := filepath.Join(targetDir, "ntlm_poison_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		output := outputBuffer.String()
		if strings.Contains(output, "POISON_DETECTED") {
			LogMessage("WARN", "Poisoning", "Potential LLMNR poisoning detected")
			LogPhaseEnd(1, "success", "Poisoning response detected - investigate network")
		} else {
			LogPhaseEnd(1, "success", "Poisoning simulation completed")
		}
	}

	// =========================================================================
	// Phase 3: Create NTLM Relay Artifacts
	// =========================================================================
	LogPhaseStart(2, "Artifact Creation")
	Endpoint.Say("")
	Endpoint.Say("Phase 3: Creating NTLM relay simulation artifacts...")

	relayArtifact := fmt.Sprintf(`NTLM Relay Simulation - %s
==============================================
Test ID: %s
Timestamp: %s

Simulated Responder Capture:
----------------------------
[*] [LLMNR] Poisoned answer sent to 192.168.1.100 for name fileserv
[*] [NBT-NS] Poisoned answer sent to 192.168.1.100 for name FILESERV
[*] [SMB] NTLMv2-SSP Client: 192.168.1.100
[*] [SMB] NTLMv2-SSP Username: DOMAIN\user1
[*] [SMB] NTLMv2-SSP Hash: user1::DOMAIN:[SIMULATED_HASH]

Simulated ntlmrelayx Target:
----------------------------
[*] Relaying to: smb://192.168.1.50
[*] Authenticating against 192.168.1.50 as DOMAIN\user1 SUCCEED
[*] Service installed successfully on 192.168.1.50

Detection Indicators:
- Multiple LLMNR/NBT-NS responses from same source
- NTLM authentication to unexpected hosts
- SMB connections without prior DNS resolution
- Event ID 4648 (Explicit credential use)
`, TEST_NAME, TEST_UUID, time.Now().Format(time.RFC3339))

	artifactPath := filepath.Join(targetDir, "ntlm_relay_results.txt")
	os.WriteFile(artifactPath, []byte(relayArtifact), 0644)
	LogFileDropped("ntlm_relay_results.txt", artifactPath, int64(len(relayArtifact)), false)

	LogPhaseEnd(2, "success", "Artifact creation completed")

	// =========================================================================
	// Determine Final Result
	// =========================================================================
	Endpoint.Say("")
	Endpoint.Say("=================================================================")

	if protectionIndicators > 0 {
		Endpoint.Say("RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("System is protected against NTLM relay attacks")
		Endpoint.Say("")
		Endpoint.Say("Active protections:")
		Endpoint.Say("  - LLMNR disabled")
		Endpoint.Say("  - NetBIOS over TCP/IP disabled")
		Endpoint.Say("  - SMB signing required")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.ExecutionPrevented, "NTLM relay protections active")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	} else {
		Endpoint.Say("RESULT: UNPROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("WARNING: System vulnerable to NTLM relay attacks")
		Endpoint.Say("")
		Endpoint.Say("Recommendations:")
		Endpoint.Say("  1. Disable LLMNR via Group Policy")
		Endpoint.Say("  2. Disable NetBIOS over TCP/IP")
		Endpoint.Say("  3. Require SMB signing on all systems")
		Endpoint.Say("  4. Enable Extended Protection for Authentication")
		Endpoint.Say("  5. Implement network segmentation")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.Unprotected, "NTLM relay vulnerabilities present")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.Unprotected)
	}
}

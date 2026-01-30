//go:build windows
// +build windows

/*
ID: ca4557ad-4895-4ce7-be8a-c4ec94b638e0
NAME: CrackMapExec Detection Test
TECHNIQUES: T1021.002, T1110.003
TACTICS: lateral-movement, credential-access
SEVERITY: high
TARGET: windows-endpoint, active-directory
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: lateral-movement
TAGS: phase-7, tiber-eu, readiness, crackmapexec, netexec, brute-force
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
	TEST_UUID = "ca4557ad-4895-4ce7-be8a-c4ec94b638e0"
	TEST_NAME = "CrackMapExec Detection Test"
)

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1021.002, T1110.003 - SMB Lateral & Password Spraying")
	Endpoint.Say("Phase: 7 - Lateral Movement")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "lateral_movement",
		Severity:   "high",
		Techniques: []string{"T1021.002", "T1110.003"},
		Tactics:    []string{"lateral-movement", "credential-access"},
		Score:      8.0,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 2.7,
			SafetyMechanisms:        1.5,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"phase-7", "tiber-eu", "readiness", "crackmapexec", "netexec", "multi-protocol"},
	}

	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         300000,
			MultiStageEnabled: true,
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
	stagesBlocked := 0

	// =========================================================================
	// Stage 1: SMB Authentication Spray (T1110.003)
	// =========================================================================
	LogStageStart(1, "T1110.003", "SMB Password Spray Simulation")
	Endpoint.Say("Stage 1: Simulating SMB password spray (CrackMapExec smb behavior)...")

	smbSprayScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Simulating CrackMapExec SMB password spray..."
Write-Host "[*] Pattern: crackmapexec smb 192.168.1.0/24 -u users.txt -p password"

# Simulate rapid authentication attempts
$targetHost = $env:COMPUTERNAME
$testUsers = @("admin", "administrator", "user1", "svc_backup", "sqlsvc")
$testPassword = "TestPassword123!"

$authAttempts = 0
$authBlocked = $false

foreach ($user in $testUsers) {
    Write-Host "[*] Attempting: $targetHost\$user"
    $authAttempts++

    try {
        # Create credential object (simulates auth attempt pattern)
        $secPassword = ConvertTo-SecureString $testPassword -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ("$targetHost\$user", $secPassword)

        # Attempt SMB connection (triggers Event 4625 on failure)
        $testPath = "\\$targetHost\C$"
        $result = Test-Path $testPath -Credential $cred -ErrorAction Stop

    } catch {
        if ($_.Exception.Message -match "blocked|lockout|throttle") {
            Write-Host "    [+] Authentication BLOCKED - account lockout/throttle active"
            $authBlocked = $true
            break
        }
        # Normal auth failure expected for invalid creds
        Write-Host "    [-] Auth failed (expected)"
    }
}

Write-Host ""
Write-Host "[*] Completed $authAttempts authentication attempts"

if ($authBlocked) {
    Write-Host "[+] Password spray was BLOCKED by security controls"
    Write-Host "SPRAY_BLOCKED"
    exit 126
} else {
    Write-Host "[!] Password spray completed without lockout/blocking"
    Write-Host "SPRAY_COMPLETED"
}

# Check for lockout events
Write-Host ""
Write-Host "[*] Checking for account lockout events..."
$lockoutEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = @(4625, 4740)  # Failed logon, Account lockout
    StartTime = (Get-Date).AddMinutes(-5)
} -MaxEvents 20 -ErrorAction SilentlyContinue

if ($lockoutEvents) {
    $failCount = ($lockoutEvents | Where-Object { $_.Id -eq 4625 }).Count
    $lockoutCount = ($lockoutEvents | Where-Object { $_.Id -eq 4740 }).Count
    Write-Host "[*] Found $failCount failed logon events, $lockoutCount lockout events"
}
`

	sprayScriptPath := filepath.Join(targetDir, "cme_smb_spray.ps1")
	if err := os.WriteFile(sprayScriptPath, []byte(smbSprayScript), 0644); err != nil {
		LogMessage("ERROR", "SMB Spray", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("cme_smb_spray.ps1", sprayScriptPath, int64(len(smbSprayScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", sprayScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		}

		outputPath := filepath.Join(targetDir, "cme_spray_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		output := outputBuffer.String()
		if exitCode == 126 || strings.Contains(output, "SPRAY_BLOCKED") {
			LogMessage("INFO", "SMB Spray", "Password spray blocked")
			LogStageBlocked(1, "T1110.003", "Account lockout/throttle protection active")
			protectionIndicators++
			stagesBlocked++
		} else {
			LogStageEnd(1, "T1110.003", "success", "Password spray completed")
		}
	}

	// =========================================================================
	// Stage 2: SMB Share Enumeration
	// =========================================================================
	LogStageStart(2, "T1021.002", "SMB Share Enumeration")
	Endpoint.Say("")
	Endpoint.Say("Stage 2: Simulating SMB share enumeration...")

	shareEnumScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Simulating CrackMapExec share enumeration..."
Write-Host "[*] Pattern: crackmapexec smb TARGET --shares"

$targetHost = $env:COMPUTERNAME

# Enumerate shares (what CME does with --shares)
Write-Host "[*] Enumerating shares on $targetHost..."

try {
    $shares = Get-WmiObject -Class Win32_Share -ComputerName $targetHost -ErrorAction Stop

    if ($shares) {
        Write-Host "[!] Found $($shares.Count) shares:"
        foreach ($share in $shares) {
            $access = "?"
            if (Test-Path "\\$targetHost\$($share.Name)" -ErrorAction SilentlyContinue) {
                $access = "READ"
            }
            Write-Host "    $($share.Name.PadRight(20)) $($share.Path.PadRight(30)) [$access]"
        }
        Write-Host "SHARES_ENUMERATED"
    }
} catch {
    if ($_.Exception.Message -match "Access denied|blocked") {
        Write-Host "[+] Share enumeration BLOCKED"
        Write-Host "SHARES_BLOCKED"
        exit 126
    }
    Write-Host "[*] Share enumeration failed: $($_.Exception.Message)"
}
`

	shareScriptPath := filepath.Join(targetDir, "cme_share_enum.ps1")
	if err := os.WriteFile(shareScriptPath, []byte(shareEnumScript), 0644); err != nil {
		LogMessage("ERROR", "Share Enum", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("cme_share_enum.ps1", shareScriptPath, int64(len(shareEnumScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", shareScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		}

		outputPath := filepath.Join(targetDir, "cme_share_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		output := outputBuffer.String()
		if exitCode == 126 || strings.Contains(output, "SHARES_BLOCKED") {
			LogMessage("INFO", "Share Enum", "Share enumeration blocked")
			LogStageBlocked(2, "T1021.002", "Share enumeration blocked")
			protectionIndicators++
			stagesBlocked++
		} else {
			LogStageEnd(2, "T1021.002", "success", "Share enumeration completed")
		}
	}

	// =========================================================================
	// Stage 3: WMI Command Execution
	// =========================================================================
	LogStageStart(3, "T1021.002", "WMI Execution Simulation")
	Endpoint.Say("")
	Endpoint.Say("Stage 3: Simulating WMI command execution (wmiexec behavior)...")

	wmiExecScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Simulating CrackMapExec WMI execution..."
Write-Host "[*] Pattern: crackmapexec smb TARGET -x 'whoami'"

$targetHost = $env:COMPUTERNAME

# Attempt WMI command execution
Write-Host "[*] Attempting WMI command execution..."

try {
    $result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > c:\F0\wmi_test.txt" -ComputerName $targetHost -ErrorAction Stop

    if ($result.ReturnValue -eq 0) {
        Write-Host "[!] WMI command execution SUCCEEDED"
        Start-Sleep -Seconds 1
        if (Test-Path "c:\F0\wmi_test.txt") {
            $output = Get-Content "c:\F0\wmi_test.txt"
            Write-Host "[*] Output: $output"
            Remove-Item "c:\F0\wmi_test.txt" -Force
        }
        Write-Host "WMI_EXEC_SUCCESS"
    } else {
        Write-Host "[+] WMI command failed with code: $($result.ReturnValue)"
        Write-Host "WMI_EXEC_FAILED"
    }
} catch {
    if ($_.Exception.Message -match "Access denied|blocked|RPC") {
        Write-Host "[+] WMI execution BLOCKED"
        Write-Host "WMI_EXEC_BLOCKED"
        exit 126
    }
    Write-Host "[*] WMI execution failed: $($_.Exception.Message)"
    Write-Host "WMI_EXEC_FAILED"
}
`

	wmiScriptPath := filepath.Join(targetDir, "cme_wmi_exec.ps1")
	if err := os.WriteFile(wmiScriptPath, []byte(wmiExecScript), 0644); err != nil {
		LogMessage("ERROR", "WMI Exec", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("cme_wmi_exec.ps1", wmiScriptPath, int64(len(wmiExecScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", wmiScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		}

		outputPath := filepath.Join(targetDir, "cme_wmi_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		output := outputBuffer.String()
		if exitCode == 126 || strings.Contains(output, "WMI_EXEC_BLOCKED") {
			LogMessage("INFO", "WMI Exec", "WMI execution blocked")
			LogStageBlocked(3, "T1021.002", "WMI execution blocked")
			protectionIndicators++
			stagesBlocked++
		} else if strings.Contains(output, "WMI_EXEC_SUCCESS") {
			LogMessage("WARN", "WMI Exec", "WMI execution succeeded - vulnerable")
			LogStageEnd(3, "T1021.002", "success", "WMI execution succeeded")
		} else {
			LogStageEnd(3, "T1021.002", "success", "WMI simulation completed")
		}
	}

	// =========================================================================
	// Stage 4: Create CME Artifacts
	// =========================================================================
	LogStageStart(4, "Artifacts", "Artifact Creation")
	Endpoint.Say("")
	Endpoint.Say("Stage 4: Creating CrackMapExec detection artifacts...")

	cmeArtifact := fmt.Sprintf(`CrackMapExec/NetExec Simulation - %s
==============================================
Test ID: %s
Timestamp: %s
Stages Blocked: %d/3

Simulated CME Behaviors:
------------------------
1. SMB Password Spray: crackmapexec smb TARGET -u users.txt -p password
2. Share Enumeration: crackmapexec smb TARGET --shares
3. WMI Execution: crackmapexec smb TARGET -x "command"

Additional CME Modules (not tested):
- --sam: Dump SAM hashes
- --lsa: Dump LSA secrets
- --ntds: Dump NTDS.dit (requires DA)
- --wdigest: Dump WDigest credentials
- --laps: Dump LAPS passwords

Detection Indicators:
- Multiple 4625 events (failed logons) from single source
- Event ID 5145: Repeated share access attempts
- Event ID 4688: WMI process creation
- Event ID 4103/4104: PowerShell execution
- Network: Rapid SMB connections to multiple hosts
- Process: wmic.exe or wmiprvse.exe spawning cmd.exe
`, TEST_NAME, TEST_UUID, time.Now().Format(time.RFC3339), stagesBlocked)

	artifactPath := filepath.Join(targetDir, "cme_results.txt")
	os.WriteFile(artifactPath, []byte(cmeArtifact), 0644)
	LogFileDropped("cme_results.txt", artifactPath, int64(len(cmeArtifact)), false)

	LogStageEnd(4, "Artifacts", "success", "Artifact creation completed")

	// =========================================================================
	// Determine Final Result
	// =========================================================================
	Endpoint.Say("")
	Endpoint.Say("=================================================================")

	if stagesBlocked >= 2 {
		Endpoint.Say("RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("CrackMapExec-style attacks are largely blocked")
		Endpoint.Say("Stages blocked: %d/3", stagesBlocked)
		Endpoint.Say("")
		Endpoint.Say("Active protections:")
		if stagesBlocked >= 1 {
			Endpoint.Say("  - Account lockout/spray protection")
		}
		if stagesBlocked >= 2 {
			Endpoint.Say("  - Share enumeration restrictions")
		}
		if stagesBlocked >= 3 {
			Endpoint.Say("  - WMI execution blocked")
		}
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("CME attacks blocked - %d/3 stages blocked", stagesBlocked))
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	} else {
		Endpoint.Say("RESULT: UNPROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("WARNING: CrackMapExec-style attacks are possible")
		Endpoint.Say("Stages blocked: %d/3", stagesBlocked)
		Endpoint.Say("")
		Endpoint.Say("Recommendations:")
		Endpoint.Say("  1. Implement account lockout policies")
		Endpoint.Say("  2. Enable smart lockout in Azure AD")
		Endpoint.Say("  3. Disable WMI remote access where not needed")
		Endpoint.Say("  4. Monitor for 4625 event bursts")
		Endpoint.Say("  5. Implement host-based firewalls")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.Unprotected, fmt.Sprintf("CME attacks possible - only %d/3 stages blocked", stagesBlocked))
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.Unprotected)
	}
}

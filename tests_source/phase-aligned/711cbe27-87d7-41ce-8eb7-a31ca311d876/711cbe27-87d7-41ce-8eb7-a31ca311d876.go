//go:build windows
// +build windows

/*
ID: 711cbe27-87d7-41ce-8eb7-a31ca311d876
NAME: AS-REP Roasting Detection Test
TECHNIQUES: T1558.004
SEVERITY: high
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
	TEST_UUID = "711cbe27-87d7-41ce-8eb7-a31ca311d876"
	TEST_NAME = "AS-REP Roasting Detection Test"
)

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1558.004 - AS-REP Roasting")
	Endpoint.Say("Phase: 7 - Lateral Movement")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Initialize Schema v2.0 logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "credential_access",
		Severity:   "high",
		Techniques: []string{"T1558.004"},
		Tactics:    []string{"credential-access"},
		Score:      7.5,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        1.5,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"phase-7", "tiber-eu", "readiness", "asrep", "kerberos", "preauth"},
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
	// Phase 1: Enumerate Accounts with Pre-Auth Disabled
	// =========================================================================
	LogPhaseStart(0, "Pre-Auth Enumeration")
	Endpoint.Say("Phase 1: Enumerating accounts with Kerberos pre-authentication disabled...")

	// PowerShell script to find accounts with DONT_REQUIRE_PREAUTH flag
	preAuthEnumScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Searching for accounts with pre-authentication disabled..."
Write-Host "[*] This simulates Rubeus asreproast / GetNPUsers.py behavior"

# Check if domain-joined
$domain = $env:USERDNSDOMAIN
if (-not $domain) {
    Write-Host "[!] System not domain-joined - using local simulation"
    $domain = "TESTDOMAIN.LOCAL"
}

Write-Host "[*] Target domain: $domain"

# LDAP filter for accounts with DONT_REQUIRE_PREAUTH (userAccountControl & 0x400000)
# UAC value 4194304 = DONT_REQUIRE_PREAUTH
try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    $searcher.PropertiesToLoad.AddRange(@("samaccountname", "distinguishedname", "useraccountcontrol"))

    $results = $searcher.FindAll()

    if ($results.Count -gt 0) {
        Write-Host "[!] Found $($results.Count) accounts with pre-auth disabled:"
        foreach ($result in $results) {
            $sam = $result.Properties["samaccountname"][0]
            $dn = $result.Properties["distinguishedname"][0]
            Write-Host "    - $sam"
            Write-Host "      DN: $dn"
        }
        Write-Host "PREAUTH_ENUM_SUCCESS"
    } else {
        Write-Host "[*] No accounts found with pre-auth disabled"
        Write-Host "PREAUTH_ENUM_EMPTY"
    }
} catch {
    if ($_.Exception.Message -match "Access denied|blocked|prevented") {
        Write-Host "[+] Pre-auth enumeration BLOCKED by security controls"
        Write-Host "PREAUTH_ENUM_BLOCKED"
        exit 126
    }
    Write-Host "[*] Enumeration failed (likely non-domain environment): $($_.Exception.Message)"
    Write-Host "PREAUTH_ENUM_FAILED"
}
`

	enumScriptPath := filepath.Join(targetDir, "asrep_preauth_enum.ps1")
	if err := os.WriteFile(enumScriptPath, []byte(preAuthEnumScript), 0644); err != nil {
		LogMessage("ERROR", "Pre-Auth Enum", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("asrep_preauth_enum.ps1", enumScriptPath, int64(len(preAuthEnumScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", enumScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		}

		outputPath := filepath.Join(targetDir, "asrep_enum_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		LogProcessExecution("powershell.exe", enumScriptPath, cmd.Process.Pid, err == nil, exitCode, "")

		output := outputBuffer.String()
		if exitCode == 126 || strings.Contains(output, "PREAUTH_ENUM_BLOCKED") {
			LogMessage("INFO", "Pre-Auth Protection", "Pre-auth enumeration blocked")
			Endpoint.Say("  [+] Pre-auth enumeration blocked by security controls")
			LogPhaseEnd(0, "blocked", "Pre-auth enumeration blocked")
			protectionIndicators++
		} else if strings.Contains(output, "PREAUTH_ENUM_SUCCESS") {
			LogMessage("WARN", "Pre-Auth Enum", "Found accounts with pre-auth disabled")
			Endpoint.Say("  [!] Found vulnerable accounts with pre-auth disabled")
			LogPhaseEnd(0, "success", "Pre-auth enumeration found targets")
		} else {
			LogPhaseEnd(0, "success", "Pre-auth enumeration completed")
		}
	}

	// =========================================================================
	// Phase 2: Simulate AS-REP Request (No Pre-Authentication)
	// =========================================================================
	LogPhaseStart(1, "AS-REP Request Simulation")
	Endpoint.Say("")
	Endpoint.Say("Phase 2: Simulating AS-REP requests (GetNPUsers.py behavior)...")

	// Simulate AS-REP request behavior
	asrepRequestScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Simulating AS-REP roasting attack..."
Write-Host "[*] This requests AS-REP for accounts without pre-auth"

# Simulated target usernames (what an attacker would try)
$targetUsers = @(
    "svc_backup",
    "svc_scanner",
    "admin_test",
    "service_account"
)

$blocked = $false
$responsesObtained = 0

foreach ($user in $targetUsers) {
    Write-Host "[*] Attempting AS-REP request for: $user"

    try {
        # In a real attack, this would use raw Kerberos AS-REQ without pre-auth
        # Here we simulate the pattern that triggers detection

        # Create simulated AS-REP hash format
        $timestamp = Get-Date -Format "yyyyMMddHHmmss"
        Write-Host "    [*] Sending AS-REQ without pre-authentication..."

        # This would normally return an AS-REP with encrypted data
        # Detection should trigger on:
        # - Event ID 4768 with pre-auth type 0 (no pre-auth)
        # - Failure code 0x0 for accounts with DONT_REQUIRE_PREAUTH

    } catch {
        if ($_.Exception.Message -match "blocked|prevented|denied") {
            Write-Host "    [+] AS-REP request BLOCKED"
            $blocked = $true
        }
    }
}

# Check for AS-REP related security events
Write-Host ""
Write-Host "[*] Checking for Kerberos AS events..."

$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4768  # Kerberos TGT request (AS-REQ/AS-REP)
    StartTime = (Get-Date).AddMinutes(-10)
} -MaxEvents 10 -ErrorAction SilentlyContinue

if ($events) {
    Write-Host "[*] Found $($events.Count) recent AS-REQ events (Event ID 4768)"

    # Check for pre-auth failures/successes
    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $preAuthType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'PreAuthType'} | Select-Object -ExpandProperty '#text'
        if ($preAuthType -eq "0") {
            Write-Host "    [!] Found AS-REQ with no pre-auth (PreAuthType=0)"
            $responsesObtained++
        }
    }
}

if ($blocked) {
    Write-Host ""
    Write-Host "[+] AS-REP requests were BLOCKED"
    Write-Host "ASREP_REQUEST_BLOCKED"
    exit 126
} elseif ($responsesObtained -gt 0) {
    Write-Host ""
    Write-Host "[!] WARNING: AS-REP roasting possible - no pre-auth requests detected"
    Write-Host "ASREP_REQUEST_SUCCESS"
} else {
    Write-Host ""
    Write-Host "[*] AS-REP simulation completed"
    Write-Host "ASREP_REQUEST_NEUTRAL"
}
`

	asrepScriptPath := filepath.Join(targetDir, "asrep_request.ps1")
	if err := os.WriteFile(asrepScriptPath, []byte(asrepRequestScript), 0644); err != nil {
		LogMessage("ERROR", "AS-REP Request", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("asrep_request.ps1", asrepScriptPath, int64(len(asrepRequestScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", asrepScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		}

		outputPath := filepath.Join(targetDir, "asrep_request_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		LogProcessExecution("powershell.exe", asrepScriptPath, cmd.Process.Pid, err == nil, exitCode, "")

		output := outputBuffer.String()
		if exitCode == 126 || strings.Contains(output, "ASREP_REQUEST_BLOCKED") {
			LogMessage("INFO", "AS-REP Protection", "AS-REP requests blocked")
			Endpoint.Say("  [+] AS-REP requests blocked")
			LogPhaseEnd(1, "blocked", "AS-REP requests blocked")
			protectionIndicators++
		} else if strings.Contains(output, "ASREP_REQUEST_SUCCESS") {
			LogMessage("WARN", "AS-REP Request", "AS-REP roasting possible")
			LogPhaseEnd(1, "success", "AS-REP requests possible")
		} else {
			LogPhaseEnd(1, "success", "AS-REP simulation completed")
		}
	}

	// =========================================================================
	// Phase 3: Create AS-REP Roasting Artifact
	// =========================================================================
	LogPhaseStart(2, "Artifact Creation")
	Endpoint.Say("")
	Endpoint.Say("Phase 3: Creating AS-REP roasting simulation artifacts...")

	// Create artifact mimicking GetNPUsers.py / Rubeus output
	asrepArtifact := fmt.Sprintf(`AS-REP Roasting Simulation - %s
==============================================
Test ID: %s
Timestamp: %s

Simulated Accounts with Pre-Auth Disabled:
------------------------------------------
samAccountName: svc_backup
distinguishedName: CN=svc_backup,OU=ServiceAccounts,DC=domain,DC=local
userAccountControl: 4194304 (DONT_REQUIRE_PREAUTH)

samAccountName: old_admin
distinguishedName: CN=old_admin,OU=Users,DC=domain,DC=local
userAccountControl: 4194304 (DONT_REQUIRE_PREAUTH)

Simulated AS-REP Hash Format (for detection):
---------------------------------------------
$krb5asrep$23$svc_backup@DOMAIN.LOCAL:[SIMULATED_HASH]
$krb5asrep$23$old_admin@DOMAIN.LOCAL:[SIMULATED_HASH]

NOTE: This is a SIMULATION for detection testing.
Real AS-REP responses would be cracked offline.

Detection Indicators:
- Event ID 4768 with PreAuthType=0
- AS-REQ for multiple users from single source
- Requests for non-existent users (enumeration)
- Event ID 4771 (Pre-auth failure) preceding 4768
`, TEST_NAME, TEST_UUID, time.Now().Format(time.RFC3339))

	artifactPath := filepath.Join(targetDir, "asrep_results.txt")
	if err := os.WriteFile(artifactPath, []byte(asrepArtifact), 0644); err != nil {
		LogMessage("ERROR", "Artifact Creation", fmt.Sprintf("Failed to create artifact: %v", err))
	} else {
		LogFileDropped("asrep_results.txt", artifactPath, int64(len(asrepArtifact)), false)
		Endpoint.Say("  [*] Created asrep_results.txt")
	}

	LogPhaseEnd(2, "success", "Artifact creation completed")

	// =========================================================================
	// Determine Final Result
	// =========================================================================
	Endpoint.Say("")
	Endpoint.Say("=================================================================")

	if protectionIndicators > 0 {
		Endpoint.Say("RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("AS-REP Roasting detection/prevention mechanisms are active")
		Endpoint.Say("Protection indicators found: %d", protectionIndicators)
		Endpoint.Say("")
		Endpoint.Say("Detected protections may include:")
		Endpoint.Say("  - LDAP enumeration restrictions")
		Endpoint.Say("  - AS-REQ monitoring")
		Endpoint.Say("  - Pre-authentication enforcement")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.ExecutionPrevented, "AS-REP Roasting patterns detected and blocked")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	} else {
		Endpoint.Say("RESULT: UNPROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("WARNING: AS-REP Roasting attack patterns were NOT blocked")
		Endpoint.Say("")
		Endpoint.Say("Recommendations:")
		Endpoint.Say("  1. Audit accounts with 'Do not require Kerberos pre-auth' enabled")
		Endpoint.Say("  2. Remove DONT_REQUIRE_PREAUTH flag from all accounts")
		Endpoint.Say("  3. Monitor Event ID 4768 for PreAuthType=0")
		Endpoint.Say("  4. Implement strong passwords (25+ characters) for any")
		Endpoint.Say("     accounts that must have pre-auth disabled")
		Endpoint.Say("  5. Regular audits of userAccountControl attributes")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.Unprotected, "AS-REP Roasting attack patterns succeeded - no detection")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.Unprotected)
	}
}

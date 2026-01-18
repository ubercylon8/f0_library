//go:build windows
// +build windows

/*
ID: 6ded8b8c-046c-491f-bc7d-85bcc762fae7
NAME: Kerberoasting Detection Test
TECHNIQUES: T1558.003
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
	TEST_UUID = "6ded8b8c-046c-491f-bc7d-85bcc762fae7"
	TEST_NAME = "Kerberoasting Detection Test"
)

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1558.003 - Kerberoasting")
	Endpoint.Say("Phase: 7 - Lateral Movement")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Initialize Schema v2.0 logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "credential_access",
		Severity:   "critical",
		Techniques: []string{"T1558.003"},
		Tactics:    []string{"credential-access"},
		Score:      7.8,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        1.5,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"phase-7", "tiber-eu", "readiness", "kerberoasting", "spn", "kerberos"},
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
	// Phase 1: Enumerate Service Principal Names (SPNs)
	// =========================================================================
	LogPhaseStart(0, "SPN Enumeration")
	Endpoint.Say("Phase 1: Enumerating Service Principal Names (SPNs)...")

	// PowerShell script to enumerate SPNs (Rubeus/GetUserSPNs.py behavior)
	spnEnumScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Starting SPN enumeration (Kerberoasting reconnaissance)..."

# Check if domain-joined
$domain = $env:USERDNSDOMAIN
if (-not $domain) {
    Write-Host "[!] System not domain-joined - using local simulation"
    $domain = "TESTDOMAIN.LOCAL"
}

Write-Host "[*] Target domain: $domain"

# Attempt LDAP query for SPNs (what Rubeus/GetUserSPNs.py does)
try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))"
    $searcher.PropertiesToLoad.AddRange(@("samaccountname", "serviceprincipalname", "pwdlastset"))

    $results = $searcher.FindAll()

    if ($results.Count -gt 0) {
        Write-Host "[!] Found $($results.Count) accounts with SPNs:"
        foreach ($result in $results) {
            $sam = $result.Properties["samaccountname"][0]
            $spns = $result.Properties["serviceprincipalname"]
            Write-Host "    - $sam : $($spns -join ', ')"
        }
        Write-Host "SPN_ENUM_SUCCESS"
    } else {
        Write-Host "[*] No user accounts with SPNs found (or not domain-joined)"
        Write-Host "SPN_ENUM_EMPTY"
    }
} catch {
    if ($_.Exception.Message -match "Access denied|blocked|prevented|0x80070005") {
        Write-Host "[+] SPN enumeration BLOCKED by security controls"
        Write-Host "SPN_ENUM_BLOCKED"
        exit 126
    }
    Write-Host "[*] SPN enumeration failed: $($_.Exception.Message)"
    Write-Host "SPN_ENUM_FAILED"
}
`

	spnScriptPath := filepath.Join(targetDir, "kerberoast_spn_enum.ps1")
	if err := os.WriteFile(spnScriptPath, []byte(spnEnumScript), 0644); err != nil {
		LogMessage("ERROR", "SPN Enumeration", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("kerberoast_spn_enum.ps1", spnScriptPath, int64(len(spnEnumScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", spnScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		}

		outputPath := filepath.Join(targetDir, "kerberoast_spn_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		LogProcessExecution("powershell.exe", spnScriptPath, cmd.Process.Pid, err == nil, exitCode, "")

		output := outputBuffer.String()
		if exitCode == 126 || strings.Contains(output, "SPN_ENUM_BLOCKED") {
			LogMessage("INFO", "SPN Protection", "SPN enumeration blocked")
			Endpoint.Say("  [+] SPN enumeration blocked by security controls")
			LogPhaseEnd(0, "blocked", "SPN enumeration blocked")
			protectionIndicators++
		} else if strings.Contains(output, "SPN_ENUM_SUCCESS") {
			LogMessage("WARN", "SPN Enumeration", "SPN enumeration succeeded - found targets")
			Endpoint.Say("  [!] SPN enumeration succeeded")
			LogPhaseEnd(0, "success", "SPN enumeration completed - targets found")
		} else {
			LogPhaseEnd(0, "success", "SPN enumeration completed")
		}
	}

	// =========================================================================
	// Phase 2: Simulate TGS Request for SPN (Kerberoasting)
	// =========================================================================
	LogPhaseStart(1, "TGS Request Simulation")
	Endpoint.Say("")
	Endpoint.Say("Phase 2: Simulating TGS service ticket requests...")

	// This simulates what Rubeus kerberoast does - requests TGS tickets for SPNs
	tgsRequestScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Simulating Kerberoasting TGS requests..."

# Common service SPNs that attackers target
$targetSPNs = @(
    "MSSQLSvc/sql01.domain.local:1433",
    "HTTP/webserver.domain.local",
    "CIFS/fileserver.domain.local",
    "LDAP/dc01.domain.local"
)

$blocked = $false
$ticketsRequested = 0

foreach ($spn in $targetSPNs) {
    Write-Host "[*] Requesting TGS for: $spn"

    try {
        # Add-Type for Kerberos ticket request
        Add-Type -AssemblyName System.IdentityModel -ErrorAction Stop

        # Create a KerberosRequestorSecurityToken (simulates TGS request)
        # This is what triggers Event ID 4769
        $token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn -ErrorAction Stop

        Write-Host "    [!] TGS ticket obtained for $spn"
        $ticketsRequested++

    } catch {
        if ($_.Exception.Message -match "blocked|prevented|denied") {
            Write-Host "    [+] TGS request BLOCKED for $spn"
            $blocked = $true
        } else {
            # Expected failure for non-existent SPNs in test environment
            Write-Host "    [-] TGS request failed (expected in non-domain environment)"
        }
    }
}

if ($blocked) {
    Write-Host ""
    Write-Host "[+] Kerberoasting TGS requests were BLOCKED"
    Write-Host "TGS_REQUEST_BLOCKED"
    exit 126
} elseif ($ticketsRequested -gt 0) {
    Write-Host ""
    Write-Host "[!] WARNING: $ticketsRequested TGS tickets obtained - Kerberoasting possible"
    Write-Host "TGS_REQUEST_SUCCESS"
    exit 101
} else {
    Write-Host ""
    Write-Host "[*] TGS requests completed (likely non-domain environment)"
    Write-Host "TGS_REQUEST_NEUTRAL"
}
`

	tgsScriptPath := filepath.Join(targetDir, "kerberoast_tgs_request.ps1")
	if err := os.WriteFile(tgsScriptPath, []byte(tgsRequestScript), 0644); err != nil {
		LogMessage("ERROR", "TGS Request", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("kerberoast_tgs_request.ps1", tgsScriptPath, int64(len(tgsRequestScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", tgsScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		}

		outputPath := filepath.Join(targetDir, "kerberoast_tgs_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		LogProcessExecution("powershell.exe", tgsScriptPath, cmd.Process.Pid, err == nil, exitCode, "")

		output := outputBuffer.String()
		if exitCode == 126 || strings.Contains(output, "TGS_REQUEST_BLOCKED") {
			LogMessage("INFO", "TGS Protection", "TGS requests blocked")
			Endpoint.Say("  [+] TGS ticket requests blocked")
			LogPhaseEnd(1, "blocked", "TGS requests blocked by security controls")
			protectionIndicators++
		} else if strings.Contains(output, "TGS_REQUEST_SUCCESS") {
			LogMessage("WARN", "TGS Request", "TGS tickets obtained - kerberoasting possible")
			Endpoint.Say("  [!] TGS tickets obtained - vulnerable to kerberoasting")
			LogPhaseEnd(1, "success", "TGS tickets obtained")
		} else {
			LogPhaseEnd(1, "success", "TGS request simulation completed")
		}
	}

	// =========================================================================
	// Phase 3: Simulate Ticket Export (Rubeus dump style)
	// =========================================================================
	LogPhaseStart(2, "Ticket Export Simulation")
	Endpoint.Say("")
	Endpoint.Say("Phase 3: Simulating Kerberos ticket export...")

	// Simulate klist command to export tickets (what attackers do after getting TGS)
	ticketExportScript := `
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Simulating Kerberos ticket export (Rubeus dump behavior)..."

# Run klist to list current tickets
Write-Host "[*] Running klist to enumerate cached tickets..."
$klistOutput = klist 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "[*] Cached Kerberos tickets:"
    Write-Host $klistOutput

    # Count tickets
    $ticketCount = ([regex]::Matches($klistOutput, "Server:")).Count
    Write-Host ""
    Write-Host "[*] Found $ticketCount cached ticket(s)"

    # Simulate hash extraction format (what would be cracked offline)
    Write-Host ""
    Write-Host "[*] In a real attack, tickets would be exported in hashcat format:"
    Write-Host '    $krb5tgs$23$*user$DOMAIN$SPN*$hash...'

    Write-Host "TICKET_EXPORT_SUCCESS"
} else {
    Write-Host "[*] klist failed or no tickets cached"
    Write-Host "TICKET_EXPORT_EMPTY"
}

# Check for suspicious klist usage in recent events
Write-Host ""
Write-Host "[*] Checking for Kerberos-related security events..."

$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4769  # TGS request
    StartTime = (Get-Date).AddMinutes(-10)
} -MaxEvents 5 -ErrorAction SilentlyContinue

if ($events) {
    Write-Host "[!] Found $($events.Count) recent TGS request events (Event ID 4769)"
    Write-Host "KERBEROS_EVENTS_FOUND"
} else {
    Write-Host "[*] No recent TGS request events found"
}
`

	ticketScriptPath := filepath.Join(targetDir, "kerberoast_ticket_export.ps1")
	if err := os.WriteFile(ticketScriptPath, []byte(ticketExportScript), 0644); err != nil {
		LogMessage("ERROR", "Ticket Export", fmt.Sprintf("Failed to write script: %v", err))
	} else {
		LogFileDropped("kerberoast_ticket_export.ps1", ticketScriptPath, int64(len(ticketExportScript)), false)

		var outputBuffer bytes.Buffer
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", ticketScriptPath)
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)
		cmd.Run()

		outputPath := filepath.Join(targetDir, "kerberoast_ticket_output.txt")
		os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)

		LogPhaseEnd(2, "success", "Ticket export simulation completed")
	}

	// =========================================================================
	// Phase 4: Create Kerberoasting Artifact File
	// =========================================================================
	LogPhaseStart(3, "Artifact Creation")
	Endpoint.Say("")
	Endpoint.Say("Phase 4: Creating Kerberoasting simulation artifacts...")

	// Create a file that mimics Rubeus output format
	kerberoastArtifact := fmt.Sprintf(`Kerberoasting Simulation - %s
==============================================
Test ID: %s
Timestamp: %s

Simulated Kerberoastable Accounts:
----------------------------------
ServicePrincipalName: MSSQLSvc/sql01.domain.local:1433
samAccountName: sqlsvc
pwdLastSet: 2024-06-15 10:30:00

ServicePrincipalName: HTTP/webapp.domain.local
samAccountName: websvc
pwdLastSet: 2023-12-01 08:15:00

ServicePrincipalName: LDAP/dc01.domain.local
samAccountName: ldapsvc
pwdLastSet: 2024-01-20 14:45:00

Simulated Hash Format (for detection):
--------------------------------------
$krb5tgs$23$*sqlsvc$DOMAIN.LOCAL$MSSQLSvc/sql01.domain.local:1433*$[SIMULATED_HASH]
$krb5tgs$23$*websvc$DOMAIN.LOCAL$HTTP/webapp.domain.local*$[SIMULATED_HASH]

NOTE: This is a SIMULATION for detection testing.
Real hashes would be cracked offline using hashcat/john.

Detection Indicators:
- Event ID 4769 with RC4 encryption (0x17)
- High volume TGS requests from single source
- TGS requests for multiple SPNs in short timeframe
`, TEST_NAME, TEST_UUID, time.Now().Format(time.RFC3339))

	artifactPath := filepath.Join(targetDir, "kerberoast_results.txt")
	if err := os.WriteFile(artifactPath, []byte(kerberoastArtifact), 0644); err != nil {
		LogMessage("ERROR", "Artifact Creation", fmt.Sprintf("Failed to create artifact: %v", err))
	} else {
		LogFileDropped("kerberoast_results.txt", artifactPath, int64(len(kerberoastArtifact)), false)
		Endpoint.Say("  [*] Created kerberoast_results.txt")
	}

	LogPhaseEnd(3, "success", "Artifact creation completed")

	// =========================================================================
	// Determine Final Result
	// =========================================================================
	Endpoint.Say("")
	Endpoint.Say("=================================================================")

	if protectionIndicators > 0 {
		Endpoint.Say("RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("Kerberoasting detection/prevention mechanisms are active")
		Endpoint.Say("Protection indicators found: %d", protectionIndicators)
		Endpoint.Say("")
		Endpoint.Say("Detected protections may include:")
		Endpoint.Say("  - SPN enumeration restrictions")
		Endpoint.Say("  - TGS request monitoring/blocking")
		Endpoint.Say("  - Kerberos ticket request anomaly detection")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.ExecutionPrevented, "Kerberoasting patterns detected and blocked")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	} else {
		Endpoint.Say("RESULT: UNPROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("WARNING: Kerberoasting attack patterns were NOT blocked")
		Endpoint.Say("")
		Endpoint.Say("Recommendations:")
		Endpoint.Say("  1. Monitor Event ID 4769 for RC4 ticket encryption (0x17)")
		Endpoint.Say("  2. Alert on high-volume TGS requests from single source")
		Endpoint.Say("  3. Use Group Managed Service Accounts (gMSA)")
		Endpoint.Say("  4. Enforce AES256 for service accounts")
		Endpoint.Say("  5. Implement honeypot service accounts with SPNs")
		Endpoint.Say("  6. Regular password rotation for service accounts")
		Endpoint.Say("=================================================================")

		SaveLog(Endpoint.Unprotected, "Kerberoasting attack patterns succeeded - no detection")
		time.Sleep(3 * time.Second)
		Endpoint.Stop(Endpoint.Unprotected)
	}
}

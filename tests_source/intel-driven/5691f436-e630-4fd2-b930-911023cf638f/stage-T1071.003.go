//go:build windows
// +build windows

/*
STAGE 2: Application Layer Protocol - Mail Protocols (T1071.003)
Simulates APT34's PowerExchange email-based C2 channel.
Creates email-like artifacts with "@@" subject markers as command delivery mechanism.
*/

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "5691f436-e630-4fd2-b930-911023cf638f"
	TECHNIQUE_ID   = "T1071.003"
	TECHNIQUE_NAME = "Application Layer Protocol: Mail Protocols"
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

	LogMessage("INFO", TECHNIQUE_ID, "Starting PowerExchange Email-Based C2 simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Simulate email-based C2 channel with @@ subject markers")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique blocked/failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Blocked/Failed: %v", err))
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		exitCode := determineExitCode(err)
		os.Exit(exitCode)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, "PowerExchange C2 simulation completed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Email-based C2 channel established without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "c:\\F0"
	c2Dir := filepath.Join(targetDir, "powerexchange_c2")

	// Step 1: Create PowerExchange C2 directory structure
	LogMessage("INFO", TECHNIQUE_ID, "Creating PowerExchange C2 infrastructure...")
	fmt.Printf("[STAGE %s] Setting up PowerExchange email-based C2 infrastructure\n", TECHNIQUE_ID)

	if err := os.MkdirAll(c2Dir, 0755); err != nil {
		return fmt.Errorf("failed to create C2 directory: %v", err)
	}

	// Step 2: Create simulated PowerExchange backdoor script
	// APT34's PowerExchange is a PowerShell-based backdoor that monitors Exchange
	// mailboxes for emails with "@@" in the subject line as C2 commands
	LogMessage("INFO", TECHNIQUE_ID, "Deploying simulated PowerExchange backdoor...")
	fmt.Printf("[STAGE %s] Deploying PowerExchange backdoor (PowerShell-based Exchange C2)\n", TECHNIQUE_ID)

	powerExchangeScript := `# F0RT1KA SIMULATION: APT34 PowerExchange Backdoor
# This is a SIMULATION - does NOT connect to any Exchange server
# Real PowerExchange monitors Exchange mailboxes for C2 commands

# PowerExchange Configuration
$C2_MARKER = "@@"
$POLL_INTERVAL = 120  # seconds
$EXCHANGE_SERVER = "mail.target-corp.local"
$MAILBOX = "svc-exchange@target-corp.local"

# Simulated C2 loop (NOT EXECUTED - for artifact generation only)
function Start-PowerExchangeC2 {
    Write-Host "[PowerExchange] Initializing email-based C2..."
    Write-Host "[PowerExchange] Monitoring mailbox: $MAILBOX"
    Write-Host "[PowerExchange] C2 marker: $C2_MARKER"
    Write-Host "[PowerExchange] Poll interval: ${POLL_INTERVAL}s"

    # Monitor inbox for emails with @@ subject pattern
    # Real implementation uses Exchange Web Services (EWS) API
    while ($true) {
        # Search for unread emails with @@ in subject
        # $emails = Get-MailboxMessage -Mailbox $MAILBOX | Where-Object { $_.Subject -match "@@" }

        # Process C2 commands from email subjects
        # Format: @@<base64-encoded-command>
        # Example: @@d2hvYW1p (whoami)

        # Execute command and send results as reply
        # $result = Invoke-Expression $decodedCommand
        # Send-MailMessage -To $sender -Subject "Re: $originalSubject" -Body $result

        Start-Sleep -Seconds $POLL_INTERVAL
    }
}

# SIMULATION MARKER - Script is not executed
Write-Host "[F0RT1KA] PowerExchange backdoor simulation artifact"
`

	scriptPath := filepath.Join(c2Dir, "PowerExchange.ps1")
	if err := os.WriteFile(scriptPath, []byte(powerExchangeScript), 0644); err != nil {
		return fmt.Errorf("failed to write PowerExchange script: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("PowerExchange backdoor script deployed: %s", scriptPath))

	// Step 3: Create simulated C2 command emails with @@ markers
	LogMessage("INFO", TECHNIQUE_ID, "Generating simulated C2 command emails with @@ markers...")
	fmt.Printf("[STAGE %s] Creating C2 command emails with @@ subject markers\n", TECHNIQUE_ID)

	c2Commands := []struct {
		command  string
		encoded  string
		response string
	}{
		{
			command:  "whoami",
			encoded:  base64.StdEncoding.EncodeToString([]byte("whoami")),
			response: "nt authority\\system",
		},
		{
			command:  "ipconfig /all",
			encoded:  base64.StdEncoding.EncodeToString([]byte("ipconfig /all")),
			response: "Windows IP Configuration\n  Host Name: EXCH-SRV01\n  Primary DNS Suffix: target-corp.local\n  IPv4 Address: 10.0.1.50",
		},
		{
			command:  "net user /domain",
			encoded:  base64.StdEncoding.EncodeToString([]byte("net user /domain")),
			response: "Administrator  Guest  krbtgt  svc-exchange  svc-backup",
		},
		{
			command:  "Get-Process | Select Name,Id",
			encoded:  base64.StdEncoding.EncodeToString([]byte("Get-Process | Select Name,Id")),
			response: "msexchangeservicehost  3456\nw3wp  7890\nsvchost  1234\nlsass  678",
		},
	}

	emailDir := filepath.Join(c2Dir, "c2_emails")
	if err := os.MkdirAll(emailDir, 0755); err != nil {
		return fmt.Errorf("failed to create email directory: %v", err)
	}

	for i, cmd := range c2Commands {
		timestamp := time.Now().Add(time.Duration(-i*5) * time.Minute).Format("2006-01-02T15:04:05Z")

		// Create inbound C2 command email
		inboundEmail := fmt.Sprintf(`From: operator@c2-infrastructure.net
To: svc-exchange@target-corp.local
Subject: @@%s
Date: %s
Message-ID: <c2cmd-%d@c2-infrastructure.net>
X-Mailer: PowerExchange-C2
Content-Type: text/plain

C2 Command Delivery
Decoded: %s
`, cmd.encoded, timestamp, i+1, cmd.command)

		inboundPath := filepath.Join(emailDir, fmt.Sprintf("c2_inbound_%d.eml", i+1))
		if err := os.WriteFile(inboundPath, []byte(inboundEmail), 0644); err != nil {
			return fmt.Errorf("failed to write C2 email %d: %v", i+1, err)
		}

		// Create outbound response email
		outboundEmail := fmt.Sprintf(`From: svc-exchange@target-corp.local
To: operator@c2-infrastructure.net
Subject: Re: @@%s
Date: %s
Message-ID: <c2resp-%d@target-corp.local>
In-Reply-To: <c2cmd-%d@c2-infrastructure.net>
Content-Type: text/plain

%s
`, cmd.encoded, timestamp, i+1, i+1, cmd.response)

		outboundPath := filepath.Join(emailDir, fmt.Sprintf("c2_outbound_%d.eml", i+1))
		if err := os.WriteFile(outboundPath, []byte(outboundEmail), 0644); err != nil {
			return fmt.Errorf("failed to write C2 response %d: %v", i+1, err)
		}

		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("C2 email pair %d created: command='%s'", i+1, cmd.command))
	}

	fmt.Printf("[STAGE %s] Created %d C2 command/response email pairs\n", TECHNIQUE_ID, len(c2Commands))

	// Step 4: Create C2 channel status file
	statusContent := fmt.Sprintf(`# PowerExchange C2 Channel Status
# Generated: %s
# Test: %s

Channel Status: ACTIVE (SIMULATED)
C2 Marker: @@
Transport: Exchange Web Services (EWS)
Mailbox: svc-exchange@target-corp.local
Exchange Server: mail.target-corp.local
Commands Processed: %d
Last Command: %s
Poll Interval: 120 seconds

# Detection Indicators:
# - Emails with @@ in subject line (C2 marker)
# - Automated replies from service accounts
# - PowerShell EWS API calls from Exchange server
# - Unusual mailbox access patterns for service accounts
`, time.Now().Format(time.RFC3339), TEST_UUID, len(c2Commands), c2Commands[len(c2Commands)-1].command)

	statusPath := filepath.Join(c2Dir, "c2_status.txt")
	if err := os.WriteFile(statusPath, []byte(statusContent), 0644); err != nil {
		return fmt.Errorf("failed to write C2 status: %v", err)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("PowerExchange C2 simulation complete: %d emails, status file created", len(c2Commands)*2))
	fmt.Printf("[STAGE %s] Email-based C2 infrastructure established successfully\n", TECHNIQUE_ID)
	return nil
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "access denied") ||
		strings.Contains(errStr, "permission denied") ||
		strings.Contains(errStr, "blocked") ||
		strings.Contains(errStr, "prevented") {
		return StageBlocked
	}
	if strings.Contains(errStr, "quarantine") ||
		strings.Contains(errStr, "quarantined") {
		return StageQuarantined
	}
	return StageBlocked
}

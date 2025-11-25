//go:build windows
// +build windows

/*
EDR Network Isolation Test - Cleanup Utility

This utility restores EDR/AV services that were stopped or disabled by the test.

Usage:
  Run as Administrator: .\cleanup_utility.exe

What it does:
  1. Restarts stopped EDR/AV services
  2. Re-enables disabled services (sets startup type to Automatic)
  3. Verifies services are running
  4. Reports restoration status

Note: WFP filters created by the test are non-persistent and automatically
removed when the test exits. This utility only handles service restoration.
*/

package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Common EDR/AV services that might have been affected by the test
var commonEDRServices = []struct {
	Name    string
	Product string
}{
	// Microsoft
	{"WinDefend", "Windows Defender"},
	{"Sense", "Microsoft Defender for Endpoint"},
	{"WdNisSvc", "Windows Defender Network Inspection"},

	// CrowdStrike
	{"CSAgent", "CrowdStrike Falcon"},
	{"CSFalconService", "CrowdStrike Falcon"},

	// SentinelOne
	{"SentinelAgent", "SentinelOne"},
	{"SentinelStaticEngine", "SentinelOne Static Engine"},

	// Carbon Black
	{"CarbonBlack", "Carbon Black"},
	{"RepMgr", "Carbon Black Response"},

	// Cylance
	{"CylanceSvc", "Cylance"},

	// Symantec
	{"SepMasterService", "Symantec Endpoint Protection"},
	{"SepScanService", "Symantec Scan Service"},

	// McAfee/Trellix
	{"McAfeeFramework", "McAfee Framework"},
	{"McShield", "McAfee Shield"},
	{"mfemms", "McAfee Endpoint Security"},

	// Trend Micro
	{"TMBMServer", "Trend Micro"},
	{"ntrtscan", "Trend Micro"},

	// Palo Alto
	{"CyveraService", "Palo Alto Cortex XDR"},

	// FireEye
	{"xagt", "FireEye Endpoint Agent"},

	// Sophos
	{"Sophos Agent", "Sophos Agent"},
	{"SAVService", "Sophos Anti-Virus"},

	// ESET
	{"ekrn", "ESET"},

	// Kaspersky
	{"AVP", "Kaspersky"},

	// Tanium
	{"TaniumClient", "Tanium"},

	// Cisco
	{"sfc", "Cisco Secure Endpoint"},

	// FortiClient
	{"FortiClient", "FortiClient"},

	// Bitdefender
	{"EPINTEGRATIONSERVICE", "Bitdefender"},
	{"EPSecurityService", "Bitdefender Security Service"},

	// Webroot
	{"WRSVC", "Webroot SecureAnywhere"},
}

func main() {
	fmt.Println("=================================================================")
	fmt.Println("EDR Network Isolation Test - Cleanup Utility")
	fmt.Println("=================================================================")
	fmt.Println()

	if !checkIsAdmin() {
		fmt.Println("❌ ERROR: Administrator privileges required")
		fmt.Println("Please run this utility as Administrator")
		fmt.Println()
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}

	fmt.Println("This utility will restore EDR/AV services that were affected by the test:")
	fmt.Println("  • Restart stopped services")
	fmt.Println("  • Re-enable disabled services (set to Automatic startup)")
	fmt.Println("  • Verify services are running")
	fmt.Println()
	fmt.Println("Note: WFP filters are non-persistent and already removed automatically.")
	fmt.Println()
	fmt.Println("Starting cleanup...")
	fmt.Println()

	// Connect to Service Control Manager
	m, err := mgr.Connect()
	if err != nil {
		fmt.Printf("❌ Failed to connect to Service Control Manager: %v\n", err)
		fmt.Println()
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}
	defer m.Disconnect()

	fmt.Println("✓ Connected to Service Control Manager")
	fmt.Println()

	restoredCount := 0
	notFoundCount := 0
	errorCount := 0

	for _, svc := range commonEDRServices {
		result := restoreService(m, svc.Name, svc.Product)
		switch result {
		case "restored":
			restoredCount++
		case "not_found":
			notFoundCount++
		case "error":
			errorCount++
		}
	}

	// Summary
	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Println("Cleanup Summary")
	fmt.Println("=================================================================")
	fmt.Printf("Services restored:  %d\n", restoredCount)
	fmt.Printf("Services not found: %d (not installed on this system)\n", notFoundCount)
	fmt.Printf("Errors encountered: %d\n", errorCount)
	fmt.Println()

	if restoredCount > 0 {
		fmt.Println("✓ EDR/AV services have been restored to running state")
	} else {
		fmt.Println("ℹ No services needed restoration (already running or not installed)")
	}

	fmt.Println()
	fmt.Println("Cleanup complete!")
	fmt.Println()
	fmt.Println("Press Enter to exit...")
	fmt.Scanln()
}

// restoreService attempts to restore a service to running state with automatic startup
func restoreService(m *mgr.Mgr, serviceName, product string) string {
	s, err := m.OpenService(serviceName)
	if err != nil {
		// Service doesn't exist on this system
		return "not_found"
	}
	defer s.Close()

	// Query current state
	status, err := s.Query()
	if err != nil {
		fmt.Printf("  ⚠ %s (%s): Failed to query status\n", serviceName, product)
		return "error"
	}

	needsRestore := false
	actions := []string{}

	// Check if service needs to be started
	if status.State == svc.Stopped {
		needsRestore = true
		actions = append(actions, "start")
	}

	// Check startup type and set to automatic if needed
	cfg, err := s.Config()
	if err != nil {
		if needsRestore {
			fmt.Printf("  ⚠ %s (%s): Service stopped but failed to check startup type\n", serviceName, product)
		}
	} else {
		// If startup type is disabled or manual, set to automatic
		if cfg.StartType == mgr.StartDisabled || cfg.StartType == mgr.StartManual {
			needsRestore = true
			actions = append(actions, "enable")
		}
	}

	if !needsRestore {
		// Service is already running with proper startup type
		return "not_found"
	}

	// Perform restoration
	fmt.Printf("  → Restoring %s (%s)...", serviceName, product)

	// Set startup type to automatic first
	if contains(actions, "enable") {
		cfg.StartType = mgr.StartAutomatic
		err = s.UpdateConfig(cfg)
		if err != nil {
			fmt.Printf(" ❌ Failed to set automatic startup: %v\n", err)
			return "error"
		}
	}

	// Start the service if it's stopped
	if contains(actions, "start") {
		err = s.Start()
		if err != nil {
			fmt.Printf(" ❌ Failed to start: %v\n", err)
			return "error"
		}

		// Wait for service to start (up to 30 seconds)
		timeout := time.Now().Add(30 * time.Second)
		for {
			status, err := s.Query()
			if err != nil {
				break
			}
			if status.State == svc.Running {
				break
			}
			if time.Now().After(timeout) {
				fmt.Printf(" ⚠ Timeout waiting for service to start\n")
				return "error"
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	fmt.Printf(" ✓ Restored\n")
	return "restored"
}

// checkIsAdmin checks if the current process has administrator privileges
func checkIsAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

// contains checks if a string slice contains a string
func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

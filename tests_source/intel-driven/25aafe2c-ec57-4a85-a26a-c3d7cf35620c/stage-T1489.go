//go:build windows
// +build windows

/*
STAGE 3: VM Kill & Snapshot Deletion (T1489, T1529)
Simulates force-killing VMs with 9x retry (LockBit pattern), deleting all snapshots
(RansomHub pattern), and stopping critical services. Based on RansomHub, LockBit Linux,
and Black Basta ESXi VM kill sequences.
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
	TECHNIQUE_ID   = "T1489"
	TECHNIQUE_NAME = "VM Kill & Snapshot Deletion"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "VM kill and snapshot deletion simulation")

	if err := performTechnique(); err != nil {
		if isBlockedError(err) {
			fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)
			LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
			os.Exit(StageBlocked)
		}

		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		os.Exit(StageError)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "All VMs killed, snapshots deleted, services stopped")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "c:\\F0"
	artifactDir := filepath.Join(targetDir, "esxi_vmkill")

	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create VM kill directory: %v", err)
	}

	// Read reconnaissance data from Stage 1
	reconPath := filepath.Join(targetDir, "recon_summary.txt")
	if _, err := os.Stat(reconPath); os.IsNotExist(err) {
		LogMessage("WARNING", TECHNIQUE_ID, "No recon summary found - using default VM data")
		fmt.Printf("[STAGE %s] Warning: Using default VM data (recon summary not found)\n", TECHNIQUE_ID)
	}

	// Phase 1: Force-kill all VMs using esxcli (LockBit 9x retry pattern)
	fmt.Printf("[STAGE %s] Phase 1: Force-killing VMs (LockBit 9x retry pattern)...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating: esxcli vm process kill --type=force --world-id=$wid (9x retry)")

	vmKillOutput := simulateVMForceKill()
	vmKillPath := filepath.Join(artifactDir, "vm_force_kill_log.txt")
	if err := os.WriteFile(vmKillPath, []byte(vmKillOutput), 0644); err != nil {
		return fmt.Errorf("failed to write VM kill log: %v", err)
	}
	fmt.Printf("[STAGE %s]   9 VMs force-killed with 9x retry pattern\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "VM force-kill simulation complete - 9 VMs killed")

	// Phase 2: Delete all snapshots (RansomHub pattern)
	fmt.Printf("[STAGE %s] Phase 2: Deleting all VM snapshots (RansomHub pattern)...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating: vim-cmd vmsvc/snapshot.removeall")

	snapshotDeleteOutput := simulateSnapshotDeletion()
	snapshotPath := filepath.Join(artifactDir, "snapshot_deletion_log.txt")
	if err := os.WriteFile(snapshotPath, []byte(snapshotDeleteOutput), 0644); err != nil {
		return fmt.Errorf("failed to write snapshot deletion log: %v", err)
	}
	fmt.Printf("[STAGE %s]   All snapshots removed from 10 VMs\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Snapshot deletion simulation complete")

	// Phase 3: Power off VMs via vim-cmd
	fmt.Printf("[STAGE %s] Phase 3: Powering off VMs via vim-cmd...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating: vim-cmd vmsvc/power.off $vmid")

	powerOffOutput := simulateVMPowerOff()
	powerOffPath := filepath.Join(artifactDir, "vm_power_off_log.txt")
	if err := os.WriteFile(powerOffPath, []byte(powerOffOutput), 0644); err != nil {
		return fmt.Errorf("failed to write power off log: %v", err)
	}
	fmt.Printf("[STAGE %s]   10 VMs powered off\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "VM power-off simulation complete")

	// Phase 4: Stop critical ESXi services (prevent recovery)
	fmt.Printf("[STAGE %s] Phase 4: Stopping critical services to prevent recovery...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Stopping critical ESXi services for recovery prevention")

	serviceStopOutput := simulateServiceStop()
	serviceStopPath := filepath.Join(artifactDir, "service_stop_log.txt")
	if err := os.WriteFile(serviceStopPath, []byte(serviceStopOutput), 0644); err != nil {
		return fmt.Errorf("failed to write service stop log: %v", err)
	}
	fmt.Printf("[STAGE %s]   Critical services stopped\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Critical services stopped")

	// Write VM kill summary
	summaryPath := filepath.Join(targetDir, "vmkill_summary.txt")
	summary := generateVMKillSummary()
	if err := os.WriteFile(summaryPath, []byte(summary), 0644); err != nil {
		return fmt.Errorf("failed to write VM kill summary: %v", err)
	}

	fmt.Printf("[STAGE %s] VM Kill & Snapshot Deletion complete\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "VM Kill & Snapshot Deletion stage complete")

	return nil
}

type vmTarget struct {
	VMID    int
	Name    string
	WorldID int
	State   string
}

func getVMTargets() []vmTarget {
	return []vmTarget{
		{1, "dc01-prod", 2098765, "poweredOn"},
		{2, "sql-prod-01", 2098432, "poweredOn"},
		{3, "web-app-01", 2099123, "poweredOn"},
		{4, "web-app-02", 2099456, "poweredOn"},
		{5, "erp-prod", 2099789, "poweredOn"},
		{6, "backup-srv", 2100123, "poweredOn"},
		{7, "mail-srv", 2100456, "poweredOn"},
		{8, "dev-test-01", 0, "poweredOff"},
		{9, "monitoring", 2100789, "poweredOn"},
		{10, "file-srv", 2101001, "poweredOn"},
	}
}

func simulateVMForceKill() string {
	var sb strings.Builder
	sb.WriteString("=== VM Force Kill Sequence (LockBit 9x Retry Pattern) ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02T15:04:05Z")))
	sb.WriteString("Pattern: esxcli vm process kill --type=force --world-id=$wid\n")
	sb.WriteString("Retry strategy: Up to 9 attempts per VM (LockBit behavior)\n\n")

	vms := getVMTargets()
	killCount := 0

	for _, vm := range vms {
		if vm.State == "poweredOff" {
			sb.WriteString(fmt.Sprintf("[SKIP] %s (VMID: %d) - Already powered off\n\n", vm.Name, vm.VMID))
			continue
		}

		sb.WriteString(fmt.Sprintf("[KILL] Target: %s (VMID: %d, WorldID: %d)\n", vm.Name, vm.VMID, vm.WorldID))

		// Simulate 9x retry pattern (LockBit behavior)
		// Most VMs "die" on attempt 1-3, stubborn ones need more retries
		killAttempt := 1
		if vm.Name == "sql-prod-01" || vm.Name == "erp-prod" {
			killAttempt = 3 // Database VMs are "stubborn"
		}

		for attempt := 1; attempt <= killAttempt; attempt++ {
			if attempt < killAttempt {
				sb.WriteString(fmt.Sprintf("  Attempt %d/9: esxcli vm process kill --type=force --world-id=%d\n", attempt, vm.WorldID))
				sb.WriteString(fmt.Sprintf("  [SIMULATED] Kill signal sent, VM still responding...\n"))
			} else {
				sb.WriteString(fmt.Sprintf("  Attempt %d/9: esxcli vm process kill --type=force --world-id=%d\n", attempt, vm.WorldID))
				sb.WriteString(fmt.Sprintf("  [SIMULATED] VM %s terminated (world-id=%d)\n", vm.Name, vm.WorldID))
			}
		}
		sb.WriteString("\n")
		killCount++
	}

	sb.WriteString(fmt.Sprintf("[+] VM Kill Summary: %d VMs terminated\n", killCount))
	return sb.String()
}

func simulateSnapshotDeletion() string {
	var sb strings.Builder
	sb.WriteString("=== Snapshot Deletion (RansomHub Pattern) ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02T15:04:05Z")))
	sb.WriteString("Command: vim-cmd vmsvc/snapshot.removeall $vmid\n\n")

	vms := getVMTargets()
	snapshotCount := 0

	for _, vm := range vms {
		// Generate simulated snapshots for each VM
		numSnapshots := 0
		switch {
		case vm.Name == "sql-prod-01":
			numSnapshots = 5
		case vm.Name == "dc01-prod":
			numSnapshots = 3
		case vm.Name == "erp-prod":
			numSnapshots = 4
		case vm.Name == "backup-srv":
			numSnapshots = 7
		default:
			numSnapshots = 2
		}

		sb.WriteString(fmt.Sprintf("[DELETE] vim-cmd vmsvc/snapshot.removeall %d (%s)\n", vm.VMID, vm.Name))
		sb.WriteString(fmt.Sprintf("  Found %d snapshots:\n", numSnapshots))

		for i := 1; i <= numSnapshots; i++ {
			snapshotName := fmt.Sprintf("Snapshot-%d_%s", i, time.Now().AddDate(0, -i, 0).Format("2006-01-02"))
			sb.WriteString(fmt.Sprintf("    [SIMULATED] Removing snapshot: %s\n", snapshotName))
			snapshotCount++
		}
		sb.WriteString(fmt.Sprintf("  [SIMULATED] All snapshots removed for %s\n\n", vm.Name))
	}

	sb.WriteString(fmt.Sprintf("[+] Total snapshots removed: %d across %d VMs\n", snapshotCount, len(vms)))
	return sb.String()
}

func simulateVMPowerOff() string {
	var sb strings.Builder
	sb.WriteString("=== VM Power Off Sequence ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02T15:04:05Z")))
	sb.WriteString("Command: vim-cmd vmsvc/power.off $vmid\n\n")

	vms := getVMTargets()

	for _, vm := range vms {
		sb.WriteString(fmt.Sprintf("[POWEROFF] vim-cmd vmsvc/power.off %d (%s)\n", vm.VMID, vm.Name))
		if vm.State == "poweredOff" {
			sb.WriteString("  [SIMULATED] Already powered off\n\n")
		} else {
			sb.WriteString(fmt.Sprintf("  [SIMULATED] VM %s powered off successfully\n\n", vm.Name))
		}
	}

	sb.WriteString("[+] All VMs powered off\n")
	return sb.String()
}

func simulateServiceStop() string {
	var sb strings.Builder
	sb.WriteString("=== Critical Service Stop (Recovery Prevention) ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format("2006-01-02T15:04:05Z")))

	services := []struct {
		Name        string
		Command     string
		Description string
	}{
		{"vmware-vpxd", "/etc/init.d/vmware-vpxd stop", "vCenter Server service"},
		{"vmware-hostd", "/etc/init.d/hostd stop", "ESXi Host Agent"},
		{"vmware-fdm", "/etc/init.d/vmware-fdm stop", "Fault Domain Manager (HA)"},
		{"vmware-sps", "/etc/init.d/vmware-sps stop", "Storage Profile Service"},
		{"vsan-health", "/etc/init.d/vsandevicemonitord stop", "vSAN Health Monitor"},
		{"vmware-vsan-syncd", "/etc/init.d/vmware-vsan-syncd stop", "vSAN Sync Daemon"},
		{"rhttpproxy", "/etc/init.d/rhttpproxy stop", "Reverse HTTP Proxy"},
		{"sfcbd-watchdog", "/etc/init.d/sfcbd-watchdog stop", "CIM Broker Watchdog"},
	}

	for _, svc := range services {
		sb.WriteString(fmt.Sprintf("[STOP] %s (%s)\n", svc.Name, svc.Description))
		sb.WriteString(fmt.Sprintf("  Command: %s\n", svc.Command))
		sb.WriteString(fmt.Sprintf("  [SIMULATED] Service %s stopped\n\n", svc.Name))
	}

	sb.WriteString(fmt.Sprintf("[+] %d critical services stopped\n", len(services)))
	return sb.String()
}

func generateVMKillSummary() string {
	var sb strings.Builder
	sb.WriteString("=== VM Kill & Snapshot Deletion Summary ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format("2006-01-02T15:04:05Z")))

	sb.WriteString("VM Kill Results:\n")
	sb.WriteString("  - VMs force-killed: 9\n")
	sb.WriteString("  - Kill method: esxcli vm process kill --type=force\n")
	sb.WriteString("  - Retry pattern: Up to 9 attempts (LockBit)\n\n")

	sb.WriteString("Snapshot Deletion Results:\n")
	sb.WriteString("  - VMs with snapshots removed: 10\n")
	sb.WriteString("  - Total snapshots deleted: 32\n")
	sb.WriteString("  - Method: vim-cmd vmsvc/snapshot.removeall\n\n")

	sb.WriteString("Service Disruption:\n")
	sb.WriteString("  - Critical services stopped: 8\n")
	sb.WriteString("  - Recovery prevention: ACTIVE\n\n")

	sb.WriteString("Impact Assessment:\n")
	sb.WriteString("  - All production VMs terminated\n")
	sb.WriteString("  - All recovery snapshots destroyed\n")
	sb.WriteString("  - HA/vSAN services disabled\n")
	sb.WriteString("  - System ready for encryption stage\n")

	return sb.String()
}

func isBlockedError(err error) bool {
	errStr := strings.ToLower(err.Error())
	blockedPatterns := []string{
		"access denied", "access is denied", "permission denied",
		"operation not permitted", "blocked", "prevented", "quarantined",
	}
	for _, pattern := range blockedPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}

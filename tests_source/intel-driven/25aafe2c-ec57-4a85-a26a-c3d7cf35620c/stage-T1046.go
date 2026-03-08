//go:build linux
// +build linux

/*
STAGE 1: Network Reconnaissance & VM Enumeration (T1046, T1018)
Simulates ESXi host discovery, VM enumeration via vim-cmd/esxcli, datastore scanning.
Based on RansomHub, LockBit Linux, and Black Basta ESXi reconnaissance patterns.
*/

package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
	TECHNIQUE_ID   = "T1046"
	TECHNIQUE_NAME = "Network Reconnaissance & VM Enumeration"
	STAGE_ID       = 1
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
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "ESXi host discovery and VM enumeration")

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
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "ESXi reconnaissance completed - all VM and datastore information collected")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "/tmp/F0"
	artifactDir := filepath.Join(targetDir, "esxi_recon")

	// Create artifact directory for reconnaissance output
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create recon directory: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, "Created reconnaissance artifact directory")

	// Phase 1: Simulate nmap/fscan network scanning for ESXi hosts
	fmt.Printf("[STAGE %s] Phase 1: Simulating network scan for ESXi hosts (port 443, 902, 22)...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating nmap/fscan network scan for ESXi hosts")

	esxiHosts := generateSimulatedESXiHosts()
	scanOutput := generateNmapOutput(esxiHosts)
	scanPath := filepath.Join(artifactDir, "nmap_esxi_scan.txt")
	if err := os.WriteFile(scanPath, []byte(scanOutput), 0644); err != nil {
		return fmt.Errorf("failed to write scan results: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Network scan found %d ESXi hosts", len(esxiHosts)))
	fmt.Printf("[STAGE %s]   Found %d ESXi hosts on management network\n", TECHNIQUE_ID, len(esxiHosts))

	// Phase 2: Simulate vim-cmd vmsvc/getallvms enumeration (RansomHub pattern)
	fmt.Printf("[STAGE %s] Phase 2: Executing vim-cmd vmsvc/getallvms (RansomHub pattern)...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating: vim-cmd vmsvc/getallvms")

	vmList := generateVMList()
	vmsvcOutput := generateVimCmdGetAllVMs(vmList)
	vmsvcPath := filepath.Join(artifactDir, "vmsvc_getallvms.txt")
	if err := os.WriteFile(vmsvcPath, []byte(vmsvcOutput), 0644); err != nil {
		return fmt.Errorf("failed to write VM list: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("vim-cmd enumerated %d VMs", len(vmList)))
	fmt.Printf("[STAGE %s]   Enumerated %d virtual machines\n", TECHNIQUE_ID, len(vmList))

	// Phase 3: Simulate esxcli vm process list (running VMs)
	fmt.Printf("[STAGE %s] Phase 3: Executing esxcli vm process list (running VM inventory)...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating: esxcli --formatter=csv vm process list")

	runningVMs := filterRunningVMs(vmList)
	esxcliOutput := generateEsxcliVMProcessList(runningVMs)
	esxcliPath := filepath.Join(artifactDir, "esxcli_vm_process_list.csv")
	if err := os.WriteFile(esxcliPath, []byte(esxcliOutput), 0644); err != nil {
		return fmt.Errorf("failed to write esxcli output: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("esxcli found %d running VMs", len(runningVMs)))
	fmt.Printf("[STAGE %s]   Found %d running VMs\n", TECHNIQUE_ID, len(runningVMs))

	// Phase 4: Simulate vmdumper -l for VM state enumeration (LockBit pattern)
	fmt.Printf("[STAGE %s] Phase 4: Executing vmdumper -l (LockBit VM state enum)...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating: vmdumper -l (LockBit pattern)")

	vmdumperOutput := generateVmdumperOutput(vmList)
	vmdumperPath := filepath.Join(artifactDir, "vmdumper_output.txt")
	if err := os.WriteFile(vmdumperPath, []byte(vmdumperOutput), 0644); err != nil {
		return fmt.Errorf("failed to write vmdumper output: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, "vmdumper VM state enumeration complete")
	fmt.Printf("[STAGE %s]   VM state dump complete\n", TECHNIQUE_ID)

	// Phase 5: Discover /vmfs/volumes/ datastores
	fmt.Printf("[STAGE %s] Phase 5: Enumerating /vmfs/volumes/ datastores...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating: ls -la /vmfs/volumes/")

	datastores := generateDatastoreList()
	datastoreOutput := generateDatastoreEnumOutput(datastores, vmList)
	datastorePath := filepath.Join(artifactDir, "vmfs_volumes_enum.txt")
	if err := os.WriteFile(datastorePath, []byte(datastoreOutput), 0644); err != nil {
		return fmt.Errorf("failed to write datastore enum: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Found %d datastores with VMDK files", len(datastores)))
	fmt.Printf("[STAGE %s]   Discovered %d datastores\n", TECHNIQUE_ID, len(datastores))

	// Write summary for subsequent stages
	summaryPath := filepath.Join(targetDir, "recon_summary.txt")
	summary := generateReconSummary(esxiHosts, vmList, runningVMs, datastores)
	if err := os.WriteFile(summaryPath, []byte(summary), 0644); err != nil {
		return fmt.Errorf("failed to write recon summary: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, "Reconnaissance summary written for subsequent stages")
	fmt.Printf("[STAGE %s] Reconnaissance complete. Summary written to recon_summary.txt\n", TECHNIQUE_ID)

	return nil
}

// --- Simulated Data Generation Functions ---

type esxiHost struct {
	IP       string
	Hostname string
	Version  string
	Build    string
}

type vmInfo struct {
	VMID      int
	Name      string
	GuestOS   string
	State     string
	WorldID   int
	VMXPath   string
	NumCPU    int
	MemoryMB  int
	DiskGB    int
}

type datastore struct {
	Name     string
	UUID     string
	SizeGB   int
	FreeGB   int
	Type     string
}

func generateSimulatedESXiHosts() []esxiHost {
	return []esxiHost{
		{IP: "10.20.30.10", Hostname: "esxi-prod-01", Version: "8.0 Update 2", Build: "22380479"},
		{IP: "10.20.30.11", Hostname: "esxi-prod-02", Version: "8.0 Update 2", Build: "22380479"},
		{IP: "10.20.30.12", Hostname: "esxi-prod-03", Version: "7.0 Update 3p", Build: "23307199"},
		{IP: "10.20.30.20", Hostname: "esxi-dr-01", Version: "8.0 Update 1", Build: "21813344"},
	}
}

func generateNmapOutput(hosts []esxiHost) string {
	var sb strings.Builder
	sb.WriteString("# Nmap 7.94 scan initiated at " + time.Now().Format("Mon Jan 2 15:04:05 2006") + "\n")
	sb.WriteString("# Scanning 10.20.30.0/24 for ESXi hosts (ports 22,443,902,5480,8697)\n\n")

	for _, h := range hosts {
		sb.WriteString(fmt.Sprintf("Nmap scan report for %s (%s)\n", h.Hostname, h.IP))
		sb.WriteString("Host is up (0.00045s latency).\n")
		sb.WriteString("PORT    STATE SERVICE     VERSION\n")
		sb.WriteString("22/tcp  open  ssh         OpenSSH 8.1 (protocol 2.0)\n")
		sb.WriteString(fmt.Sprintf("443/tcp open  ssl/http    VMware ESXi %s (build %s)\n", h.Version, h.Build))
		sb.WriteString("902/tcp open  ssl/vmware  VMware Authentication Daemon\n")
		sb.WriteString("5480/tcp open  ssl/http   VMware VAMI\n")
		sb.WriteString(fmt.Sprintf("| ssl-cert: Subject: commonName=%s\n", h.Hostname))
		sb.WriteString("| http-title: VMware ESXi\n")
		sb.WriteString("\n")
	}
	sb.WriteString(fmt.Sprintf("# Nmap done: 256 IP addresses scanned, %d hosts up\n", len(hosts)))
	return sb.String()
}

func generateVMList() []vmInfo {
	return []vmInfo{
		{VMID: 1, Name: "dc01-prod", GuestOS: "windows2019srv_64Guest", State: "poweredOn", WorldID: 2098765, VMXPath: "/vmfs/volumes/datastore1/dc01-prod/dc01-prod.vmx", NumCPU: 4, MemoryMB: 8192, DiskGB: 120},
		{VMID: 2, Name: "sql-prod-01", GuestOS: "windows2019srv_64Guest", State: "poweredOn", WorldID: 2098432, VMXPath: "/vmfs/volumes/datastore1/sql-prod-01/sql-prod-01.vmx", NumCPU: 8, MemoryMB: 32768, DiskGB: 500},
		{VMID: 3, Name: "web-app-01", GuestOS: "ubuntu64Guest", State: "poweredOn", WorldID: 2099123, VMXPath: "/vmfs/volumes/datastore2/web-app-01/web-app-01.vmx", NumCPU: 4, MemoryMB: 16384, DiskGB: 80},
		{VMID: 4, Name: "web-app-02", GuestOS: "ubuntu64Guest", State: "poweredOn", WorldID: 2099456, VMXPath: "/vmfs/volumes/datastore2/web-app-02/web-app-02.vmx", NumCPU: 4, MemoryMB: 16384, DiskGB: 80},
		{VMID: 5, Name: "erp-prod", GuestOS: "windows2019srv_64Guest", State: "poweredOn", WorldID: 2099789, VMXPath: "/vmfs/volumes/datastore1/erp-prod/erp-prod.vmx", NumCPU: 8, MemoryMB: 65536, DiskGB: 1024},
		{VMID: 6, Name: "backup-srv", GuestOS: "centos64Guest", State: "poweredOn", WorldID: 2100123, VMXPath: "/vmfs/volumes/datastore3/backup-srv/backup-srv.vmx", NumCPU: 4, MemoryMB: 16384, DiskGB: 2048},
		{VMID: 7, Name: "mail-srv", GuestOS: "windows2019srv_64Guest", State: "poweredOn", WorldID: 2100456, VMXPath: "/vmfs/volumes/datastore1/mail-srv/mail-srv.vmx", NumCPU: 4, MemoryMB: 16384, DiskGB: 256},
		{VMID: 8, Name: "dev-test-01", GuestOS: "ubuntu64Guest", State: "poweredOff", WorldID: 0, VMXPath: "/vmfs/volumes/datastore2/dev-test-01/dev-test-01.vmx", NumCPU: 2, MemoryMB: 4096, DiskGB: 40},
		{VMID: 9, Name: "monitoring", GuestOS: "centos64Guest", State: "poweredOn", WorldID: 2100789, VMXPath: "/vmfs/volumes/datastore2/monitoring/monitoring.vmx", NumCPU: 2, MemoryMB: 8192, DiskGB: 100},
		{VMID: 10, Name: "file-srv", GuestOS: "windows2019srv_64Guest", State: "poweredOn", WorldID: 2101001, VMXPath: "/vmfs/volumes/datastore3/file-srv/file-srv.vmx", NumCPU: 4, MemoryMB: 8192, DiskGB: 4096},
	}
}

func filterRunningVMs(vms []vmInfo) []vmInfo {
	var running []vmInfo
	for _, vm := range vms {
		if vm.State == "poweredOn" {
			running = append(running, vm)
		}
	}
	return running
}

func generateVimCmdGetAllVMs(vms []vmInfo) string {
	var sb strings.Builder
	sb.WriteString("Vmid   Name             File                                                    Guest OS            Version   Annotation\n")
	sb.WriteString("-----  ---------------  ------------------------------------------------------  ------------------  --------  ----------\n")
	for _, vm := range vms {
		sb.WriteString(fmt.Sprintf("%-6d %-16s %-54s %-19s vmx-20\n", vm.VMID, vm.Name, vm.VMXPath, vm.GuestOS))
	}
	return sb.String()
}

func generateEsxcliVMProcessList(vms []vmInfo) string {
	var sb strings.Builder
	sb.WriteString("WorldID,ProcessID,DisplayName,ConfigFile,UUID\n")
	for _, vm := range vms {
		vmUUID := fmt.Sprintf("50%02x%04x-%04x-%04x-%04x-%012x",
			rand.Intn(256), rand.Intn(65536), rand.Intn(65536),
			rand.Intn(65536), rand.Intn(65536), rand.Int63n(1<<48))
		sb.WriteString(fmt.Sprintf("%d,%d,%s,%s,%s\n", vm.WorldID, vm.WorldID+1, vm.Name, vm.VMXPath, vmUUID))
	}
	return sb.String()
}

func generateVmdumperOutput(vms []vmInfo) string {
	var sb strings.Builder
	sb.WriteString("=== Virtual Machine State Dump ===\n")
	sb.WriteString(fmt.Sprintf("Date: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	for _, vm := range vms {
		sb.WriteString(fmt.Sprintf("vmid=%d pid=%d cfgFile=\"%s\" uuid=\"\" displayName=\"%s\" vmxCartelID=%d\n",
			vm.VMID, vm.WorldID+1, vm.VMXPath, vm.Name, vm.WorldID))
	}
	return sb.String()
}

func generateDatastoreList() []datastore {
	return []datastore{
		{Name: "datastore1", UUID: "6156e4a0-4dc4f948-a24e-000c29a1b2c3", SizeGB: 8192, FreeGB: 2048, Type: "VMFS-6"},
		{Name: "datastore2", UUID: "6256e4a0-5dc5f949-b25f-000c29a1b2c4", SizeGB: 4096, FreeGB: 1024, Type: "VMFS-6"},
		{Name: "datastore3", UUID: "6356e4a0-6dc6f950-c26a-000c29a1b2c5", SizeGB: 16384, FreeGB: 4096, Type: "VMFS-6"},
	}
}

func generateDatastoreEnumOutput(datastores []datastore, vms []vmInfo) string {
	var sb strings.Builder
	sb.WriteString("=== /vmfs/volumes/ Datastore Enumeration ===\n\n")

	for _, ds := range datastores {
		sb.WriteString(fmt.Sprintf("Datastore: %s (UUID: %s)\n", ds.Name, ds.UUID))
		sb.WriteString(fmt.Sprintf("  Type: %s | Size: %dGB | Free: %dGB | Used: %d%%\n", ds.Type, ds.SizeGB, ds.FreeGB, 100-(ds.FreeGB*100/ds.SizeGB)))
		sb.WriteString("  VM Directories:\n")

		// List VMs on this datastore
		for _, vm := range vms {
			if strings.Contains(vm.VMXPath, ds.Name) {
				sb.WriteString(fmt.Sprintf("    /%s/\n", vm.Name))
				sb.WriteString(fmt.Sprintf("      %s.vmx      (%d KB)\n", vm.Name, 4+rand.Intn(8)))
				sb.WriteString(fmt.Sprintf("      %s.vmdk     (%d GB)\n", vm.Name, vm.DiskGB))
				sb.WriteString(fmt.Sprintf("      %s-flat.vmdk (%d GB)\n", vm.Name, vm.DiskGB))
				sb.WriteString(fmt.Sprintf("      %s.nvram    (8 KB)\n", vm.Name))
				sb.WriteString(fmt.Sprintf("      %s.vmsd     (1 KB)\n", vm.Name))
				if vm.State == "poweredOn" {
					sb.WriteString(fmt.Sprintf("      %s.vswp     (%d MB)\n", vm.Name, vm.MemoryMB))
					sb.WriteString(fmt.Sprintf("      %s.vmsn     (4 KB)\n", vm.Name))
				}
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func generateReconSummary(hosts []esxiHost, vms []vmInfo, running []vmInfo, datastores []datastore) string {
	var sb strings.Builder
	sb.WriteString("=== ESXi Reconnaissance Summary ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format("2006-01-02T15:04:05Z")))

	sb.WriteString(fmt.Sprintf("ESXi Hosts Discovered: %d\n", len(hosts)))
	for _, h := range hosts {
		sb.WriteString(fmt.Sprintf("  - %s (%s) - ESXi %s\n", h.IP, h.Hostname, h.Version))
	}

	sb.WriteString(fmt.Sprintf("\nTotal VMs: %d (Running: %d, Powered Off: %d)\n", len(vms), len(running), len(vms)-len(running)))
	var totalDiskGB int
	for _, vm := range vms {
		sb.WriteString(fmt.Sprintf("  - %s [%s] %dCPU/%dMB RAM/%dGB Disk - %s\n", vm.Name, vm.GuestOS, vm.NumCPU, vm.MemoryMB, vm.DiskGB, vm.State))
		totalDiskGB += vm.DiskGB
	}

	sb.WriteString(fmt.Sprintf("\nDatastores: %d\n", len(datastores)))
	for _, ds := range datastores {
		sb.WriteString(fmt.Sprintf("  - %s (%s) %dGB total / %dGB free\n", ds.Name, ds.Type, ds.SizeGB, ds.FreeGB))
	}

	sb.WriteString(fmt.Sprintf("\nTotal Virtual Disk Size: %d GB\n", totalDiskGB))
	sb.WriteString(fmt.Sprintf("WorldIDs for kill: "))
	for i, vm := range running {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("%d", vm.WorldID))
	}
	sb.WriteString("\n")

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

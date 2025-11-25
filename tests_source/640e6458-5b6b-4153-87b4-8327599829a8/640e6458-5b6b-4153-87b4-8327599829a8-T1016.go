//go:build windows
// +build windows

/*
Stage 1: EDR Process Discovery
Technique: T1016 - System Network Configuration Discovery
MITRE ATT&CK Tactic: Discovery

This stage enumerates running processes to identify EDR/AV products.
*/

package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TH32CS_SNAPPROCESS = 0x00000002
	STAGE_ID           = 1
	TECHNIQUE_ID       = "T1016"
	STAGE_NAME         = "EDR Process Discovery"
)

type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [260]uint16
}

// EDRTarget represents a discovered EDR/AV process
type EDRTarget struct {
	ProcessName string
	PID         uint32
	Product     string
}

// ComprehensiveEDRList contains process names for modern EDR/AV products
var ComprehensiveEDRList = map[string]string{
	// Microsoft
	"msmpeng.exe":        "Windows Defender",
	"mssense.exe":        "Microsoft Defender for Endpoint",
	"sensecncproxy.exe":  "Microsoft Defender for Endpoint",
	"senseir.exe":        "Microsoft Defender for Endpoint",
	"sensesampleuploader.exe": "Microsoft Defender for Endpoint",

	// CrowdStrike
	"csagent.exe":        "CrowdStrike Falcon",
	"csfalconservice.exe": "CrowdStrike Falcon",
	"csfalconcontainer.exe": "CrowdStrike Falcon",

	// SentinelOne
	"sentinelagent.exe":  "SentinelOne",
	"sentinelservicehost.exe": "SentinelOne",
	"sentinelstaticscanagent.exe": "SentinelOne",

	// Carbon Black
	"cb.exe":             "Carbon Black",
	"cbdefense.exe":      "Carbon Black Defense",
	"repcli.exe":         "Carbon Black Response",

	// Cylance
	"cylanceservice.exe": "Cylance",
	"cylancesvc.exe":     "Cylance",

	// Symantec/Broadcom
	"sep.exe":            "Symantec Endpoint Protection",
	"smc.exe":            "Symantec Management Client",
	"smcgui.exe":         "Symantec Endpoint Protection",
	"ccsvchst.exe":       "Symantec Norton",

	// McAfee/Trellix
	"mcshield.exe":       "McAfee",
	"mfemms.exe":         "McAfee Endpoint Security",
	"masvc.exe":          "McAfee Agent",
	"mctray.exe":         "McAfee",

	// Trend Micro
	"coreserviceshell.exe": "Trend Micro",
	"tmbmsrv.exe":        "Trend Micro",
	"ntrtscan.exe":       "Trend Micro",

	// Palo Alto
	"cyserver.exe":       "Palo Alto Cortex XDR",
	"cytray.exe":         "Palo Alto Cortex XDR",

	// FireEye/Mandiant
	"xagt.exe":           "FireEye Endpoint Agent",
	"xagtnotif.exe":      "FireEye Endpoint Agent",

	// Sophos
	"sophoshealth.exe":   "Sophos",
	"savservice.exe":     "Sophos Anti-Virus",
	"sophosfs.exe":       "Sophos",

	// ESET
	"ekrn.exe":           "ESET",
	"egui.exe":           "ESET",

	// Kaspersky
	"avp.exe":            "Kaspersky",
	"kavfswp.exe":        "Kaspersky",

	// Tanium
	"taniumclient.exe":   "Tanium",
	"taniumtraceagent.exe": "Tanium",

	// Cisco
	"sfc.exe":            "Cisco Secure Endpoint (AMP)",
	"immunetprotect.exe": "Cisco Secure Endpoint",

	// Fortinet
	"forticlient.exe":    "FortiClient",

	// Bitdefender
	"epag.exe":           "Bitdefender",
	"epintegrationservice.exe": "Bitdefender",

	// Webroot
	"wrsa.exe":           "Webroot SecureAnywhere",
}

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("Stage %d: %s", STAGE_ID, STAGE_NAME)
	Endpoint.Say("Technique: %s", TECHNIQUE_ID)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Attach to parent test logger (if running as part of orchestrator)
	AttachLogger("640e6458-5b6b-4153-87b4-8327599829a8", STAGE_NAME)

	Endpoint.Say(fmt.Sprintf("[*] Scanning for EDR/AV processes (%d known products)", len(ComprehensiveEDRList)))

	targets, err := DiscoverEDRProcesses()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[!] Failed to enumerate processes: %v", err))
		LogMessage("ERROR", "Stage1", fmt.Sprintf("Failed to enumerate processes: %v", err))
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	if len(targets) == 0 {
		Endpoint.Say("[!] No EDR/AV processes discovered")
		LogMessage("INFO", "Stage1", "No EDR processes found")
		Endpoint.Stop(Endpoint.UnexpectedTestError) // Can't test without targets
	}

	Endpoint.Say(fmt.Sprintf("[+] Discovered %d EDR/AV process(es)", len(targets)))

	// Log discovery results
	for _, target := range targets {
		Endpoint.Say(fmt.Sprintf("    [+] %s (PID: %d) - %s", target.ProcessName, target.PID, target.Product))
		LogMessage("INFO", "Stage1", fmt.Sprintf("Discovered: %s (PID: %d) - %s",
			target.ProcessName, target.PID, target.Product))
	}

	Endpoint.Say("")
	Endpoint.Say("[+] Stage 1 completed successfully")
	LogMessage("INFO", "Stage1", fmt.Sprintf("EDR discovery completed - %d targets found", len(targets)))

	// Success - targets discovered
	Endpoint.Stop(Endpoint.Unprotected) // 101 = successful discovery
}

// DiscoverEDRProcesses enumerates running processes and identifies EDR/AV products
func DiscoverEDRProcesses() ([]EDRTarget, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	process32First := kernel32.NewProc("Process32FirstW")
	process32Next := kernel32.NewProc("Process32NextW")
	closeHandle := kernel32.NewProc("CloseHandle")

	// Create snapshot of running processes
	snapshot, _, err := createToolhelp32Snapshot.Call(
		uintptr(TH32CS_SNAPPROCESS),
		0,
	)
	if snapshot == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("failed to create process snapshot: %v", err)
	}
	defer closeHandle.Call(snapshot)

	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	var targets []EDRTarget

	// Get first process
	ret, _, _ := process32First.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
	if ret == 0 {
		return nil, fmt.Errorf("failed to get first process")
	}

	// Iterate through processes
	for {
		processName := syscall.UTF16ToString(pe32.ExeFile[:])
		processNameLower := strings.ToLower(processName)

		// Check if process matches known EDR/AV
		if product, exists := ComprehensiveEDRList[processNameLower]; exists {
			targets = append(targets, EDRTarget{
				ProcessName: processName,
				PID:         pe32.ProcessID,
				Product:     product,
			})
		}

		// Get next process
		ret, _, _ = process32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
		if ret == 0 {
			break
		}
	}

	return targets, nil
}

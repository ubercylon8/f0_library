//go:build windows
// +build windows

package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	TEST_UUID         = "8f68dda1-94be-430f-8f35-d8af3f9b5d2e"
	TECHNIQUE_ID      = "T1562.001"
	TECHNIQUE_NAME    = "BYOVD EDR-Killer"
	STAGE_ID          = 2
	hlpTerminateIOCTL = 0x2222008
)

//go:embed rwdrv.sys
var realVulnerableDriver []byte

type callbackTarget struct {
	Driver   string `json:"driver"`
	Callback string `json:"callback"`
	Active   bool   `json:"active"`
}

type byovdOutcomes struct {
	success int
	blocked int
	errors  int
}

var ownedStandinPIDs []int

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--standin" {
		time.Sleep(90 * time.Second)
		return
	}
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)
	code := performBYOVD()
	switch code {
	case StageSuccess:
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "BYOVD emulation primitives executed; no vulnerable driver loaded")
	case StageBlocked, StageQuarantined:
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "One or more BYOVD primitives positively prevented")
	default:
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "BYOVD primitives inconclusive")
	}
	os.Exit(code)
}

func performBYOVD() int {
	var outcomes byovdOutcomes
	rwdrvPath := filepath.Join(LOG_DIR, "rwdrv.sys")
	hlpdrvPath := filepath.Join(LOG_DIR, "hlpdrv.sys")
	callbackPath := filepath.Join(ARTIFACT_DIR, "Qilin", "callback_registry.json")
	services := []string{"qilin_rwdrv_f0", "qilin_hlpdrv_f0"}
	createdServices := []string{}
	ownedStandinPIDs = nil

	for _, service := range services {
		_, _ = runSC("delete", service)
	}
	defer func() {
		for _, service := range createdServices {
			out, code := runSC("delete", service)
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("service cleanup %s exit=%d output=%s", service, code, out))
		}
		for _, pid := range ownedStandinPIDs {
			if process, err := os.FindProcess(pid); err == nil {
				_ = process.Kill()
				_, _ = process.Wait()
			}
		}
		for _, path := range []string{rwdrvPath, hlpdrvPath, callbackPath, filepath.Join(LOG_DIR, "MsMpEng.exe"), filepath.Join(LOG_DIR, "CSFalconService.exe"), filepath.Join(LOG_DIR, "CrowdStrike.exe")} {
			_ = os.Remove(path)
		}
	}()

	LogMessage("WARN", "T1211", "Dropping real rwdrv.sys only for signature inspection; it will be deleted before service/native-load operations")
	if err := os.WriteFile(rwdrvPath, realVulnerableDriver, 0644); err != nil {
		LogMessage("ERROR", "T1211", fmt.Sprintf("real driver drop returned: %v", err))
		outcomes.errors++
	} else {
		LogFileDropped("rwdrv.sys", rwdrvPath, int64(len(realVulnerableDriver)), false)
		time.Sleep(3 * time.Second)
		if _, err := os.Stat(rwdrvPath); os.IsNotExist(err) {
			LogMessage("BLOCKED", "T1211", "Real rwdrv.sys quarantined after extraction (os.Stat evidence)")
			outcomes.blocked++
		} else {
			LogMessage("SUCCESS", "T1211", "Real rwdrv.sys survived the signature-observation window")
			outcomes.success++
		}
		if err := os.Remove(rwdrvPath); err != nil && !os.IsNotExist(err) {
			LogMessage("ERROR", "T1211", fmt.Sprintf("real driver safety removal returned: %v", err))
			outcomes.errors++
		}
	}

	if err := writeNonfunctionalDriver(rwdrvPath); err != nil {
		LogMessage("ERROR", "T1211", fmt.Sprintf("nonfunctional rwdrv write returned: %v", err))
		outcomes.errors++
	}
	if err := writeNonfunctionalDriver(hlpdrvPath); err != nil {
		LogMessage("ERROR", "T1211", fmt.Sprintf("nonfunctional hlpdrv write returned: %v", err))
		outcomes.errors++
	}

	for i, service := range services {
		driverPath := rwdrvPath
		if i == 1 {
			driverPath = hlpdrvPath
		}
		out, code := runSC("create", service, "binPath=", driverPath, "type=", "kernel", "start=", "demand")
		switch {
		case code == 0:
			createdServices = append(createdServices, service)
			queryOut, queryCode := runSC("query", service)
			if queryCode == 0 {
				LogMessage("SUCCESS", "T1543.003", fmt.Sprintf("Created nonfunctional kernel service %s", service))
				outcomes.success++
			} else {
				LogMessage("ERROR", "T1543.003", fmt.Sprintf("service %s creation could not be corroborated: %s", service, queryOut))
				outcomes.errors++
			}
		case isProtectionExit(code):
			LogMessage("BLOCKED", "T1543.003", fmt.Sprintf("fresh kernel service %s creation returned protection exit %d: %s", service, code, out))
			outcomes.blocked++
		default:
			LogMessage("ERROR", "T1543.003", fmt.Sprintf("service %s creation returned exit %d: %s", service, code, out))
			outcomes.errors++
		}
	}

	privilegeErr := enablePrivilege("SeLoadDriverPrivilege")
	if privilegeErr != nil {
		LogMessage("WARNING", "T1211", fmt.Sprintf("SeLoadDriverPrivilege unavailable; native-load denial will be inconclusive: %v", privilegeErr))
	}
	for _, service := range createdServices {
		status := ntLoadNonfunctionalDriver(service)
		switch status {
		case StageSuccess:
			outcomes.success++
		case StageBlocked:
			outcomes.blocked++
		default:
			outcomes.errors++
		}
	}

	targets := buildCallbackTargets(320)
	for i := range targets {
		targets[i].Active = false
	}
	if err := os.MkdirAll(filepath.Dir(callbackPath), 0755); err == nil {
		if payload, marshalErr := json.MarshalIndent(targets, "", "  "); marshalErr == nil {
			if writeErr := os.WriteFile(callbackPath, payload, 0644); writeErr == nil {
				LogFileDropped("callback_registry.json", callbackPath, int64(len(payload)), false)
				LogMessage("WARN", TECHNIQUE_ID, "Simulated 320 process/thread/image callback removals in a sandbox JSON registry; no kernel callback was touched")
				outcomes.success++
			} else {
				outcomes.errors++
			}
		}
	}

	probeHLPDriverDevice()
	for _, imageName := range []string{"MsMpEng.exe", "CSFalconService.exe", "CrowdStrike.exe"} {
		outcome := terminateOwnedStandin(imageName)
		switch outcome {
		case StageSuccess:
			outcomes.success++
		case StageBlocked, StageQuarantined:
			outcomes.blocked++
		default:
			outcomes.errors++
		}
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("BYOVD outcome metrics success=%d blocked=%d error=%d", outcomes.success, outcomes.blocked, outcomes.errors))
	if outcomes.blocked > 0 {
		return StageBlocked
	}
	if outcomes.success > 0 {
		return StageSuccess
	}
	return StageError
}

func runSC(args ...string) (string, int) {
	out, err := exec.Command("sc.exe", args...).CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), exitErr.ExitCode()
	}
	return string(out), -1
}

func isProtectionExit(code int) bool {
	for _, candidate := range []int{5, 225, 226, 1260, 4551} {
		if code == candidate {
			return true
		}
	}
	return false
}

type ntUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

func ntLoadNonfunctionalDriver(service string) int {
	registryPath := `\Registry\Machine\System\CurrentControlSet\Services\` + service
	pathPtr, err := windows.UTF16PtrFromString(registryPath)
	if err != nil {
		return StageError
	}
	length := uint16(len(registryPath) * 2)
	unicodePath := ntUnicodeString{Length: length, MaximumLength: length + 2, Buffer: pathPtr}
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	loadDriver := ntdll.NewProc("NtLoadDriver")
	status, _, _ := loadDriver.Call(uintptr(unsafe.Pointer(&unicodePath)))
	code := uint32(status)
	LogMessage("WARN", "T1211", fmt.Sprintf("NtLoadDriver(%s) NTSTATUS=0x%08x against nonfunctional stand-in", registryPath, code))
	switch code {
	case 0:
		unloadDriver := ntdll.NewProc("NtUnloadDriver")
		unloadDriver.Call(uintptr(unsafe.Pointer(&unicodePath)))
		LogMessage("ERROR", "T1211", "Nonfunctional stand-in unexpectedly loaded; NtUnloadDriver invoked")
		return StageError
	case 0xC000007B, 0xC0000011:
		LogMessage("SUCCESS", "T1211", "Windows rejected the invalid stand-in image as designed; native-load telemetry executed")
		return StageSuccess
	case 0xC0020022, 0xC0000428:
		if isAdmin() || isSystemContext() {
			LogMessage("BLOCKED", "T1211", fmt.Sprintf("Native load returned protection NTSTATUS 0x%08x in elevated context", code))
			return StageBlocked
		}
	}
	LogMessage("WARNING", "T1211", fmt.Sprintf("Native load status 0x%08x is not positive protection evidence", code))
	return StageError
}

func probeHLPDriverDevice() {
	pathPtr, _ := windows.UTF16PtrFromString(`\\.\hlpdrv_f0_nonfunctional`)
	handle, err := windows.CreateFile(pathPtr, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		LogMessage("INFO", "T1211", fmt.Sprintf("Emulated hlpdrv IOCTL 0x%x against a guaranteed-nonfunctional device; absence returned: %v", uint32(hlpTerminateIOCTL), err))
		return
	}
	defer windows.CloseHandle(handle)
	LogMessage("ERROR", "T1211", "Guaranteed-nonfunctional hlpdrv device unexpectedly exists; no IOCTL sent")
}

func buildCallbackTargets(count int) []callbackTarget {
	names := strings.Fields(`MsMpEng WdFilter WdNisDrv NisSrv SecurityHealthService Sense WinDefend CSFalconService CSAgent CSDesktop CSDeviceControl CSPM CSNet CSBoot CrowdStrike FalconSensor SentinalAgent SentinelStaticEngine SentinelMonitor SentinelHelper SntService SntDriver SophosED SophosEL SophosFS SophosNtp SophosSAVI SophosEndpointDefense SophosMcsAgentD SophosWebIntelligence SophosZap SymEFA SymEvent SymIron SymNetS SymRedir SymDS SymDiag SymProxySys SymTdi SymVmi SymWsc Symvt Symefasi SrtSp SrtSpX EraserUtilDrv BHDrvx64 IDSvia64 NAVEX15 NAVENG ccSet ccHP Teefer2 wgss wfp callout fwpkclnt klsmd klif klflt klbackup klwfp klhk kl1 kl2 kl3 kl4 kl5 klavif klava klam klbg kldriver kltdi klrsdp klprcp klsft klsmc klsns klsrvc klupm klwsc klmou klkbd klpd klpnp klusb klvirt klprv klcrypt klnpk klfle klnfl klnfw klsock klsync klvss klwdi klxml mcshield mfeapfk mfeavfk mfebopk mfefirek mfehidk mfenlfk mfeplk mfetdi mfewfpk mfdriver mfpromonitor mfencfilter mfemalert mfendisk mfenc ransomware mpfilter tmxpflt tmactmon tmcomm tmevtmgr tmlisten tmnciesc tmwfp tmusa tmvfs tm_prelight tm_filter tm_file pbfilter pbedrv pbsvc pbo pbp pbf pbd pbc pba pandaav psinproc psinknc psinfile psinreg psinprot psinaflt pskmad psanncore psanhost psanav avp avguard avgntflt avipbb avkmgr bdfsfltr bdfm bdsdrv bdservice bdkernel bdprotect bdselfpr bdstack bdtdi bdupd bdwfp bdwrkr bdfs bdfltr bdmonitor bdnetsvc bdnetwork bdsandbox bdshellex bdspy bdsysmon bdthreat bdusb bdverify bdwfpdrv bdwintmp bdwnet bdwrsp bdwsd bdav bdcam bdagent bdpolicy bdquarantine bdupdate bdvuln`)
	callbacks := []string{"process", "thread", "image-load"}
	targets := make([]callbackTarget, 0, count)
	for i := 0; i < count; i++ {
		targets = append(targets, callbackTarget{Driver: names[i%len(names)] + ".sys", Callback: callbacks[i%len(callbacks)], Active: true})
	}
	return targets
}

func terminateOwnedStandin(imageName string) int {
	path := filepath.Join(LOG_DIR, imageName)
	if err := copyCurrentExecutable(path); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("stand-in copy %s returned: %v", imageName, err))
		return StageError
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return StageQuarantined
	}
	cmd := exec.Command(path, "--standin")
	if err := cmd.Start(); err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) && isProtectionExit(int(errno)) {
			return StageBlocked
		}
		return StageError
	}
	pid := cmd.Process.Pid
	ownedStandinPIDs = append(ownedStandinPIDs, pid)
	time.Sleep(500 * time.Millisecond)
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		if errnoIs(err, windows.ERROR_ACCESS_DENIED) && (isAdmin() || isSystemContext()) {
			return StageBlocked
		}
		return StageError
	}
	defer windows.CloseHandle(handle)
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	terminate := ntdll.NewProc("NtTerminateProcess")
	status, _, _ := terminate.Call(uintptr(handle), 0)
	if uint32(status) == 0 {
		LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("NtTerminateProcess terminated test-owned %s (PID %d)", imageName, pid))
		return StageSuccess
	}
	if uint32(status) == 0xC0020022 && (isAdmin() || isSystemContext()) {
		return StageBlocked
	}
	LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("NtTerminateProcess(%s) NTSTATUS=0x%08x", imageName, uint32(status)))
	return StageError
}

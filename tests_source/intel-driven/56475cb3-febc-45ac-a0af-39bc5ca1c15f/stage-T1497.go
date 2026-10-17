//go:build windows
// +build windows

/*
STAGE 2: Virtualization / Sandbox Evasion + Dormancy (T1497)

Recreates the 3CX implant's patience: the trojan stayed dormant for roughly
seven days before beaconing, and DPRK tooling routinely fingerprints the host
to avoid detonating inside analyst sandboxes. This stage performs READ-ONLY
environment checks (VM artifacts, system uptime, domain-join state) and logs
the INTENDED 7-day dormancy — it does NOT actually sleep for a week; the real
delay is compressed to a few seconds so the test remains runnable.

Safety: every check is read-only (registry queries, env vars, a tick-count
call). Nothing is written outside LOG_DIR and nothing is modified. Benign
recon almost never draws a protection response, so this stage classifies as
success unless a genuine runtime error occurs — it never manufactures a block.
*/

package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID      = "56475cb3-febc-45ac-a0af-39bc5ca1c15f"
	TECHNIQUE_ID   = "T1497"
	TECHNIQUE_NAME = "Virtualization/Sandbox Evasion"
	STAGE_ID       = 2

	IntendedDormancySeconds = 604800 // 7 days — logged, never actually slept
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting sandbox/dormancy evasion simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Read-only host fingerprint representing the 3CX 7-day dormancy")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "VM-artifact, uptime and domain-join checks; intended 7-day sleep logged not slept")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))

		exitCode := determineExitCode(err)
		if exitCode == StageBlocked || exitCode == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] Sandbox/dormancy evasion completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Sandbox/dormancy evasion completed successfully")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Environment fingerprint gathered; dormancy compressed from 7 days to seconds")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Check 1: VM / sandbox artifacts (read-only registry + resource heuristics)
	vmIndicators := detectVirtualization()
	if len(vmIndicators) > 0 {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Virtualization indicators observed: %s", strings.Join(vmIndicators, ", ")))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "No virtualization indicators observed (bare-metal-like)")
	}

	cpuCount := runtime.NumCPU()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Logical CPU count: %d (low counts are a common sandbox tell)", cpuCount))

	// Check 2: system uptime (short uptime is a classic sandbox tell)
	uptime := getSystemUptime()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("System uptime: %s (very short uptime suggests a fresh sandbox)", uptime.Round(time.Second)))

	// Check 3: domain-join state (targeted-intrusion tell — implants prefer domain-joined hosts)
	domainJoined, domainName := detectDomainJoin()
	if domainJoined {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Host appears domain-joined (domain: %s)", domainName))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Host appears workgroup / not domain-joined")
	}

	// Dormancy: log the INTENDED 7-day sleep, actually delay only seconds.
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Intended dormancy: %d seconds (~7 days) before next stage — NOT actually slept", IntendedDormancySeconds))
	LogMessage("INFO", TECHNIQUE_ID, "Compressing dormancy to a short delay for test execution")
	time.Sleep(3 * time.Second)

	LogMessage("INFO", TECHNIQUE_ID, "Dormancy elapsed (compressed); implant would now proceed to config retrieval")
	return nil
}

// detectVirtualization performs read-only checks for common hypervisor artifacts.
func detectVirtualization() []string {
	var indicators []string

	// BIOS / system firmware strings
	biosKeys := []struct {
		path  string
		value string
	}{
		{`HARDWARE\DESCRIPTION\System\BIOS`, "SystemManufacturer"},
		{`HARDWARE\DESCRIPTION\System\BIOS`, "SystemProductName"},
		{`HARDWARE\DESCRIPTION\System`, "SystemBiosVersion"},
	}
	needles := []string{"vbox", "virtualbox", "vmware", "qemu", "xen", "virtual", "kvm", "hyper-v", "innotek", "parallels"}

	for _, bk := range biosKeys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, bk.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		val, _, err := k.GetStringValue(bk.value)
		k.Close()
		if err != nil {
			// SystemBiosVersion is a multi-string on some systems; ignore read errors.
			continue
		}
		low := strings.ToLower(val)
		for _, n := range needles {
			if strings.Contains(low, n) {
				indicators = append(indicators, fmt.Sprintf("%s=%s", bk.value, val))
				break
			}
		}
	}

	// Disk enumeration string (frequently reveals VBOX/VMware virtual disks)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Disk\Enum`, registry.QUERY_VALUE); err == nil {
		if val, _, err := k.GetStringValue("0"); err == nil {
			low := strings.ToLower(val)
			for _, n := range needles {
				if strings.Contains(low, n) {
					indicators = append(indicators, "Disk\\Enum contains virtual-disk marker")
					break
				}
			}
		}
		k.Close()
	}

	// Hypervisor-present guest additions services (existence only, read-only)
	vmServices := []string{
		`SYSTEM\CurrentControlSet\Services\VBoxGuest`,
		`SYSTEM\CurrentControlSet\Services\VBoxService`,
		`SYSTEM\CurrentControlSet\Services\vmci`,
		`SYSTEM\CurrentControlSet\Services\vmtools`,
	}
	for _, svc := range vmServices {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, svc, registry.QUERY_VALUE); err == nil {
			k.Close()
			parts := strings.Split(svc, `\`)
			indicators = append(indicators, "service:"+parts[len(parts)-1])
		}
	}

	return indicators
}

// getSystemUptime returns the host uptime via kernel32!GetTickCount64 (read-only).
func getSystemUptime() time.Duration {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getTickCount64 := kernel32.NewProc("GetTickCount64")
	ret, _, _ := getTickCount64.Call()
	return time.Duration(ret) * time.Millisecond
}

// detectDomainJoin infers domain membership from environment (read-only, no netapi mutation).
func detectDomainJoin() (bool, string) {
	userDomain := os.Getenv("USERDOMAIN")
	computerName := os.Getenv("COMPUTERNAME")
	dnsDomain := os.Getenv("USERDNSDOMAIN")

	if dnsDomain != "" {
		return true, dnsDomain
	}
	if userDomain != "" && !strings.EqualFold(userDomain, computerName) {
		return true, userDomain
	}
	return false, ""
}

// ==============================================================================
// EXIT CODE DETERMINATION (Bug Prevention Rule 8: never default to a block code)
// ==============================================================================

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"access is denied", "access denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	// Ambiguous / benign / prerequisite failures → 999, never a block.
	return StageError
}

func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if containsCI(s, substr) {
			return true
		}
	}
	return false
}

func containsCI(s, substr string) bool {
	return len(s) >= len(substr) && indexIgnoreCase(s, substr) >= 0
}

func indexIgnoreCase(s, substr string) int {
	s = toLowerStr(s)
	substr = toLowerStr(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func toLowerStr(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}

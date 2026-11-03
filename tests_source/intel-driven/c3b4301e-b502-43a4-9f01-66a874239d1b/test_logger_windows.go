//go:build windows
// +build windows

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const LOG_DIR = `C:\F0`
const ARTIFACT_DIR = `c:\Users\fortika-test`

func captureSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()

	info := SystemInfo{
		Hostname:        hostname,
		OSVersion:       getOSVersion(),
		Architecture:    getArchitecture(),
		DefenderRunning: isDefenderRunning(),
		MDEInstalled:    isMDEInstalled(),
		ProcessID:       os.Getpid(),
		Username:        os.Getenv("USERNAME"),
		IsAdmin:         isAdmin(),
		EDRProducts:     []EDRProduct{},
	}

	if info.MDEInstalled {
		info.MDEVersion = getMDEVersion()
		info.EDRProducts = append(info.EDRProducts, EDRProduct{
			Name:    "Microsoft Defender for Endpoint",
			Version: info.MDEVersion,
			Running: info.DefenderRunning,
		})
	}

	// Enumerate ALL AV/EDR products the OS Security Center knows about, so the
	// record is not limited to Microsoft Defender. This surfaces third-party
	// sensors (CrowdStrike, Sophos, SentinelOne, etc.) that are the active
	// protection on many hosts. Best-effort: SecurityCenter2 exists only on
	// client SKUs (not Windows Server) and the query fails gracefully to empty.
	for _, p := range detectRegisteredAV() {
		if edrAlreadyListed(info.EDRProducts, p.Name) {
			continue
		}
		info.EDRProducts = append(info.EDRProducts, p)
	}

	return info
}

// detectRegisteredAV queries the Windows Security Center (root\SecurityCenter2)
// for every registered antivirus/EDR product. Returns nil on any failure
// (e.g. Windows Server, where the namespace is absent) rather than erroring —
// EDR enumeration is diagnostic metadata, never a prerequisite.
func detectRegisteredAV() []EDRProduct {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | `+
			`ForEach-Object { '{0}|{1}' -f $_.displayName, $_.productState }`)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var products []EDRProduct
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		running := false
		if len(parts) == 2 {
			running = avRealtimeOn(strings.TrimSpace(parts[1]))
		}
		products = append(products, EDRProduct{Name: name, Running: running})
	}
	return products
}

// avRealtimeOn decodes a SecurityCenter2 productState. The 0x1000 bit of the
// state indicates on-access / real-time protection is enabled (verified:
// Sophos Intercept X active = 0x41000 -> on; passive Defender = 0x60100 -> off).
func avRealtimeOn(productState string) bool {
	state, err := strconv.Atoi(productState)
	if err != nil {
		return false
	}
	return state&0x1000 == 0x1000
}

// edrAlreadyListed reports whether an EDR/AV with the given name is already
// recorded, treating any two "Defender" entries as the same product so the
// Security Center "Windows Defender" row does not duplicate the MDE entry.
func edrAlreadyListed(existing []EDRProduct, name string) bool {
	n := strings.ToLower(name)
	for _, e := range existing {
		en := strings.ToLower(e.Name)
		if en == n {
			return true
		}
		if strings.Contains(en, "defender") && strings.Contains(n, "defender") {
			return true
		}
	}
	return false
}

func getOSVersion() string {
	cmd := exec.Command("cmd", "/C", "ver")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

func getArchitecture() string {
	arch := os.Getenv("PROCESSOR_ARCHITECTURE")
	if arch != "" {
		return arch
	}
	return "Unknown"
}

func isDefenderRunning() bool {
	cmd := exec.Command("sc", "query", "WinDefend")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "RUNNING")
}

func isMDEInstalled() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Advanced Threat Protection`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	return true
}

func getMDEVersion() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Advanced Threat Protection`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()

	version, _, err := key.GetStringValue("Version")
	if err != nil {
		return "Unknown"
	}
	return version
}

func isAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

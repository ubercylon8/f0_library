//go:build windows
// +build windows

package main

import (
	"os"
	"os/exec"
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

	return info
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

//go:build darwin
// +build darwin

package main

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const LOG_DIR = "/tmp/F0"
const ARTIFACT_DIR = "/Users/fortika-test"

func captureSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()

	info := SystemInfo{
		Hostname:        hostname,
		OSVersion:       getOSVersion(),
		Architecture:    getArchitecture(),
		DefenderRunning: isDefenderRunning(),
		MDEInstalled:    isMDEInstalled(),
		ProcessID:       os.Getpid(),
		Username:        os.Getenv("USER"),
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

	// Detect macOS EDR products
	detectMacEDR(&info)

	return info
}

func getOSVersion() string {
	cmd := exec.Command("sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown macOS"
	}
	return "macOS " + strings.TrimSpace(string(output))
}

func getArchitecture() string {
	return runtime.GOARCH
}

func isDefenderRunning() bool {
	cmd := exec.Command("pgrep", "-x", "wdavdaemon")
	err := cmd.Run()
	return err == nil
}

func isMDEInstalled() bool {
	_, err := os.Stat("/Applications/Microsoft Defender.app")
	return err == nil
}

func getMDEVersion() string {
	cmd := exec.Command("mdatp", "version")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

func isAdmin() bool {
	return os.Getuid() == 0
}

func detectMacEDR(info *SystemInfo) {
	edrPaths := []struct {
		path string
		name string
	}{
		{"/Library/CS/", "CrowdStrike Falcon"},
		{"/Library/Sentinel/", "SentinelOne"},
		{"/Library/Application Support/com.jamf.protect.agent/", "Jamf Protect"},
		{"/Library/Addigy/", "Addigy"},
		{"/usr/local/bin/osqueryi", "osquery"},
	}

	for _, edr := range edrPaths {
		if _, err := os.Stat(edr.path); err == nil {
			info.EDRProducts = append(info.EDRProducts, EDRProduct{
				Name:    edr.name,
				Running: true,
			})
		}
	}
}

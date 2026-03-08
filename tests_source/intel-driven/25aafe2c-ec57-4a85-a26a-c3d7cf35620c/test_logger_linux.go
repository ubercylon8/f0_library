//go:build linux
// +build linux

package main

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const LOG_DIR = "/tmp/F0"
const ARTIFACT_DIR = "/home/fortika-test"

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

	detectLinuxEDR(&info)
	return info
}

func getOSVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				name := strings.TrimPrefix(line, "PRETTY_NAME=")
				return strings.Trim(name, "\"")
			}
		}
	}
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown Linux"
	}
	return "Linux " + strings.TrimSpace(string(output))
}

func getArchitecture() string {
	return runtime.GOARCH
}

func isDefenderRunning() bool {
	cmd := exec.Command("systemctl", "is-active", "mdatp")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "active"
}

func isMDEInstalled() bool {
	_, err := os.Stat("/opt/microsoft/mdatp")
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

func detectLinuxEDR(info *SystemInfo) {
	edrPaths := []struct {
		path string
		name string
	}{
		{"/opt/CrowdStrike/", "CrowdStrike Falcon"},
		{"/opt/sentinelone/", "SentinelOne"},
		{"/opt/carbonblack/", "VMware Carbon Black"},
		{"/opt/qualys/", "Qualys Cloud Agent"},
		{"/opt/rapid7/", "Rapid7 InsightAgent"},
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

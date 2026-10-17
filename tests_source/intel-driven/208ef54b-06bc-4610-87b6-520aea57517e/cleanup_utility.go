//go:build windows
// +build windows

/*
ScreenConnect RMM Abuse Test — Cleanup Utility

Reverses everything the test installs/creates:
  - Stops and uninstalls the ConnectWise ScreenConnect Client agent
  - Removes the ScreenConnect Windows service(s)
  - Removes install + data directories
  - Removes staged decoy data from ARTIFACT_DIR
  - Removes dropped test artifacts from LOG_DIR

Self-contained (built from cleanup_utility.go alone) so it can be dropped and run
independently. Because this test REALLY installs software, snapshot the VM before
running the test and revert after (see SAFETY.md).
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	CLEAN_LOG_DIR      = `C:\F0`
	CLEAN_ARTIFACT_DIR = `c:\Users\fortika-test`
	MSI_DROP           = `C:\F0\screenconnect-setup.msi`
)

func main() {
	fmt.Println("=================================================================")
	fmt.Println("ScreenConnect RMM Abuse Test - Cleanup Utility")
	fmt.Println("=================================================================")
	fmt.Println()

	if !checkIsAdmin() {
		fmt.Println("ERROR: Administrator privileges required. Re-run as Administrator.")
		os.Exit(1)
	}

	steps := []struct {
		label string
		fn    func()
	}{
		{"Stopping ScreenConnect service(s)", stopScreenConnectServices},
		{"Uninstalling ScreenConnect agent", uninstallScreenConnect},
		{"Deleting residual ScreenConnect service(s)", deleteScreenConnectServices},
		{"Removing ScreenConnect install/data directories", removeScreenConnectDirs},
		{"Removing staged decoy data", removeDecoyData},
		{"Removing dropped test artifacts", removeTestArtifacts},
	}

	for i, s := range steps {
		fmt.Printf("[%d/%d] %s...\n", i+1, len(steps), s.label)
		s.fn()
	}

	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Println("Cleanup Complete!")
	fmt.Println("=================================================================")
}

// screenConnectServiceNames returns the NAMEs of all ScreenConnect Client services.
func screenConnectServiceNames() []string {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		"Get-Service -Name 'ScreenConnect Client*' -ErrorAction SilentlyContinue | "+
			"ForEach-Object { $_.Name }")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if n := strings.TrimSpace(line); n != "" {
			names = append(names, n)
		}
	}
	return names
}

func stopScreenConnectServices() {
	for _, name := range screenConnectServiceNames() {
		exec.Command("sc", "stop", name).Run()
		fmt.Printf("    Stopped service: %s\n", name)
	}
	// Kill any residual agent processes.
	exec.Command("taskkill", "/F", "/IM", "ScreenConnect.ClientService.exe").Run()
	exec.Command("taskkill", "/F", "/IM", "ScreenConnect.WindowsClient.exe").Run()
	time.Sleep(2 * time.Second)
}

func uninstallScreenConnect() {
	// Method 1: uninstall via the dropped MSI if still present (fast, exact).
	if _, err := os.Stat(MSI_DROP); err == nil {
		fmt.Println("    Uninstalling via dropped MSI (/x /qn)...")
		exec.Command("msiexec", "/x", MSI_DROP, "/qn", "/norestart").Run()
		time.Sleep(10 * time.Second)
	}

	// Method 2: uninstall by product name (works even if the MSI was removed).
	fmt.Println("    Searching for installed ScreenConnect products...")
	ps := "Get-CimInstance Win32_Product -Filter \"Name LIKE 'ScreenConnect Client%'\" | " +
		"ForEach-Object { $_ | Invoke-CimMethod -MethodName Uninstall | Out-Null }"
	exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps).Run()
	time.Sleep(5 * time.Second)
	fmt.Println("    Uninstall commands executed")
}

func deleteScreenConnectServices() {
	for _, name := range screenConnectServiceNames() {
		exec.Command("sc", "delete", name).Run()
		fmt.Printf("    Deleted service: %s\n", name)
	}
}

func removeScreenConnectDirs() {
	roots := []string{`C:\Program Files (x86)`, `C:\Program Files`, `C:\ProgramData`}
	for _, root := range roots {
		matches, _ := filepath.Glob(filepath.Join(root, "ScreenConnect Client (*"))
		for _, m := range matches {
			if err := os.RemoveAll(m); err == nil {
				fmt.Printf("    Removed: %s\n", m)
			}
		}
	}
}

func removeDecoyData() {
	dir := filepath.Join(CLEAN_ARTIFACT_DIR, "shared_finance_export")
	if err := os.RemoveAll(dir); err == nil {
		fmt.Printf("    Removed decoy dir: %s\n", dir)
	}
}

func removeTestArtifacts() {
	// Remove dropped stage binaries.
	matches, _ := filepath.Glob(filepath.Join(CLEAN_LOG_DIR, "208ef54b-06bc-4610-87b6-520aea57517e-*.exe"))
	for _, m := range matches {
		if err := os.Remove(m); err == nil {
			fmt.Printf("    Removed: %s\n", filepath.Base(m))
		}
	}

	files := []string{
		MSI_DROP,
		filepath.Join(CLEAN_LOG_DIR, "collected_export.zip"),
		filepath.Join(CLEAN_LOG_DIR, "screenconnect_cleanup.exe"),
		filepath.Join(CLEAN_LOG_DIR, "test_config.txt"),
		filepath.Join(CLEAN_LOG_DIR, "test_execution_log.json"),
		filepath.Join(CLEAN_LOG_DIR, "test_execution_log.txt"),
		filepath.Join(CLEAN_LOG_DIR, "bundle_results.json"),
	}
	for _, f := range files {
		if err := os.Remove(f); err == nil {
			fmt.Printf("    Removed: %s\n", filepath.Base(f))
		}
	}
}

func checkIsAdmin() bool {
	return exec.Command("net", "session").Run() == nil
}

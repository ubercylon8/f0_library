//go:build windows
// +build windows

/*
APT33 Tickler Backdoor DLL Sideloading - Cleanup Utility
Removes all test artifacts including:
- Registry Run key persistence
- Scheduled task persistence
- Spearphishing artifacts (ZIP, extracted files)
- Masqueraded binaries
- C2 staging data
- Stage binaries and log files

Runs unattended - no user prompts (suitable for remote/automated execution)
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	CLEANUP_TEST_UUID = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
	TASK_NAME         = "MicrosoftSharePointSync"
	RUN_KEY_VALUE     = "SharePoint"
)

func main() {
	fmt.Println("=================================================================")
	fmt.Println("APT33 Tickler DLL Sideloading - Cleanup Utility")
	fmt.Println("Test UUID: " + CLEANUP_TEST_UUID)
	fmt.Println("=================================================================")
	fmt.Println()

	if !checkIsAdmin() {
		fmt.Println("WARNING: Not running as administrator - some cleanup may fail")
		fmt.Println("Proceeding with available permissions...")
		fmt.Println()
	}

	fmt.Println("Starting cleanup (unattended mode)...")
	fmt.Println()

	totalSteps := 7
	currentStep := 0

	// Step 1: Remove registry Run key
	currentStep++
	fmt.Printf("[%d/%d] Removing registry Run key persistence...\n", currentStep, totalSteps)
	removeRegistryRunKey()

	// Step 2: Remove scheduled task
	currentStep++
	fmt.Printf("[%d/%d] Removing scheduled task...\n", currentStep, totalSteps)
	removeScheduledTask()

	// Step 3: Remove spearphishing artifacts
	currentStep++
	fmt.Printf("[%d/%d] Removing spearphishing artifacts...\n", currentStep, totalSteps)
	removeSpearphishingArtifacts()

	// Step 4: Remove C2 staging data
	currentStep++
	fmt.Printf("[%d/%d] Removing C2 staging data...\n", currentStep, totalSteps)
	removeC2StagingData()

	// Step 5: Remove masqueraded binaries
	currentStep++
	fmt.Printf("[%d/%d] Removing masqueraded binaries...\n", currentStep, totalSteps)
	removeMasqueradedBinaries()

	// Step 6: Remove stage binaries and logs
	currentStep++
	fmt.Printf("[%d/%d] Removing stage binaries and log files...\n", currentStep, totalSteps)
	removeStageBinaries()

	// Step 7: Remove state files
	currentStep++
	fmt.Printf("[%d/%d] Removing state files...\n", currentStep, totalSteps)
	removeStateFiles()

	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Println("Cleanup Complete!")
	fmt.Println("=================================================================")
	fmt.Println()
}

func removeRegistryRunKey() {
	// Read state file to determine which hive was used
	stateFile := filepath.Join("c:\\F0", "registry_run_key_state.txt")
	stateData, err := os.ReadFile(stateFile)
	if err != nil {
		fmt.Println("  No registry state file found - checking both HKCU and HKLM...")
		// Try both hives
		removeRunKeyFromHive(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, "HKCU")
		removeRunKeyFromHive(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKLM")
		return
	}

	config := parseStateFile(string(stateData))
	hive := config["HIVE"]
	hadValue := config["HAD_VALUE"]
	originalValue := config["ORIGINAL_VALUE"]

	var regHive registry.Key
	var keyPath string

	if hive == "HKLM" {
		regHive = registry.LOCAL_MACHINE
		keyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	} else {
		regHive = registry.CURRENT_USER
		keyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	}

	key, err := registry.OpenKey(regHive, keyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		fmt.Printf("  Failed to open registry key: %v\n", err)
		return
	}
	defer key.Close()

	if hadValue == "true" && originalValue != "" {
		// Restore original value
		if err := key.SetStringValue(RUN_KEY_VALUE, originalValue); err != nil {
			fmt.Printf("  Failed to restore original value: %v\n", err)
		} else {
			fmt.Printf("  Restored original '%s' value: %s\n", RUN_KEY_VALUE, originalValue)
		}
	} else {
		// Delete the value (it didn't exist before)
		if err := key.DeleteValue(RUN_KEY_VALUE); err != nil {
			if !strings.Contains(err.Error(), "not exist") {
				fmt.Printf("  Failed to delete registry value: %v\n", err)
			} else {
				fmt.Println("  Registry value already removed")
			}
		} else {
			fmt.Printf("  Deleted registry value '%s' from %s\\%s\n", RUN_KEY_VALUE, hive, keyPath)
		}
	}
}

func removeRunKeyFromHive(hive registry.Key, keyPath, hiveName string) {
	key, err := registry.OpenKey(hive, keyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer key.Close()

	if err := key.DeleteValue(RUN_KEY_VALUE); err == nil {
		fmt.Printf("  Deleted registry value '%s' from %s\\%s\n", RUN_KEY_VALUE, hiveName, keyPath)
	}
}

func removeScheduledTask() {
	// Check if task exists
	checkCmd := exec.Command("schtasks.exe", "/Query", "/TN", TASK_NAME)
	if err := checkCmd.Run(); err != nil {
		fmt.Println("  Scheduled task not found (already removed)")
		return
	}

	cmd := exec.Command("schtasks.exe", "/Delete", "/TN", TASK_NAME, "/F")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("  Failed to delete scheduled task: %v (%s)\n", err, strings.TrimSpace(string(output)))
	} else {
		fmt.Printf("  Deleted scheduled task '%s'\n", TASK_NAME)
	}
}

func removeSpearphishingArtifacts() {
	artifactDir := `c:\Users\fortika-test`

	// Remove ZIP archive
	zipPath := filepath.Join(artifactDir, "Q3_Financial_Report_2025.pdf.zip")
	if err := os.Remove(zipPath); err == nil {
		fmt.Println("  Removed: Q3_Financial_Report_2025.pdf.zip")
	}

	// Remove extraction directory
	extractDir := filepath.Join(artifactDir, "tickler_extract")
	if err := os.RemoveAll(extractDir); err == nil {
		fmt.Println("  Removed: tickler_extract/ directory")
	} else if !os.IsNotExist(err) {
		fmt.Printf("  Warning: Failed to remove tickler_extract/: %v\n", err)
	}

	// Try to remove the artifact directory if empty
	entries, err := os.ReadDir(artifactDir)
	if err == nil && len(entries) == 0 {
		os.Remove(artifactDir)
		fmt.Println("  Removed empty artifact directory")
	}
}

func removeC2StagingData() {
	stagingDir := filepath.Join("c:\\F0", "c2_staging")
	if err := os.RemoveAll(stagingDir); err == nil {
		fmt.Println("  Removed: c2_staging/ directory")
	} else if !os.IsNotExist(err) {
		fmt.Printf("  Warning: Failed to remove c2_staging/: %v\n", err)
	}
}

func removeMasqueradedBinaries() {
	// These would be in the tickler_extract directory (already removed above)
	// But check for any stray files
	strayFiles := []string{
		filepath.Join(`c:\Users\fortika-test`, "tickler_extract", "SharePoint.exe"),
		filepath.Join(`c:\Users\fortika-test`, "tickler_extract", "Microsoft.SharePoint.NativeMessaging.exe"),
		filepath.Join(`c:\Users\fortika-test`, "tickler_extract", "msvcp140.dll"),
		filepath.Join(`c:\Users\fortika-test`, "tickler_extract", "vcruntime140.dll"),
	}

	for _, f := range strayFiles {
		if err := os.Remove(f); err == nil {
			fmt.Printf("  Removed: %s\n", filepath.Base(f))
		}
	}
}

func removeStageBinaries() {
	// Remove stage binaries
	pattern := fmt.Sprintf("c:\\F0\\%s-*.exe", CLEANUP_TEST_UUID)
	matches, _ := filepath.Glob(pattern)
	for _, match := range matches {
		if err := os.Remove(match); err == nil {
			fmt.Printf("  Removed: %s\n", filepath.Base(match))
		}
	}

	// Remove output files
	outputFiles := []string{
		"c:\\F0\\T1566.001_output.txt",
		"c:\\F0\\T1574.002_output.txt",
		"c:\\F0\\T1547.001_output.txt",
		"c:\\F0\\T1053.005_output.txt",
		"c:\\F0\\T1036_output.txt",
		"c:\\F0\\T1071.001_output.txt",
	}
	for _, f := range outputFiles {
		if err := os.Remove(f); err == nil {
			fmt.Printf("  Removed: %s\n", filepath.Base(f))
		}
	}

	// Remove log files
	logFiles := []string{
		"c:\\F0\\test_execution_log.json",
		"c:\\F0\\test_execution_log.txt",
		"c:\\F0\\bundle_results.json",
	}
	for _, f := range logFiles {
		if err := os.Remove(f); err == nil {
			fmt.Printf("  Removed: %s\n", filepath.Base(f))
		}
	}

	// Remove cleanup utility itself (best effort - may fail because it's running)
	// Schedule self-deletion
	time.Sleep(500 * time.Millisecond)
	fmt.Println("  Stage binaries and logs cleaned up")
}

func removeStateFiles() {
	stateFiles := []string{
		"c:\\F0\\registry_run_key_state.txt",
		"c:\\F0\\scheduled_task_state.txt",
	}
	for _, f := range stateFiles {
		if err := os.Remove(f); err == nil {
			fmt.Printf("  Removed: %s\n", filepath.Base(f))
		}
	}
}

func parseStateFile(content string) map[string]string {
	config := make(map[string]string)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) == 2 {
			config[parts[0]] = parts[1]
		}
	}
	return config
}

func checkIsAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

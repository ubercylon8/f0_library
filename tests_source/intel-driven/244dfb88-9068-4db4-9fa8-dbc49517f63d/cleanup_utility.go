//go:build darwin
// +build darwin

/*
Cleanup Utility for DPRK BlueNoroff Financial Sector Attack Chain
Test UUID: 244dfb88-9068-4db4-9fa8-dbc49517f63d

Removes all test artifacts without user prompts (unattended execution).
Safe for remote/automated cleanup operations.
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	fmt.Println("=================================================================")
	fmt.Println("F0RT1KA Cleanup: DPRK BlueNoroff Financial Sector Attack Chain")
	fmt.Println("Test UUID: 244dfb88-9068-4db4-9fa8-dbc49517f63d")
	fmt.Printf("Cleanup started at: %s\n", time.Now().Format("2006-01-02T15:04:05"))
	fmt.Println("=================================================================")
	fmt.Println()

	targetDir := "/tmp/F0"
	artifactDir := "/Users/fortika-test"
	removed := 0
	errors := 0

	// --- Clean up stage binaries ---
	fmt.Println("[*] Removing stage binaries...")
	stageBinaries := []string{
		"244dfb88-9068-4db4-9fa8-dbc49517f63d-T1553.001",
		"244dfb88-9068-4db4-9fa8-dbc49517f63d-T1543.004",
		"244dfb88-9068-4db4-9fa8-dbc49517f63d-T1059.002",
		"244dfb88-9068-4db4-9fa8-dbc49517f63d-T1071.001",
		"244dfb88-9068-4db4-9fa8-dbc49517f63d-T1041",
	}
	for _, bin := range stageBinaries {
		path := filepath.Join(targetDir, bin)
		if err := os.Remove(path); err == nil {
			fmt.Printf("  [+] Removed: %s\n", bin)
			removed++
		} else if !os.IsNotExist(err) {
			fmt.Printf("  [!] Failed to remove %s: %v\n", bin, err)
			errors++
		}
	}

	// --- Clean up stage output files ---
	fmt.Println("[*] Removing stage output files...")
	outputFiles := []string{
		"T1553.001_output.txt",
		"T1543.004_output.txt",
		"T1059.002_output.txt",
		"T1071.001_output.txt",
		"T1041_output.txt",
	}
	for _, f := range outputFiles {
		path := filepath.Join(targetDir, f)
		if err := os.Remove(path); err == nil {
			fmt.Printf("  [+] Removed: %s\n", f)
			removed++
		} else if !os.IsNotExist(err) {
			fmt.Printf("  [!] Failed to remove %s: %v\n", f, err)
			errors++
		}
	}

	// --- Clean up simulation artifacts in /tmp/F0 ---
	fmt.Println("[*] Removing simulation artifacts from /tmp/F0...")
	f0Artifacts := []string{
		"codesign_metadata.json",
		"remove_quarantine.sh",
		"validate_creds.sh",
		"keychain_dump.sh",
		"tcc_manipulation.sh",
	}
	for _, f := range f0Artifacts {
		path := filepath.Join(targetDir, f)
		if err := os.Remove(path); err == nil {
			fmt.Printf("  [+] Removed: %s\n", f)
			removed++
		} else if !os.IsNotExist(err) {
			fmt.Printf("  [!] Failed to remove %s: %v\n", f, err)
			errors++
		}
	}

	// --- Clean up staging directories ---
	fmt.Println("[*] Removing staging directories...")
	stagingDirs := []string{
		filepath.Join(targetDir, "credential_staging"),
		filepath.Join(targetDir, "c2_simulation"),
		filepath.Join(targetDir, "exfil_staging"),
	}
	for _, dir := range stagingDirs {
		if err := os.RemoveAll(dir); err == nil {
			fmt.Printf("  [+] Removed directory: %s\n", filepath.Base(dir))
			removed++
		} else if !os.IsNotExist(err) {
			fmt.Printf("  [!] Failed to remove %s: %v\n", filepath.Base(dir), err)
			errors++
		}
	}

	// --- Clean up artifacts in /Users/fortika-test ---
	fmt.Println("[*] Removing artifacts from /Users/fortika-test...")
	testArtifacts := []string{
		filepath.Join(artifactDir, "InternalPDFViewer.sh"),
		filepath.Join(artifactDir, "CryptoExchangePro_Info.plist"),
		filepath.Join(artifactDir, ".zshenv"),
		filepath.Join(artifactDir, "password_prompt.applescript"),
	}
	for _, f := range testArtifacts {
		if err := os.Remove(f); err == nil {
			fmt.Printf("  [+] Removed: %s\n", filepath.Base(f))
			removed++
		} else if !os.IsNotExist(err) {
			fmt.Printf("  [!] Failed to remove %s: %v\n", filepath.Base(f), err)
			errors++
		}
	}

	// Remove simulated LaunchAgents/LaunchDaemons directories
	artifactDirs := []string{
		filepath.Join(artifactDir, "Library", "LaunchAgents"),
		filepath.Join(artifactDir, "Library", "LaunchDaemons"),
		filepath.Join(artifactDir, "Library"),
	}
	for _, dir := range artifactDirs {
		if err := os.RemoveAll(dir); err == nil {
			if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
				fmt.Printf("  [+] Removed directory: %s\n", dir)
				removed++
			}
		}
	}

	// --- Clean up log files ---
	fmt.Println("[*] Removing log files...")
	logFiles := []string{
		filepath.Join(targetDir, "test_execution_log.json"),
		filepath.Join(targetDir, "test_execution_log.txt"),
		filepath.Join(targetDir, "bundle_results.json"),
	}
	for _, f := range logFiles {
		if err := os.Remove(f); err == nil {
			fmt.Printf("  [+] Removed: %s\n", filepath.Base(f))
			removed++
		} else if !os.IsNotExist(err) {
			fmt.Printf("  [!] Failed to remove %s: %v\n", filepath.Base(f), err)
			errors++
		}
	}

	// Summary
	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Printf("Cleanup complete at: %s\n", time.Now().Format("2006-01-02T15:04:05"))
	fmt.Printf("  Items removed: %d\n", removed)
	fmt.Printf("  Errors: %d\n", errors)
	fmt.Println("=================================================================")
}

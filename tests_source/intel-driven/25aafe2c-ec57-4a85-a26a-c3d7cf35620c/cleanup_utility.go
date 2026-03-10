//go:build linux
// +build linux

/*
Cleanup Utility for ESXi Hypervisor Ransomware Kill Chain Test
Removes all test artifacts created during the 5-stage simulation.
Runs unattended (no user prompts) suitable for remote/automated execution.
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
	fmt.Println("F0RT1KA Cleanup: ESXi Hypervisor Ransomware Kill Chain")
	fmt.Printf("Timestamp: %s\n", time.Now().Format("2006-01-02T15:04:05"))
	fmt.Println("=================================================================")
	fmt.Println("")

	targetDir := "/tmp/F0"
	simulationDir := "/home/fortika-test/vmfs_simulation"

	errors := 0

	// Remove Stage 1 artifacts
	fmt.Println("[*] Removing Stage 1 artifacts (ESXi Reconnaissance)...")
	if err := os.RemoveAll(filepath.Join(targetDir, "esxi_recon")); err != nil {
		fmt.Printf("    WARNING: Failed to remove esxi_recon: %v\n", err)
		errors++
	} else {
		fmt.Println("    [+] esxi_recon/ removed")
	}
	removeFile(filepath.Join(targetDir, "recon_summary.txt"), &errors)

	// Remove Stage 2 artifacts
	fmt.Println("[*] Removing Stage 2 artifacts (Lateral Movement)...")
	if err := os.RemoveAll(filepath.Join(targetDir, "esxi_lateral")); err != nil {
		fmt.Printf("    WARNING: Failed to remove esxi_lateral: %v\n", err)
		errors++
	} else {
		fmt.Println("    [+] esxi_lateral/ removed")
	}
	removeFile(filepath.Join(targetDir, "lateral_movement_summary.txt"), &errors)

	// Remove Stage 3 artifacts
	fmt.Println("[*] Removing Stage 3 artifacts (VM Kill)...")
	if err := os.RemoveAll(filepath.Join(targetDir, "esxi_vmkill")); err != nil {
		fmt.Printf("    WARNING: Failed to remove esxi_vmkill: %v\n", err)
		errors++
	} else {
		fmt.Println("    [+] esxi_vmkill/ removed")
	}
	removeFile(filepath.Join(targetDir, "vmkill_summary.txt"), &errors)

	// Remove Stage 4 artifacts
	fmt.Println("[*] Removing Stage 4 artifacts (Data Exfiltration)...")
	if err := os.RemoveAll(filepath.Join(targetDir, "esxi_exfil")); err != nil {
		fmt.Printf("    WARNING: Failed to remove esxi_exfil: %v\n", err)
		errors++
	} else {
		fmt.Println("    [+] esxi_exfil/ removed")
	}
	removeFile(filepath.Join(targetDir, "exfil_summary.txt"), &errors)

	// Remove Stage 5 artifacts
	fmt.Println("[*] Removing Stage 5 artifacts (Encryption)...")
	if err := os.RemoveAll(filepath.Join(targetDir, "esxi_encrypt")); err != nil {
		fmt.Printf("    WARNING: Failed to remove esxi_encrypt: %v\n", err)
		errors++
	} else {
		fmt.Println("    [+] esxi_encrypt/ removed")
	}
	removeFile(filepath.Join(targetDir, "encryption_summary.txt"), &errors)

	// Remove simulation directory (try both ARTIFACT_DIR and fallback location)
	fmt.Println("[*] Removing simulation artifacts...")
	if err := os.RemoveAll(simulationDir); err != nil {
		fmt.Printf("    WARNING: Failed to remove %s: %v\n", simulationDir, err)
		errors++
	} else {
		fmt.Println("    [+] vmfs_simulation/ removed from ARTIFACT_DIR")
	}
	// Also clean fallback location
	fallbackSimDir := filepath.Join(targetDir, "fortika-test")
	if _, err := os.Stat(fallbackSimDir); err == nil {
		if err := os.RemoveAll(fallbackSimDir); err != nil {
			fmt.Printf("    WARNING: Failed to remove fallback dir: %v\n", err)
			errors++
		} else {
			fmt.Println("    [+] fortika-test/ fallback removed")
		}
	}

	// Remove stage binaries
	fmt.Println("[*] Removing stage binaries...")
	testUUID := "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"
	techniques := []string{"T1046", "T1021.004", "T1489", "T1048", "T1486"}
	for _, t := range techniques {
		binaryName := fmt.Sprintf("%s-%s", testUUID, t)
		removeFile(filepath.Join(targetDir, binaryName), &errors)
	}
	removeFile(filepath.Join(targetDir, "esxi_cleanup"), &errors)

	// Remove test config
	removeFile(filepath.Join(targetDir, "test_config.txt"), &errors)

	fmt.Println("")
	fmt.Println("=================================================================")
	if errors == 0 {
		fmt.Println("Cleanup complete. All test artifacts removed.")
	} else {
		fmt.Printf("Cleanup complete with %d warnings.\n", errors)
	}
	fmt.Println("=================================================================")
}

func removeFile(path string, errors *int) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return // File doesn't exist, skip silently
	}

	if err := os.Remove(path); err != nil {
		fmt.Printf("    WARNING: Failed to remove %s: %v\n", filepath.Base(path), err)
		*errors++
	} else {
		fmt.Printf("    [+] %s removed\n", filepath.Base(path))
	}
}

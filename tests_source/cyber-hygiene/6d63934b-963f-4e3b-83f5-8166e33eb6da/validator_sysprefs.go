//go:build ignore
// +build ignore

// validator_sysprefs.go — standalone validator binary for System Preferences & Security checks.
// Built separately by build_all.sh, signed, then embedded in the orchestrator.
// Exit 126 = compliant, 101 = non-compliant, 999 = error.

package main

import (
	"fmt"
	"os"
)

const validatorName = "sysprefs"

func main() {
	fmt.Println("[validator-sysprefs] Running System Preferences & Security checks...")

	if !IsRunningAsRoot() {
		fmt.Println("[ERROR] Root privileges required")
		os.Exit(999)
	}

	result := RunSysPrefsChecks()

	for i, check := range result.Checks {
		if i == len(result.Checks)-1 {
			fmt.Println(FormatLastCheckResult(check))
		} else {
			fmt.Println(FormatCheckResult(check))
		}
	}

	if err := WriteValidatorOutput(validatorName, result); err != nil {
		fmt.Printf("[ERROR] Failed to write output: %v\n", err)
		os.Exit(999)
	}

	if result.IsCompliant {
		fmt.Printf("[validator-sysprefs] COMPLIANT (%d/%d passed)\n", result.PassedCount, result.TotalChecks)
		os.Exit(126)
	}
	fmt.Printf("[validator-sysprefs] NON-COMPLIANT (%d/%d passed)\n", result.PassedCount, result.TotalChecks)
	os.Exit(101)
}

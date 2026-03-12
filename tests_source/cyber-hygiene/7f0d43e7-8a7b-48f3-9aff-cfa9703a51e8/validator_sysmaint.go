//go:build ignore
// +build ignore

// validator_sysmaint.go - standalone validator binary for system maintenance checks.
// Built separately by build_all.sh, then embedded in the orchestrator.
// Exit 126 = compliant, 101 = non-compliant, 999 = error.

package main

import (
	"fmt"
	"os"
)

const validatorName = "sysmaint"

func main() {
	fmt.Println("[validator-sysmaint] Running system maintenance checks...")

	if !IsAdmin() {
		fmt.Println("[ERROR] Root privileges required")
		os.Exit(999)
	}

	result := RunSysMaintChecks()

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
		fmt.Printf("[validator-sysmaint] COMPLIANT (%d/%d passed)\n", result.PassedCount, result.TotalChecks)
		os.Exit(126)
	}
	fmt.Printf("[validator-sysmaint] NON-COMPLIANT (%d/%d passed)\n", result.PassedCount, result.TotalChecks)
	os.Exit(101)
}

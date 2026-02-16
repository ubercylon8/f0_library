//go:build ignore
// +build ignore

// validator_defender.go — standalone validator binary for Microsoft Defender checks.
// Built separately by build_all.sh, signed, then embedded in the orchestrator.
// Exit 126 = compliant, 101 = non-compliant, 999 = error.

package main

import (
	"fmt"
	"os"
)

const validatorName = "defender"

func main() {
	fmt.Println("[validator-defender] Running Microsoft Defender checks...")

	if !IsAdmin() {
		fmt.Println("[ERROR] Administrator privileges required")
		os.Exit(999)
	}

	result := RunDefenderChecks()

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
		fmt.Printf("[validator-defender] COMPLIANT (%d/%d passed)\n", result.PassedCount, result.TotalChecks)
		os.Exit(126)
	}
	fmt.Printf("[validator-defender] NON-COMPLIANT (%d/%d passed)\n", result.PassedCount, result.TotalChecks)
	os.Exit(101)
}

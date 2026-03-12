//go:build ignore
// +build ignore

// validator_network.go — standalone validator binary for Network Security checks.
// Built separately by build_all.sh, signed, then embedded in the orchestrator.
// Exit 126 = compliant, 101 = non-compliant, 999 = error.

package main

import (
	"fmt"
	"os"
)

const validatorName = "network"

func main() {
	fmt.Println("[validator-network] Running Network Security checks...")

	if !IsRunningAsRoot() {
		fmt.Println("[ERROR] Root privileges required")
		os.Exit(999)
	}

	result := RunNetworkChecks()

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
		fmt.Printf("[validator-network] COMPLIANT (%d/%d passed)\n", result.PassedCount, result.TotalChecks)
		os.Exit(126)
	}
	fmt.Printf("[validator-network] NON-COMPLIANT (%d/%d passed)\n", result.PassedCount, result.TotalChecks)
	os.Exit(101)
}

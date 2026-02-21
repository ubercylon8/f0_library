//go:build ignore
// +build ignore

// validator_crowdstrike.go -- standalone validator binary for CrowdStrike Falcon checks.
// Built separately by build_all.sh, signed, then embedded in the orchestrator.
// Exit 126 = compliant, 101 = non-compliant, 999 = error.

package main

import (
	"fmt"
	"os"
)

const validatorName = "crowdstrike"

func main() {
	fmt.Println("[validator-crowdstrike] Running CrowdStrike Falcon checks...")

	if !IsAdmin() {
		fmt.Println("[ERROR] Administrator privileges required")
		os.Exit(999)
	}

	// Check if CrowdStrike Falcon is installed before running checks
	if !isFalconInstalled() {
		fmt.Println("[ERROR] CrowdStrike Falcon is not detected on this system")
		// Write output with all checks failed
		result := ValidatorResult{
			Name:        "CrowdStrike Falcon Configuration",
			Checks:      []CheckResult{},
			PassedCount: 0,
			FailedCount: 0,
			TotalChecks: 0,
			IsCompliant: false,
		}
		if err := WriteValidatorOutput(validatorName, result); err != nil {
			fmt.Printf("[ERROR] Failed to write output: %v\n", err)
		}
		os.Exit(999)
	}

	result := RunCrowdStrikeChecks()

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
		fmt.Printf("[validator-crowdstrike] COMPLIANT (%d/%d passed)\n", result.PassedCount, result.TotalChecks)
		os.Exit(126)
	}
	fmt.Printf("[validator-crowdstrike] NON-COMPLIANT (%d/%d passed)\n", result.PassedCount, result.TotalChecks)
	os.Exit(101)
}

//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"os"
)

const validatorName = "lockout"

func main() {
	fmt.Println("[validator-lockout] Running Account Lockout Policy checks...")

	if !IsAdmin() {
		fmt.Println("[ERROR] Administrator privileges required")
		os.Exit(999)
	}

	result := RunLockoutChecks()

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
		fmt.Printf("[validator-lockout] COMPLIANT (%d/%d passed)\n", result.PassedCount, result.TotalChecks)
		os.Exit(126)
	}
	fmt.Printf("[validator-lockout] NON-COMPLIANT (%d/%d passed)\n", result.PassedCount, result.TotalChecks)
	os.Exit(101)
}

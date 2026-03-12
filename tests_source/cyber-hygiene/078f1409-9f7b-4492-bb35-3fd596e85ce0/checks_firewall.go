//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
)

// RunFirewallChecks performs Windows Firewall checks (CIS Level 1)
func RunFirewallChecks() ValidatorResult {
	checks := []CheckResult{
		checkFirewallDomainProfile(),
		checkFirewallPrivateProfile(),
		checkFirewallPublicProfile(),
		checkFirewallDomainInbound(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Windows Firewall",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// getFirewallProfileStatus queries firewall status for a specific profile
func getFirewallProfileStatus(profile string) (enabled bool, inboundBlocked bool, err error) {
	script := fmt.Sprintf(`
		$fw = Get-NetFirewallProfile -Name "%s" -ErrorAction SilentlyContinue
		if ($fw) {
			Write-Output "ENABLED:$($fw.Enabled)"
			Write-Output "INBOUND:$($fw.DefaultInboundAction)"
		} else {
			Write-Output "ERROR:Profile not found"
		}
	`, profile)

	output, err := RunPowerShell(script)
	if err != nil {
		// Fallback to netsh
		netshOutput, netshErr := RunCommand("netsh", "advfirewall", "show", strings.ToLower(profile)+"profile")
		if netshErr != nil {
			return false, false, fmt.Errorf("both PowerShell and netsh failed: %v", netshErr)
		}
		enabled = strings.Contains(strings.ToLower(netshOutput), "state") && strings.Contains(strings.ToLower(netshOutput), "on")
		inboundBlocked = strings.Contains(strings.ToLower(netshOutput), "block")
		return enabled, inboundBlocked, nil
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ENABLED:") {
			enabled = strings.Contains(line, "True")
		}
		if strings.HasPrefix(line, "INBOUND:") {
			// DefaultInboundAction: 2 = Block, 4 = Allow
			val := strings.TrimPrefix(line, "INBOUND:")
			val = strings.TrimSpace(val)
			inboundBlocked = val == "Block" || val == "2"
		}
	}
	return enabled, inboundBlocked, nil
}

// CH-CW1-030: Domain Profile Firewall Enabled
func checkFirewallDomainProfile() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-030",
		Name:        "Domain Profile Firewall Enabled",
		Category:    "firewall",
		Description: "Windows Firewall: Domain profile - Firewall state = On (CIS 9.1.1)",
		Severity:    "high",
		Expected:    "Firewall enabled for Domain profile",
		Techniques:  []string{"T1562.004"},
		Tactics:     []string{"defense-evasion"},
	}

	enabled, _, err := getFirewallProfileStatus("Domain")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = enabled
	result.Actual = BoolToEnabledDisabled(enabled)
	result.Details = "Domain profile: " + result.Actual
	return result
}

// CH-CW1-031: Private Profile Firewall Enabled
func checkFirewallPrivateProfile() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-031",
		Name:        "Private Profile Firewall Enabled",
		Category:    "firewall",
		Description: "Windows Firewall: Private profile - Firewall state = On (CIS 9.2.1)",
		Severity:    "high",
		Expected:    "Firewall enabled for Private profile",
		Techniques:  []string{"T1562.004"},
		Tactics:     []string{"defense-evasion"},
	}

	enabled, _, err := getFirewallProfileStatus("Private")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = enabled
	result.Actual = BoolToEnabledDisabled(enabled)
	result.Details = "Private profile: " + result.Actual
	return result
}

// CH-CW1-032: Public Profile Firewall Enabled
func checkFirewallPublicProfile() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-032",
		Name:        "Public Profile Firewall Enabled",
		Category:    "firewall",
		Description: "Windows Firewall: Public profile - Firewall state = On (CIS 9.3.1)",
		Severity:    "high",
		Expected:    "Firewall enabled for Public profile",
		Techniques:  []string{"T1562.004"},
		Tactics:     []string{"defense-evasion"},
	}

	enabled, _, err := getFirewallProfileStatus("Public")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = enabled
	result.Actual = BoolToEnabledDisabled(enabled)
	result.Details = "Public profile: " + result.Actual
	return result
}

// CH-CW1-033: Domain Profile Inbound Connections Blocked
func checkFirewallDomainInbound() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CW1-033",
		Name:        "Domain Profile Inbound Block",
		Category:    "firewall",
		Description: "Windows Firewall: Domain profile - Inbound connections = Block (CIS 9.1.2)",
		Severity:    "high",
		Expected:    "DefaultInboundAction = Block",
		Techniques:  []string{"T1562.004"},
		Tactics:     []string{"defense-evasion"},
	}

	_, inboundBlocked, err := getFirewallProfileStatus("Domain")
	if err != nil {
		result.Passed = false
		result.Actual = fmt.Sprintf("Unable to query: %v", err)
		result.Details = result.Actual
		return result
	}

	result.Passed = inboundBlocked
	if inboundBlocked {
		result.Actual = "Block (inbound connections blocked by default)"
	} else {
		result.Actual = "Allow (inbound connections allowed)"
	}
	result.Details = result.Actual
	return result
}

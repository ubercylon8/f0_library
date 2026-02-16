//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Network protocol registry paths
const (
	DNSClientPath     = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
	NetBTPath         = `SYSTEM\CurrentControlSet\Services\NetBT\Parameters`
	NetBTInterfacePathPrefix = `SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`
	WPADPath          = `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad`
	WinHttpPath       = `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp`
)

// RunNetworkChecks performs all network protocol hardening checks
func RunNetworkChecks() ValidatorResult {
	checks := []CheckResult{
		checkLLMNRDisabled(),
		checkNetBIOSDisabled(),
		checkWPADDisabled(),
		checkIPv6DisabledOrSecured(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:         "Network Protocol Hardening",
		Checks:       checks,
		PassedCount:  passed,
		FailedCount:  failed,
		TotalChecks:  len(checks),
		IsCompliant:  failed == 0,
	}
}

// checkLLMNRDisabled verifies LLMNR is disabled
func checkLLMNRDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-NET-001",
		Name:        "LLMNR Disabled",
		Category:    "network",
		Description: "Checks if Link-Local Multicast Name Resolution is disabled",
		Severity:    "high",
		Expected:    "Disabled (EnableMulticast = 0)",
		Techniques:  []string{"T1557.001"},
		Tactics:     []string{"credential-access"},
	}

	// Check DNS Client policy
	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, DNSClientPath, "EnableMulticast", 0)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured (default enabled)"
		result.Details = "Not configured"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("EnableMulticast = %d", val)
	result.Details = BoolToEnabledDisabled(!match) + " (LLMNR)"
	return result
}

// checkNetBIOSDisabled verifies NetBIOS over TCP/IP is disabled
func checkNetBIOSDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-NET-002",
		Name:        "NetBIOS over TCP/IP",
		Category:    "network",
		Description: "Checks if NetBIOS over TCP/IP is disabled",
		Severity:    "high",
		Expected:    "Disabled on all interfaces (NetbiosOptions = 2)",
		Techniques:  []string{"T1557.001"},
		Tactics:     []string{"credential-access"},
	}

	// Check via PowerShell - more reliable for checking all interfaces
	output, err := RunPowerShell(`
		$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'"
		$allDisabled = $true
		$statuses = @()
		foreach ($adapter in $adapters) {
			# TcpipNetbiosOptions: 0=Default, 1=Enable, 2=Disable
			$status = switch ($adapter.TcpipNetbiosOptions) {
				0 { "Default" }
				1 { "Enabled" }
				2 { "Disabled" }
				default { "Unknown" }
			}
			$statuses += "$($adapter.Description):$status"
			if ($adapter.TcpipNetbiosOptions -ne 2) { $allDisabled = $false }
		}
		if ($adapters.Count -eq 0) { "NoAdapters" }
		elseif ($allDisabled) { "AllDisabled" }
		else { "NotAllDisabled|$($statuses -join ';')" }
	`)

	if err == nil {
		output = strings.TrimSpace(output)
		if output == "AllDisabled" {
			result.Passed = true
			result.Actual = "Disabled on all interfaces"
			result.Details = "Disabled"
		} else if output == "NoAdapters" {
			result.Passed = true
			result.Actual = "No IP-enabled adapters"
			result.Details = "N/A"
		} else if strings.HasPrefix(output, "NotAllDisabled") {
			result.Passed = false
			result.Actual = "Not disabled on all interfaces"
			result.Details = "Some interfaces have NetBIOS enabled"
		} else {
			result.Passed = false
			result.Actual = output
			result.Details = output
		}
		return result
	}

	// Fallback: check global NodeType
	match, val, err := CheckRegistryDWORD(registry.LOCAL_MACHINE, NetBTPath, "NodeType", 2)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	// NodeType 2 = P-node (point-to-point, no broadcast)
	result.Passed = match
	result.Actual = fmt.Sprintf("NodeType = %d", val)
	if match {
		result.Details = "P-node (no broadcast)"
	} else {
		result.Details = "Not P-node"
	}
	return result
}

// checkWPADDisabled verifies WPAD is disabled
func checkWPADDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-NET-003",
		Name:        "WPAD Disabled",
		Category:    "network",
		Description: "Checks if Web Proxy Auto-Discovery is disabled",
		Severity:    "medium",
		Expected:    "Disabled (WpadOverride = 1 or AutoDetect = 0)",
		Techniques:  []string{"T1557.001"},
		Tactics:     []string{"credential-access"},
	}

	// Check WpadOverride in WinHttp
	match1, _, err1 := CheckRegistryDWORD(registry.LOCAL_MACHINE, WinHttpPath, "WpadOverride", 1)

	// Check AutoDetect in Internet Settings
	match2, _, err2 := CheckRegistryDWORD(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "AutoDetect", 0)

	if err1 == nil && match1 {
		result.Passed = true
		result.Actual = "WpadOverride = 1"
		result.Details = "Disabled via WpadOverride"
		return result
	}

	if err2 == nil && match2 {
		result.Passed = true
		result.Actual = "AutoDetect = 0"
		result.Details = "Disabled via AutoDetect"
		return result
	}

	// Check via PowerShell
	output, err := RunPowerShell(`
		$ie = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
		if ($ie.AutoDetect -eq 0) { "Disabled" }
		elseif ($ie.AutoDetect -eq 1) { "Enabled" }
		else { "Default" }
	`)

	if err == nil {
		status := strings.TrimSpace(output)
		result.Passed = status == "Disabled"
		result.Actual = status
		result.Details = status
		return result
	}

	result.Passed = false
	result.Actual = "Not configured (default enabled)"
	result.Details = "Not configured"
	return result
}

// checkIPv6DisabledOrSecured verifies IPv6 is properly configured
func checkIPv6DisabledOrSecured() CheckResult {
	result := CheckResult{
		ControlID:   "CH-NET-004",
		Name:        "IPv6 Tunneling Disabled",
		Category:    "network",
		Description: "Checks if IPv6 transition technologies (6to4, ISATAP, Teredo) are disabled",
		Severity:    "medium",
		Expected:    "Transition technologies disabled",
		Techniques:  []string{"T1572"},
		Tactics:     []string{"command-and-control"},
	}

	// Check via PowerShell
	output, err := RunPowerShell(`
		$issues = @()

		# Check 6to4
		$6to4 = Get-NetAdapterBinding -ComponentId ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*6to4*' }

		# Check Teredo
		$teredo = netsh interface teredo show state 2>$null
		if ($teredo -match 'qualified' -or $teredo -match 'client') {
			$issues += 'Teredo'
		}

		# Check ISATAP
		$isatap = netsh interface isatap show state 2>$null
		if ($isatap -match 'enabled') {
			$issues += 'ISATAP'
		}

		# Check registry for DisabledComponents
		$reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -ErrorAction SilentlyContinue
		$disabled = $reg.DisabledComponents

		# 0xFF = disable all IPv6, 0x20 = disable 6to4, 0x01 = disable all tunnel interfaces
		if ($disabled -band 0xFF -eq 0xFF) {
			"AllDisabled"
		} elseif ($disabled -band 0x21) {
			"TunnelsDisabled"
		} elseif ($issues.Count -gt 0) {
			"Issues:$($issues -join ',')"
		} else {
			"Default"
		}
	`)

	if err == nil {
		output = strings.TrimSpace(output)
		switch {
		case output == "AllDisabled":
			result.Passed = true
			result.Actual = "IPv6 fully disabled"
			result.Details = "IPv6 disabled"
		case output == "TunnelsDisabled":
			result.Passed = true
			result.Actual = "Tunnel technologies disabled"
			result.Details = "Tunnels disabled"
		case strings.HasPrefix(output, "Issues:"):
			result.Passed = false
			issues := strings.TrimPrefix(output, "Issues:")
			result.Actual = fmt.Sprintf("Active: %s", issues)
			result.Details = result.Actual
		default:
			result.Passed = false
			result.Actual = "Default configuration"
			result.Details = "Not hardened"
		}
		return result
	}

	// Fallback to registry only
	match, val, err := CheckRegistryDWORDMinimum(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`, "DisabledComponents", 0x20)
	if err != nil {
		result.Passed = false
		result.Actual = "Not configured"
		result.Details = "Not configured"
		return result
	}

	result.Passed = match
	result.Actual = fmt.Sprintf("DisabledComponents = 0x%X", val)
	if match {
		result.Details = "Tunnels disabled"
	} else {
		result.Details = "Tunnels may be active"
	}
	return result
}

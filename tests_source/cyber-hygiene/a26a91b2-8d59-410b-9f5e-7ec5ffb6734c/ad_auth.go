//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
)

// ADPreFlight validates Active Directory PowerShell prerequisites:
// 1. PowerShell available
// 2. ActiveDirectory module installed (RSAT)
// 3. Machine is domain-joined
// 4. Can query AD (test Get-ADDomain)
// Returns the domain DNS name on success.
func ADPreFlight() (string, error) {
	// 1. Check PowerShell is available
	_, err := RunPowerShell("$PSVersionTable.PSVersion.ToString()")
	if err != nil {
		return "", fmt.Errorf("PowerShell is not available: %v", err)
	}

	// 2. Check ActiveDirectory module is installed (RSAT)
	modCheck, err := RunPowerShell(`if (Get-Module -ListAvailable -Name ActiveDirectory) { 'OK' } else { 'MISSING' }`)
	if err != nil || strings.TrimSpace(modCheck) != "OK" {
		return "", fmt.Errorf(
			"ActiveDirectory PowerShell module not found\n" +
				"  Install RSAT tools:\n" +
				"    Windows 10/11: Settings > Apps > Optional Features > Add RSAT: Active Directory\n" +
				"    Server:        Install-WindowsFeature RSAT-AD-PowerShell")
	}

	// 3. Check domain membership
	domainCheck, err := RunPowerShell(`(Get-WmiObject Win32_ComputerSystem).PartOfDomain`)
	if err != nil {
		return "", fmt.Errorf("failed to check domain membership: %v", err)
	}
	if !strings.EqualFold(strings.TrimSpace(domainCheck), "True") {
		return "", fmt.Errorf("this machine is not domain-joined (required for AD queries)")
	}

	// 4. Test AD connectivity by querying domain
	domainName, err := RunADCommand(`(Get-ADDomain).DNSRoot`)
	if err != nil {
		return "", fmt.Errorf("failed to query Active Directory: %v\n  Ensure a domain controller is reachable", err)
	}

	domainName = strings.TrimSpace(domainName)
	if domainName == "" {
		return "", fmt.Errorf("could not determine AD domain name")
	}

	return domainName, nil
}

// RunADCommand executes a PowerShell command with the ActiveDirectory module imported.
func RunADCommand(script string) (string, error) {
	fullScript := "Import-Module ActiveDirectory -ErrorAction Stop\n" + script
	return RunPowerShell(fullScript)
}

// RunADJSON executes an AD command and returns JSON-parsed output.
func RunADJSON(query string) ([]map[string]interface{}, error) {
	script := fmt.Sprintf("Import-Module ActiveDirectory -ErrorAction Stop\n%s | ConvertTo-Json -Depth 10 -Compress", query)
	output, err := RunPowerShell(script)
	if err != nil {
		return nil, err
	}
	return ParseGraphJSON(output)
}

//go:build windows
// +build windows

/*
ID: 5685dd5a-5a03-4884-a50e-b19123f9a1e9
NAME: Active Directory Recon
UNIT: response
CREATED: 2024-02-15 20:16:25.302114+00:00
*/
package main

import (
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

func credsInFiles() bool {
	_, err := Endpoint.Shell([]string{"cmd", "/c", "findstr /si password *.xml *.doc *.txt *.xls"})
	return err == nil
}

func adJoined() bool {
	Endpoint.Say("Determining if endpoint is conected to Active Directory")
	command := []string{"powershell.exe", "-c", "[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()"}
	_, err := Endpoint.Shell(command)
	if err != nil {
		Endpoint.Say("Computer not connected to Active Directory")
		return false
	}
	return true
}

func adUserEnum() bool {
	commands := [][]string{{"powershell.exe", "-c", "net group \"Domain Admins\" /dom"},
		{"powerhsell.exe", "-c", "net group \"Sharepoint admin\" /dom"}}
	for _, command := range commands {
		_, err := Endpoint.Shell(command)
		if err != nil {
			return false
		}
	}
	return true
}

func adComputerEnum() bool {
	command := []string{"powershell.exe", "-c", "Get-ADComputer -Filter \"Name -like 'Domain Controller'\" | Select-Object Name, Enabled"}
	_, err := Endpoint.Shell(command)
	return err == nil
}

func adTrustEnum() bool {
	Endpoint.Say("Attempting Active Directory trust enumeration")
	command := []string{"powershell.exe", "-c", "Get-ADTrust -Filter {Direction -eq 'Outbound'}"}
	_, err := Endpoint.Shell(command)
	return err == nil
}

func fileEnum() bool {
	enums := [][]string{
		{"cmd.exe", "/c", "dir /AH c:\\"}, {"cmd.exe", "/c", "tree"}, {"cmd.exe", "/c", "dir /s *pass* == *cred* == *vnc* == *.config*"},
	}
	_, err := Endpoint.ExecuteRandomCommand(enums)
	return err == nil
}

func networkDiscovery() bool {
	commands := [][]string{
		{"powershell.exe", "-c", "arp -a"},
		{"powershell.exe", "-c", "ipconfig /all"},
		{"powershell.exe", "-c", "netstat -ano"},
	}

	_, err := Endpoint.ExecuteRandomCommand(commands)
	return err == nil
}

func test() {
	Endpoint.Say("Performing relevance check")
	if !adJoined() {
		Endpoint.Say("Test is irrelevant")
		Endpoint.Stop(Endpoint.NotRelevant)
	}
	Endpoint.Say("Searching for credentials in files on host")
	if !credsInFiles() {
		Endpoint.Say("Credential search was interrupted or failed")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Attempting Active Directory user enumeration")
	if !adUserEnum() {
		Endpoint.Say("AD user enumeration commands interrupted or failed")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Attempting Active Directory computer enumeration")
	if !adComputerEnum() {
		Endpoint.Say("AD computer enumeration commands interrupted or failed")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Attempting Active Directory trust enumeration")
	if !adTrustEnum() {
		Endpoint.Say("AD trust enumeration commands interrupted or failed")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Attempting generic file and directory enumeration")
	if !fileEnum() {
		Endpoint.Say("File enumeration commands interrupted or failed")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Attempting network discovery and enumeration")
	if !networkDiscovery() {
		Endpoint.Say("Network discovery commands interrupted or failed")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Stop(Endpoint.TestCompletedNormally)
}

func main() {
	Endpoint.Start(test)
}

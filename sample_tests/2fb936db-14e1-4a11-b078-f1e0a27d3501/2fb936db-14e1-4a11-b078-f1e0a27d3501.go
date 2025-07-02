/*
ID: 2fb936db-14e1-4a11-b078-f1e0a27d3501
NAME: Conti Ransomware
TECHNIQUE: T1204.002
UNIT: response
CREATED: 2023-10-04 15:47:47.375048
*/
package main

import (
	_ "embed"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed conti.exe
var malicious []byte

func test() {
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("%v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	Endpoint.Say("Extracting file for quarantine test")
	Endpoint.Say("Pausing for 3 seconds to gauge defensive reaction")
	if Endpoint.Quarantined("conti.exe", malicious) {
		Endpoint.Say("Malicious file was caught!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}
	Endpoint.Say("Malicious file was not caught")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}

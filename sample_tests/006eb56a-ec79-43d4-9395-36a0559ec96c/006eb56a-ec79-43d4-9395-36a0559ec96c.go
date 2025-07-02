/*
ID: 006eb56a-ec79-43d4-9395-36a0559ec96c
NAME: Non-Standard Port
TECHNIQUE: T1571
UNIT: response
CREATED: 2024-01-13 01:12:34.096156+00:00
*/
package main

import (
	"math/rand"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	Network "github.com/preludeorg/libraries/go/tests/network"
)

func nonStandardPort() bool {
	scanner := &Network.PortScan{}
	randPort := rand.Intn(65534) + 1 // [1,65536)

	return scanner.ScanPort("tcp", "portquiz.net", randPort)
}

func test() {
	Endpoint.Say("Attempting to contact external resource over random, non-standard port")
	if !nonStandardPort() {
		Endpoint.Say("Error when contacting resource over non-standard port!")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	Endpoint.Say("Connection test successful")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}

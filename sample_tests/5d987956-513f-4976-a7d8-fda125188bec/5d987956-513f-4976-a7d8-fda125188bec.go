//go:build windows
// +build windows

/*
ID: 5d987956-513f-4976-a7d8-fda125188bec
NAME: Remote Services: RDP
TECHNIQUE: T1021.001
UNIT: response
CREATED: 2024-01-04 20:09:07.903984
*/
package main

import (
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

func rdpOut() bool {
	if _, err := Endpoint.Shell([]string{"powershell.exe", "-c", `$mstsc = Start-Process mstsc -ArgumentList '/v:localhost' -PassThru -ea SilentlyContinue; sleep 5; if ($mstsc.Id -and (ps -Id $mstsc.Id -ea SilentlyContinue)) { spps -Id $mstsc.Id -Force }`}); err != nil {
		Endpoint.Say("Got error \"%v\" when issuing RDP connection command", err)
		return false
	}
	return true
}

func test() {
	Endpoint.Say("Attempting to issue RDP connection command")
	if !rdpOut() {
		Endpoint.Say("Error while issuing RDP command, exiting test")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	Endpoint.Say("Successfully issued RDP command, exiting test")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}

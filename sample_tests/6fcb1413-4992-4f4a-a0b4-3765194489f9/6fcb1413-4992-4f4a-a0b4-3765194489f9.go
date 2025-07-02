//go:build windows
// +build windows

/*
ID: 6fcb1413-4992-4f4a-a0b4-3765194489f9
NAME: Cobalt Strike Trojan
TECHNIQUE: T1218
UNIT: response
CREATED: 2023-04-25
*/
package main

import (
	_ "embed"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed cobaltstrike.dll
var malicious []byte

var commands = [][]string{
	{"cmd.exe", "/C", "C:\\Windows\\System32\\rundll32.exe"},
	{"cmd.exe", "/C", "powershell -nop -exec bypass -EncodedCommand dwBoAG8AYQBtAGkA"},
	{"cmd.exe", "/C", "powershell -nop new-object System.IO.Pipes.NamedPipeServerStream 'msagent_f0rtika1337','Out'"},
}

func test() {
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("%v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	Endpoint.Say("Extracting file for quarantine test")
	Endpoint.Say("Pausing for 3 seconds to gauge defensive reaction")
	if Endpoint.Quarantined("cobaltstrike.dll", malicious) {
		Endpoint.Say("Malicious file was caught!")
		Endpoint.Stop(105)
		return
	}

	Endpoint.Say("Malicious file was not caught, continuing with technique execution")

	for _, command := range commands {
		cmd, err := Endpoint.Shell(command)
		if err != nil {
			Endpoint.Say("The test was prevented or machine not vulnerable")
			Endpoint.Stop(107)
		}
		Endpoint.Say(cmd)
	}
	Endpoint.Say("TTPs were able to be executed")
	Endpoint.Stop(101)
}

func main() {
	Endpoint.Start(test)
}

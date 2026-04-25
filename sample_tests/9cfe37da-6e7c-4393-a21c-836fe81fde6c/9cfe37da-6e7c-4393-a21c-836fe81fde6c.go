/*
ID: 9cfe37da-6e7c-4393-a21c-836fe81fde6c
NAME: Web Shell
TECHNIQUE: T1505.003
UNIT: response
CREATED: 2024-01-11 14:28:39.783068
*/
package main

import (
	_ "embed"
	"math/rand"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed shell.asp
var aspShell []byte

//go:embed shell.jsp
var jspShell []byte

//go:embed shell.php
var phpShell []byte

func writeWebShell(ext string) bool {
	filename := "shell." + ext
	Endpoint.Say("Extracting %s web shell with filename %s", ext, filename)
	switch ext {
	case "php":
		return !Endpoint.Quarantined(filename, phpShell)
	case "jsp":
		return !Endpoint.Quarantined(filename, jspShell)
	case "asp":
		return !Endpoint.Quarantined(filename, aspShell)
	}
	Endpoint.Stop(Endpoint.UnexpectedTestError) // in case of emergency stop
	return false                                // trap ret
}

func test() {
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("%v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	Endpoint.Say("Extracting web shell file to test directory")
	exts := []string{"jsp", "asp", "php"}
	if !writeWebShell(exts[rand.Intn(len(exts))]) {
		Endpoint.Say("Web shell was quarantined on extraction")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}
	Endpoint.Say("Successfully extracted web shell file")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}

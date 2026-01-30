//go:build windows
// +build windows

/*
ID: bcba14e7-6f87-4cbd-9c32-718fdeb39b65
NAME: EDRSilencer Detection
TECHNIQUES: T1562.001
TACTICS: defense-evasion
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: edr-evasion
TAGS: edrsilencer, wfp-filter, telemetry-blocking
UNIT: response
CREATED: 2024-10-07
AUTHOR: sectest-builder
*/
package main

import (
	_ "embed"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed EDRSilencer.exe
var malicious []byte

func execute() error {
	// Command to run EDRSilencer to detect EDR processes
	command := []string{
		".\\EDRSilencer.exe", "blockedr",
	}

	// Execute the command
	_, err := Endpoint.Shell(command)
	if err != nil {
		return err
	}

	// Clean up by removing all filters
	cleanupCommand := []string{
		".\\EDRSilencer.exe", "unblockall",
	}

	_, err = Endpoint.Shell(cleanupCommand)
	if err != nil {
		Endpoint.Say("Warning: Failed to clean up WFP filters: %v", err)
		// Continue execution even if cleanup fails
	}

	return nil
}

func test() {
	// Initialize the dropper
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("%v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Extract the EDRSilencer binary and check if it gets quarantined
	Endpoint.Say("Extracting EDRSilencer tool for quarantine test")
	Endpoint.Say("Pausing for 3 seconds to gauge defensive reaction")
	Endpoint.Wait(3)

	if Endpoint.Quarantined("EDRSilencer.exe", malicious) {
		Endpoint.Say("EDRSilencer binary was caught!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	Endpoint.Say("EDRSilencer binary was not caught, attempting execution")

	// Try to execute EDRSilencer
	err := execute()
	if err != nil {
		Endpoint.Say("Got error \"%v\" when executing EDRSilencer", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	Endpoint.Say("EDRSilencer execution was not prevented")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}

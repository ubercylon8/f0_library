/*
ID: 890267cf-d9b0-479a-8084-8a415c21c3b2
NAME: Credentials in Files
TECHNIQUE: T1552.001
UNIT: response
CREATED: 2024-01-11 19:35:17.624777
*/
package main

import (
	"runtime"
	"strings"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

func writeDummy() bool {
	Endpoint.Say("Writing dummy credentials file to disk")
	return !Endpoint.Quarantined("creds.txt", []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'})
}

func credsInFiles(platform string) bool {
	switch platform {
	case "linux", "darwin":
		out, err := Endpoint.Shell([]string{"/bin/bash", "-c", "grep -ri password ./"})
		if err != nil {
			Endpoint.Say("Got error \"%v\" when executing search commands", err)
			return false
		}
		Endpoint.Say(out)
		return true
	case "windows":
		out, err := Endpoint.Shell([]string{"cmd", "/c", "findstr /si password *.xml *.doc *.txt *.xls"})
		if err != nil && !strings.Contains(err.Error(), "status 1") {
			Endpoint.Say("Got error \"%v\" when executing search commands", err)
			return false
		}
		Endpoint.Say(out)
		return true
	}
	return false
}

func test() {
	if !writeDummy() {
		Endpoint.Say("Unable to write dummy file to testing directory")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}
	Endpoint.Say("Wrote dummy credentials file to disk. Performing search")
	if !credsInFiles(runtime.GOOS) {
		Endpoint.Say("Error executing search commands")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Successfully ran search commands")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}

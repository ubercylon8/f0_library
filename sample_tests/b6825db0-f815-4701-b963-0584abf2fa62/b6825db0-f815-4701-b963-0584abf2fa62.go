//go:build !windows
// +build !windows

/*
ID: b6825db0-f815-4701-b963-0584abf2fa62
NAME: Untrusted User Execution
TECHNIQUE: T1059.004
UNIT: response
CREATED: 2023-07-13 18:08:34.011153
*/
package main

import (
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

func getIDs() (uint32, uint32, error) {
	nobody, err := user.Lookup("nobody")
	if err != nil {
		return 0, 0, err
	}

	uid, err := strconv.ParseUint(nobody.Uid, 10, 32)
	if err != nil {
		return 0, 0, err
	}

	gid, err := strconv.ParseUint(nobody.Gid, 10, 32)
	if err != nil {
		return 0, 0, err
	}

	return uint32(uid), uint32(gid), nil
}

func executeCommand(command string) ([]byte, error) {
	nobodyUID, nobodyGID, err := getIDs()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(command)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: nobodyUID,
			Gid: nobodyGID,
		},
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return output, nil
}

func test() {
	Endpoint.Say("Attempting to execute code as the nobody user")
	output, err := executeCommand("whoami")
	if err != nil {
		Endpoint.Say("Endpoint is not vulnerable")
		Endpoint.Stop(107)
		return
	}

	Endpoint.Say("Command executed as:" + string(output))
	Endpoint.Stop(101)

}

func main() {
	Endpoint.Start(test)
}

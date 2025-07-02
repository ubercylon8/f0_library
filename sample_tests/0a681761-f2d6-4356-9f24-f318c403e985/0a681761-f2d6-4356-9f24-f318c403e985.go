//go:build windows
// +build windows

/*
ID: 0a681761-f2d6-4356-9f24-f318c403e985
NAME: Impair Defenses: Indicator Blocking
TECHNIQUE: T1562.006
UNIT: response
CREATED: 2024-01-12 22:15:31.733910+00:00
*/
package main

import (
	"fmt"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

func getSecurityLogPath() (string, error) {
	out, err := Endpoint.Shell([]string{"powershell.exe", "-c", `(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "File").File`})
	if err != nil {
		return "", err
	}
	return out, nil
}

func setSecurityLogPath(key string) error {
	_, err := Endpoint.Shell([]string{"powershell.exe", "-c",
		fmt.Sprintf(`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "File" -Value "%s"`, key)})
	if err != nil {
		return err
	}
	return nil
}

func test() {
	if !Endpoint.CheckAdmin() {
		Endpoint.Say("Test is running with insufficient privileges")
		Endpoint.Stop(Endpoint.InsufficientPrivileges)
	}
	f0rtikaSecLogKey := Endpoint.Pwd("f0rtikaSecLog.evtx")
	Endpoint.Say("Gathering current security log setting")
	currSecLogKey, err := getSecurityLogPath()
	if err != nil {
		Endpoint.Say("Got error \"%v\" when querying registry", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Current Security event log path is: %s", currSecLogKey)
	Endpoint.Say("Changing Security event log path")
	if err := setSecurityLogPath(f0rtikaSecLogKey); err != nil {
		Endpoint.Say("Got error \"%v\" when changing Security event log path", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	newSecLogKey, err := getSecurityLogPath()
	if err != nil {
		Endpoint.Say("Got error \"%v\" when querying registry", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("New Security event log path is: %s", newSecLogKey)
	Endpoint.Say("Successfully changed Security event log path")
	Endpoint.Say("Reverting Security event log path changes")
	if err := setSecurityLogPath(currSecLogKey); err != nil {
		Endpoint.Say("Got error \"%v\" when reverting registry changes", err)
		Endpoint.Stop(Endpoint.CleanupFailed)
	}
	currSecLogKey, err = getSecurityLogPath()
	if err != nil {
		Endpoint.Say("Got error \"%v\" when querying registry", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Security event log path after reversion is: %s", currSecLogKey)
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}

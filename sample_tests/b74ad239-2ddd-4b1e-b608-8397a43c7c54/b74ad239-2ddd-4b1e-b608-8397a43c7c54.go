//go:build windows
// +build windows

/*
ID: b74ad239-2ddd-4b1e-b608-8397a43c7c54
NAME: Malicious Office Document
TECHNIQUE: T1204.002
UNIT: response
CREATED: 2023-01-03
*/
package main

import (
	_ "embed"
	"fmt"
	"strings"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

var (
	ver, origMacroAllow string
)

//go:embed mal.docm
var malicious []byte

func checkAndKillWord() error {
	_, err := Endpoint.Shell([]string{"powershell.exe", "-c", `stop-process -name "WINWORD" -force`})
	return err
}

func getCurrentRegSetting(ver, value string) (string, error) {
	out, err := Endpoint.Shell([]string{"powershell.exe", "-c", fmt.Sprintf(`get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\%s\Word\Security" -Name "%s"`, ver, value)})
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return "", nil
		}
		return "", err
	}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, value) {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				return parts[len(parts)-1], nil
			}
		}
	}
	return out, nil
}

func isWordInstalled() string {
	installPaths := map[string]string{
		`C:\Program Files\Microsoft Office\Office14\WINWORD.EXE`:            "14.0",
		`C:\Program Files (x86)\Microsoft Office\Office14\WINWORD.EXE`:      "14.0",
		`C:\Program Files\Microsoft Office\Office15\WINWORD.EXE`:            "15.0",
		`C:\Program Files (x86)\Microsoft Office\Office15\WINWORD.EXE`:      "15.0",
		`C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`:       "16.0",
		`C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE`: "16.0",
		`C:\Program Files\Microsoft Office\Office16\WINWORD.EXE`:            "16.0",
		`C:\Program Files (x86)\Microsoft Office\Office16\WINWORD.EXE`:      "16.0",
	}

	for path, version := range installPaths {
		if Endpoint.Exists(path) {
			return version
		}
	}

	return ""
}

func removeMacroAllowance(ver string) error {
	_, err := Endpoint.Shell([]string{"powershell.exe", "-c", fmt.Sprintf(`remove-itemproperty -path "Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Microsoft\Office\%s\Word\Security" -name "VBAWarnings"`, ver)})
	return err
}

func setMacroAllowance(ver, desiredSetting string) error {
	_, err := Endpoint.Shell([]string{"powershell.exe", "-c", fmt.Sprintf(`set-itemproperty -path "Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Microsoft\Office\%s\Word\Security" -name "VBAWarnings" -type dword -value "%s" -force`, ver, desiredSetting)}) // allow all macros
	return err
}

func test() {
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("Dropper was quarantined")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	Endpoint.Say("Checking for existence and version of installed Office software")
	if ver = isWordInstalled(); ver == "" {
		Endpoint.Say("Word not found on system, exiting test")
		Endpoint.Stop(Endpoint.NotRelevant)
	}
	Endpoint.Say("Word version %s found", ver)

	Endpoint.Say("Getting macro allowance setting for current user")
	out, err := getCurrentRegSetting(ver, "VBAWarnings")
	if out == "" && err != nil {
		Endpoint.Say("Got error \"%v\" when enumerating local host", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	if out == "" && err == nil {
		Endpoint.Say("Macro allowance setting not found on host. Will set for test.")
	}
	origMacroAllow = out
	Endpoint.Say("Initial macro allowance setting is \"%s\"", out)
	Endpoint.Say("Setting macro allowance setting")
	err = setMacroAllowance(ver, "1")
	if err != nil {
		Endpoint.Say("Got error \"%v\" when setting macro allowance in registry", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Successfully set macro allowance in registry")
	currSetting, err := getCurrentRegSetting(ver, "VBAWarnings")
	if err != nil {
		Endpoint.Say("Got error \"%v\" when performing secondary enumeration", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented) // might be heuristics-based execution prevented
	}
	Endpoint.Say("Current macro allowance setting is \"%s\"", currSetting)

	Endpoint.Say("Writing maldoc to testing directory")
	if Endpoint.Quarantined("mal.docm", malicious) {
		Endpoint.Say("Maldoc was quarantined")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}
	Endpoint.Say("Successfully wrote maldoc to testing directory")
	Endpoint.Say("Opening maldoc")
	_, err = Endpoint.Shell([]string{"cmd.exe", "/c", "start", `.\mal.docm`})
	Endpoint.Wait(1)
	if err != nil {
		Endpoint.Say("Got error \"%v\" when opening maldoc", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	if !Endpoint.Exists(`.\f0rtika.txt`) {
		Endpoint.Say("Didn't find IoC text file")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say("Found IoC text file")
	Endpoint.Say("Attempting to kill WINWORD.exe")
	err = checkAndKillWord()
	if err != nil {
		Endpoint.Say("Got error \"%v\" when attempting to kill WINWORD process", err)
	}
	Endpoint.Stop(Endpoint.Unprotected)
}

func clean() {
	var err error
	Endpoint.Say("Cleaning up")
	if origMacroAllow != "" {
		err = setMacroAllowance(ver, origMacroAllow)
	} else {
		err = removeMacroAllowance(ver)
	}
	if err != nil {
		Endpoint.Say("Got error \"%v\" when reverting macro allowance settings", err)
		Endpoint.Stop(Endpoint.CleanupFailed)
	}
	Endpoint.Say("Reversion successful")
	return
}

func main() {
	Endpoint.Start(test, clean)
}

//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

const (
	TEST_UUID      = "8f68dda1-94be-430f-8f35-d8af3f9b5d2e"
	TECHNIQUE_ID   = "T1003.001"
	TECHNIQUE_NAME = "LSASS Open/Read Access Attempt"
	STAGE_ID       = 4
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)
	code := performLSASSAccess()
	switch code {
	case StageSuccess:
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "LSASS PROCESS_VM_READ handle granted and closed without reading memory")
	case StageBlocked:
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Elevated LSASS access denied after SeDebugPrivilege was enabled")
	default:
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "LSASS access result not attributable to protection")
	}
	os.Exit(code)
}

func performLSASSAccess() int {
	elevated := isAdmin() || isSystemContext()
	privilegeErr := enablePrivilege("SeDebugPrivilege")
	if privilegeErr != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("SeDebugPrivilege enable returned: %v; a later denial is baseline/inconclusive", privilegeErr))
	}
	pid, err := findProcessByName("lsass.exe")
	if err != nil || pid == 0 {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("LSASS process discovery returned pid=%d error=%v", pid, err))
		return StageError
	}
	access := uint32(windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION)
	handle, openErr := windows.OpenProcess(access, false, pid)
	if openErr == nil {
		windows.CloseHandle(handle)
		LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION) granted for LSASS PID %d; handle closed without ReadProcessMemory or dump", pid))
		return StageSuccess
	}
	if errnoIs(openErr, windows.ERROR_ACCESS_DENIED) && elevated && privilegeErr == nil {
		LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("LSASS OpenProcess returned ERROR_ACCESS_DENIED in elevated SeDebug context for PID %d", pid))
		return StageBlocked
	}
	LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("LSASS OpenProcess returned inconclusive error in elevated=%v SeDebug=%v context: %v", elevated, privilegeErr == nil, openErr))
	return StageError
}

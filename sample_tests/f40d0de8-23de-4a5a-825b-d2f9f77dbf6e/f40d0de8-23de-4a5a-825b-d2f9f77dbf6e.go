//go:build windows
// +build windows

/*
ID: f40d0de8-23de-4a5a-825b-d2f9f77dbf6e
NAME: Spoof Parent Process ID
TECHNIQUE: T1134.004
UNIT: response
CREATED: 2024-07-01 17:35:27.694781+00:00
*/
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

type STARTUPINFOEX struct {
	STARTUPINFO     syscall.StartupInfo
	LpAttributeList *byte
}

var (
	// modules
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	pCreateProcessW               = kernel32.NewProc("CreateProcessW")
	pCreateToolhelp32Snapshot     = kernel32.NewProc("CreateToolhelp32Snapshot")
	pInitializeProcThreadAttrList = kernel32.NewProc("InitializeProcThreadAttributeList")
	pOpenProcess                  = kernel32.NewProc("OpenProcess")
	pProcess32First               = kernel32.NewProc("Process32FirstW")
	pProcess32Next                = kernel32.NewProc("Process32NextW")
	pUpdateProcThreadAttribute    = kernel32.NewProc("UpdateProcThreadAttribute")
)

const (
	EXTENDED_STARTUP_PRESENT             = 0x00080000
	PROCESS_CREATE_PROCESS               = 0x0080
	PROCESS_DUP_HANDLE                   = 0x0040
	PROCESS_QUERY_INFORMATION            = 0x0400
	PROCESS_TERMINATE                    = 0x0001
	SYNCHRONIZE                          = 0x00100000
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
)

func initializeProcThreadAttributeList(lpAttrList *byte, dwAttrCount uint32, dwFlags uint32, lpSize *uintptr) bool {
	ret, _, err := pInitializeProcThreadAttrList.Call(
		uintptr(unsafe.Pointer(lpAttrList)),
		uintptr(dwAttrCount),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(lpSize)),
	)
	if err != nil && err != syscall.Errno(122) && err != syscall.Errno(0) {
		Endpoint.Say(fmt.Sprintf("Got error %s when initializing proc thread attribute list, extiting test", err.Error()))
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	} // neither ERR_INSUFFICIENT_BUFFER nor SUCCESS
	return ret == 0 // zero retval is error, should return > 0
}

func openParentHandle(dwPid uint32) (uintptr, error) {
	hParentHandle, _, err := pOpenProcess.Call(
		uintptr(PROCESS_CREATE_PROCESS|PROCESS_QUERY_INFORMATION|PROCESS_DUP_HANDLE|PROCESS_TERMINATE|SYNCHRONIZE),
		uintptr(0),
		uintptr(dwPid),
	)
	if err != nil && err != syscall.Errno(0) {
		return 0, err
	}
	return hParentHandle, nil
}

func updateProcThreadAttribute(lpAttributeList *byte, dwFlags uint32, attribute uintptr, lpVal *uintptr, cbSize uintptr, lpPreviousValue *uintptr, lpReturnSize *uintptr) bool {
	ret, _, _ := pUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(lpAttributeList)),
		uintptr(dwFlags),
		attribute,
		uintptr(unsafe.Pointer(lpVal)),
		cbSize,
		uintptr(unsafe.Pointer(lpPreviousValue)),
		uintptr(unsafe.Pointer(lpReturnSize)),
	)
	return ret == 0 // zero retval is error
}

func test() {
	Endpoint.Say(fmt.Sprintf("Creating new child process with spoofed parent process ID"))
	parentPinfo := syscall.ProcessInformation{}
	parentSinfo := syscall.StartupInfo{}
	_, _, err := pCreateProcessW.Call(
		0,
		uintptr(unsafe.Pointer(
			syscall.StringToUTF16Ptr("c:\\windows\\system32\\dllhost.exe"))),
		0,
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&parentSinfo)),
		uintptr(unsafe.Pointer(&parentPinfo)),
	)
	if err != nil && err != syscall.Errno(0) {
		Endpoint.Say(fmt.Sprintf("Got error \"%s\" when creating parent process", err.Error()))
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	hParentProc, err := openParentHandle(parentPinfo.ProcessId)
	Endpoint.Say(fmt.Sprintf("Created parent process with PID %d", parentPinfo.ProcessId))
	if err != nil && err != syscall.Errno(0) {
		Endpoint.Say(fmt.Sprintf("Got error \"%s\" when opening handle to parent process", err.Error()))
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	defer syscall.CloseHandle(syscall.Handle(hParentProc))
	Endpoint.Say(fmt.Sprintf("Got parent process handle %d", hParentProc))

	sInfoEx := STARTUPINFOEX{}
	sInfoEx.STARTUPINFO.Cb = uint32(unsafe.Sizeof(sInfoEx))
	pInfo := syscall.ProcessInformation{}
	var lpProcThreadAttrListSize uintptr

	Endpoint.Say(fmt.Sprintf("Initializing process thread attribute list"))
	if !initializeProcThreadAttributeList(
		nil,
		1,
		0,
		&lpProcThreadAttrListSize) {
		Endpoint.Say(fmt.Sprintf("Got error when sizing proc thread attribute list, exiting test"))
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	pProcThreadAttrList := make([]byte, lpProcThreadAttrListSize)
	if initializeProcThreadAttributeList(
		&pProcThreadAttrList[0],
		1,
		0,
		&lpProcThreadAttrListSize) {
		Endpoint.Say(fmt.Sprintf("Got error when initializing proc thread attribute list, exiting test"))
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say(fmt.Sprintf("Successfully initialized process thread attribute list"))

	Endpoint.Say(fmt.Sprintf("Updating attribute list"))
	if updateProcThreadAttribute( // remember, 0 retval is error
		&pProcThreadAttrList[0],
		0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		&hParentProc,
		unsafe.Sizeof(hParentProc),
		nil,
		nil,
	) {
		Endpoint.Say(fmt.Sprintf("Got error when updating process thread attributes"))
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}
	Endpoint.Say(fmt.Sprintf("Updated proc thread attribute list"))

	sInfoEx.LpAttributeList = &pProcThreadAttrList[0]
	szCommandLine := "C:\\Windows\\System32\\RuntimeBroker.exe -f0rtikaSecurity"
	Endpoint.Say(fmt.Sprintf("Creating child process with commandline \"%s\" and spoofed parent PID %d", szCommandLine, parentPinfo.ProcessId))

	_, _, err = pCreateProcessW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(szCommandLine))),
		0,
		0,
		0,
		EXTENDED_STARTUP_PRESENT,
		0,
		0,
		uintptr(unsafe.Pointer(&sInfoEx.STARTUPINFO)),
		uintptr(unsafe.Pointer(&pInfo)),
	)
	if err != nil && err != syscall.Errno(0) {
		Endpoint.Say(fmt.Sprintf("Got error %s when creating process, exiting test", err.Error()))
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	Endpoint.Say(fmt.Sprintf("Successfully created child process with PID %d", pInfo.ProcessId))
	Endpoint.Say(fmt.Sprintf("Waiting 5 seconds before terminating parent and child processes"))
	Endpoint.Wait(5)
	Endpoint.Say(fmt.Sprintf("Terminating parent process"))
	syscall.TerminateProcess(parentPinfo.Process, 1)
	Endpoint.Say(fmt.Sprintf("Terminated parent process"))
	Endpoint.Say(fmt.Sprintf("Terminating child process"))
	syscall.TerminateProcess(pInfo.Process, 1)
	Endpoint.Say(fmt.Sprintf("Terminated child process"))
	Endpoint.Say(fmt.Sprintf("Successfully spoofed parent process information in child process"))
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}

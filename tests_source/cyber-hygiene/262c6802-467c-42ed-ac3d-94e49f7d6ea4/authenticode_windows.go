//go:build windows

package main

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          windows.Handle
	pgKnownSubject *windows.GUID
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               *wintrustFileInfo
	dwStateAction       uint32
	hWVTStateData       windows.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

var (
	wintrustActionGenericVerifyV2 = windows.GUID{Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11D0, Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}}
	wintrustDLL                   = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust            = wintrustDLL.NewProc("WinVerifyTrust")
)

func probeAuthenticode(path, caseName string) probeResult {
	probe := probeResult{Runtime: "authenticode", Case: caseName, Status: probeError}
	filePath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		probe.Evidence = fmt.Sprintf("file path could not be encoded: %v", err)
		return probe
	}
	fileInfo := wintrustFileInfo{pcwszFilePath: filePath}
	fileInfo.cbStruct = uint32(unsafe.Sizeof(fileInfo))
	data := wintrustData{
		dwUIChoice:          2,
		fdwRevocationChecks: 0,
		dwUnionChoice:       1,
		pFile:               &fileInfo,
		dwStateAction:       1,
	}
	data.cbStruct = uint32(unsafe.Sizeof(data))
	result, _, _ := procWinVerifyTrust.Call(^uintptr(0), uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)), uintptr(unsafe.Pointer(&data)))
	status := uint32(result)
	data.dwStateAction = 2
	_, _, _ = procWinVerifyTrust.Call(^uintptr(0), uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)), uintptr(unsafe.Pointer(&data)))
	runtime.KeepAlive(filePath)
	runtime.KeepAlive(fileInfo)
	runtime.KeepAlive(data)

	probe.Evidence = fmt.Sprintf("WinVerifyTrust WTD_REVOKE_NONE returned HRESULT 0x%08X", status)
	if status == 0 {
		probe.Status = probeAccepted
		return probe
	}
	switch status {
	case 0x800B0111, 0x800B0004, 0x800B0109, 0x800B010A, 0x800B010C, 0x80092010:
		probe.Status = probeRejected
	default:
		probe.Status = probeError
	}
	LogMessage("INFO", "Authenticode", caseName+": "+probe.Evidence)
	return probe
}

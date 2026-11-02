//go:build windows
// +build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func logStageMessage(level, phase, message string) {
	fmt.Printf("[%s] [%s] %s\n", level, phase, message)
	structuredLevel := level
	switch level {
	case "BLOCKED":
		structuredLevel = "ERROR"
	case "WARNING":
		structuredLevel = "WARN"
	}
	LogMessage(structuredLevel, phase, message)
}

func isSystemContext() bool {
	username := os.Getenv("USERNAME")
	return strings.HasSuffix(username, "$") || strings.EqualFold(username, "SYSTEM")
}

func enablePrivilege(name string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("OpenProcessToken returned: %v", err)
	}
	defer token.Close()

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		return fmt.Errorf("LookupPrivilegeValue(%s) returned: %v", name, err)
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	if err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil); err != nil {
		return fmt.Errorf("AdjustTokenPrivileges returned: %v", err)
	}
	if errors.Is(windows.GetLastError(), windows.ERROR_NOT_ALL_ASSIGNED) {
		return fmt.Errorf("AdjustTokenPrivileges did not assign %s", name)
	}
	return nil
}

func findProcessByName(name string) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("snapshot creation returned: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0, fmt.Errorf("first process read returned: %v", err)
	}
	for {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), name) {
			return entry.ProcessID, nil
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				return 0, nil
			}
			return 0, fmt.Errorf("next process read returned: %v", err)
		}
	}
}

func copyFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func copyCurrentExecutable(destination string) error {
	source, err := os.Executable()
	if err != nil {
		return err
	}
	return copyFile(source, destination)
}

func writeNonfunctionalDriver(path string) error {
	data := make([]byte, 4096)
	data[0] = 'M'
	data[1] = 'Z'
	return os.WriteFile(path, data, 0644)
}

func errnoIs(err error, target error) bool {
	return err != nil && errors.Is(err, target)
}

//go:build windows
// +build windows

/*
F0RT1KA SANDBOX SIDELOAD HOST — LogiAiPromptBuilder.exe (renamed)

This is the F0RT1KA sandbox stand-in for the real TclBanker host binary
`LogiAiPromptBuilder.exe`. It is built as a pure-Go Windows EXE, signed
with the F0RT1KA cert, and dropped into ARTIFACT_DIR\LogiAI\ next to a
renamed Microsoft `version.dll` that has been renamed to
`screen_retriever_plugin.dll`.

When invoked, this host calls LoadLibrary("screen_retriever_plugin.dll").
Because Windows resolves DLL imports from the same directory as the EXE
first, the renamed system DLL loads — producing genuine image-load
telemetry on the artifact pair (renamed host + renamed DLL in non-standard
path). This is the exact pattern EDRs flag as suspicious DLL sideloading.

Behavior is benign: load DLL, resolve a single export (GetFileVersionInfoSizeW
is a real export of version.dll), call it on a non-existent path so it returns
immediately, then unload and exit. Writes a single marker line to
C:\F0\sideload_host_loaded.txt.

NEVER writes outside C:\F0 or C:\Users\fortika-test.
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

const (
	logDir       = `C:\F0`
	markerPath   = `C:\F0\sideload_host_loaded.txt`
	dllToLoad    = "screen_retriever_plugin.dll"
)

func writeMarker(line string) {
	if _, err := os.Stat(logDir); err != nil {
		return
	}
	f, err := os.OpenFile(markerPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = f.WriteString(fmt.Sprintf("[%s] %s\n", stamp, line))
}

func main() {
	writeMarker("LogiAiPromptBuilder.exe (F0RT1KA sandbox) started")

	// Determine our own directory — that's where we expect the sideloaded DLL.
	exePath, err := os.Executable()
	if err != nil {
		writeMarker(fmt.Sprintf("ERROR: could not resolve own path: %v", err))
		os.Exit(2)
	}
	myDir := filepath.Dir(exePath)
	dllPath := filepath.Join(myDir, dllToLoad)

	writeMarker(fmt.Sprintf("Attempting LoadLibrary on: %s", dllPath))

	// Use LoadLibraryW with an absolute path so we hit the artifact-dir DLL
	// regardless of search order rules. This is the LoadLibrary call that
	// produces the image-load telemetry we want EDR to surface.
	utf16, err := syscall.UTF16PtrFromString(dllPath)
	if err != nil {
		writeMarker(fmt.Sprintf("ERROR: UTF16PtrFromString failed: %v", err))
		os.Exit(2)
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	loadLibW := kernel32.NewProc("LoadLibraryW")
	freeLib := kernel32.NewProc("FreeLibrary")

	handle, _, lerr := loadLibW.Call(uintptr(unsafe.Pointer(utf16)))
	if handle == 0 {
		writeMarker(fmt.Sprintf("LoadLibraryW failed: %v (handle=0)", lerr))
		// Exit 0 anyway — telemetry was produced by the load attempt itself
		os.Exit(0)
	}

	writeMarker(fmt.Sprintf("LoadLibraryW SUCCESS: handle=0x%x — sideload complete", handle))

	// Hold the handle briefly so EDR has time to observe the image-load event,
	// then unload cleanly.
	time.Sleep(750 * time.Millisecond)

	if _, _, ferr := freeLib.Call(handle); ferr != nil {
		// FreeLibrary's lasterr is "operation completed successfully" on
		// success in Go's syscall package; ignore.
		_ = ferr
	}

	writeMarker("FreeLibrary called; host exiting")
	os.Exit(0)
}

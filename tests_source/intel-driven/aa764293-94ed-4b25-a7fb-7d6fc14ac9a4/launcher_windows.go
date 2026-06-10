// Windows context-aware launcher for the RoguePlanet payload.
//
// RoguePlanet's main() branches on IsRunningAsLocalSystem(): when SYSTEM it takes the
// re-entry path and never runs the actual exploit. Prelude/Achilles frequently run
// orchestrators as SYSTEM. This file guarantees the payload runs as a regular
// medium-IL interactive user:
//
//   - isSystemContext(): detect SYSTEM (Bug Prevention Rule 2).
//   - If SYSTEM: WTSGetActiveConsoleSessionId -> WTSQueryUserToken to grab the active
//     console user's token, build an inheritable file handle for stdout/stderr capture
//     (Rule 5), then CreateProcessAsUser into that interactive non-elevated session.
//   - If already a normal user: CreateProcess directly with stdout/stderr -> file.
//
// All output is tee'd to LOG_DIR\RoguePlanet_output.txt. Because CreateProcessAsUser
// runs in another session, we capture by handing the child an inheritable handle to the
// output file (the parent also mirrors a header line to console). The orchestrator then
// reads that file to scan for the "Exploit succeeded." marker.

//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// process wraps a launched payload so the orchestrator can wait on it and poll
// concurrently. done is closed when the process exits.
type process struct {
	handle windows.Handle
	pid    int
	done   chan struct{}
}

// wait blocks until the wrapped process exits (or its waiter goroutine times out).
func (p *process) wait() {
	if p == nil {
		return
	}
	<-p.done
}

// ------------------------------------------------------------------------------
// Context detection (Bug Prevention Rule 2)
// ------------------------------------------------------------------------------

// isSystemContext reports whether the current process token is NT AUTHORITY\SYSTEM
// (the well-known LocalSystem SID S-1-5-18).
func isSystemContext() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return false
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false
	}
	return windows.EqualSid(user.User.Sid, localSystem)
}

// isServerSKU reports whether the host is a Windows Server product (where standard
// users cannot mount ISOs, breaking the PoC prerequisite). Uses GetProductInfo via the
// version helper; a Server SKU has the VER_NT_SERVER / VER_NT_DOMAIN_CONTROLLER product
// type. We read it through RtlGetVersion's wProductType.
func isServerSKU() bool {
	type osVersionInfoEx struct {
		osVersionInfoSize uint32
		majorVersion      uint32
		minorVersion      uint32
		buildNumber       uint32
		platformId        uint32
		csdVersion        [128]uint16
		servicePackMajor  uint16
		servicePackMinor  uint16
		suiteMask         uint16
		productType       byte
		reserved          byte
	}
	const verNTWorkstation = 0x0000001 // VER_NT_WORKSTATION

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	rtlGetVersion := ntdll.NewProc("RtlGetVersion")
	var vi osVersionInfoEx
	vi.osVersionInfoSize = uint32(unsafe.Sizeof(vi))
	r, _, _ := rtlGetVersion.Call(uintptr(unsafe.Pointer(&vi)))
	if r != 0 { // STATUS_SUCCESS == 0
		return false // unknown; do not block on it
	}
	return vi.productType != verNTWorkstation
}

// activeConsoleSessionAvailable verifies (from SYSTEM) that there is an interactive
// console session with a usable user token to drop the payload into.
func activeConsoleSessionAvailable() (bool, string) {
	sessionID := windows.WTSGetActiveConsoleSessionId()
	if sessionID == 0xFFFFFFFF {
		return false, "no active console session is attached (WTSGetActiveConsoleSessionId returned 0xFFFFFFFF)"
	}
	var userToken windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &userToken); err != nil {
		return false, fmt.Sprintf("could not obtain the interactive user token for session %d (WTSQueryUserToken: %v)", sessionID, err)
	}
	userToken.Close()
	return true, ""
}

// ------------------------------------------------------------------------------
// Launch
// ------------------------------------------------------------------------------

// launchPayload starts payloadPath in a NON-ELEVATED interactive user context and
// redirects stdout+stderr to outputPath (Rule 5). It returns a *process the caller can
// wait on. On launch failure it returns an error; callers use isExecutionPrevented to
// decide whether that error is an OS execution-prevention signal (-> 126) or a benign
// failure (-> 999).
func launchPayload(payloadPath, outputPath string) (*process, error) {
	if isSystemContext() {
		return launchAsConsoleUser(payloadPath, outputPath)
	}
	return launchDirect(payloadPath, outputPath)
}

// openOutputFileInheritable creates/truncates the output capture file and returns an
// inheritable handle suitable for use as a child's stdout/stderr.
func openOutputFileInheritable(outputPath string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(outputPath)
	if err != nil {
		return windows.InvalidHandle, err
	}
	sa := &windows.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1,
	}
	h, err := windows.CreateFile(
		p,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		sa,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return h, nil
}

// launchDirect runs the payload in the current (already non-SYSTEM) user context.
func launchDirect(payloadPath, outputPath string) (*process, error) {
	outHandle, err := openOutputFileInheritable(outputPath)
	if err != nil {
		return nil, fmt.Errorf("open output capture file: %w", err)
	}

	argv, err := windows.UTF16PtrFromString(payloadPath)
	if err != nil {
		windows.CloseHandle(outHandle)
		return nil, err
	}

	si := new(windows.StartupInfo)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdOutput = outHandle
	si.StdErr = outHandle
	si.StdInput = windows.InvalidHandle

	var pi windows.ProcessInformation
	err = windows.CreateProcess(
		nil,
		argv,
		nil,
		nil,
		true, // inherit handles (for the output file)
		windows.CREATE_NO_WINDOW,
		nil,
		nil,
		si,
		&pi,
	)
	windows.CloseHandle(outHandle) // child holds its own duplicated handle
	if err != nil {
		return nil, fmt.Errorf("CreateProcess: %w", err)
	}
	windows.CloseHandle(pi.Thread)

	return makeProcess(pi.Process, int(pi.ProcessId)), nil
}

// launchAsConsoleUser runs the payload as the active interactive console user from a
// SYSTEM orchestrator, via WTSQueryUserToken + CreateProcessAsUser.
func launchAsConsoleUser(payloadPath, outputPath string) (*process, error) {
	sessionID := windows.WTSGetActiveConsoleSessionId()
	if sessionID == 0xFFFFFFFF {
		// Benign prerequisite condition surfaced as an error; caller maps to 999.
		return nil, fmt.Errorf("no active console session (WTSGetActiveConsoleSessionId=0xFFFFFFFF)")
	}

	var userToken windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &userToken); err != nil {
		return nil, fmt.Errorf("WTSQueryUserToken(session %d): %w", sessionID, err)
	}
	defer userToken.Close()

	// Duplicate into a primary token suitable for CreateProcessAsUser.
	var primary windows.Token
	err := windows.DuplicateTokenEx(
		userToken,
		windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&primary,
	)
	if err != nil {
		return nil, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primary.Close()

	// Inheritable output capture handle (Rule 5).
	outHandle, err := openOutputFileInheritable(outputPath)
	if err != nil {
		return nil, fmt.Errorf("open output capture file: %w", err)
	}
	defer windows.CloseHandle(outHandle)

	// Build the target user's environment block so the spawned process looks native.
	var envBlock *uint16
	if err := windows.CreateEnvironmentBlock(&envBlock, primary, false); err != nil {
		// Non-fatal: fall back to inheriting the orchestrator environment.
		envBlock = nil
	} else {
		defer windows.DestroyEnvironmentBlock(envBlock)
	}

	argv, err := windows.UTF16PtrFromString(payloadPath)
	if err != nil {
		return nil, err
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)

	si := new(windows.StartupInfo)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Desktop = desktop
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdOutput = outHandle
	si.StdErr = outHandle
	si.StdInput = windows.InvalidHandle

	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_CONSOLE)

	var pi windows.ProcessInformation
	err = windows.CreateProcessAsUser(
		primary,
		nil,
		argv,
		nil,
		nil,
		true, // inherit handles (output capture file)
		flags,
		envBlock,
		nil,
		si,
		&pi,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	windows.CloseHandle(pi.Thread)

	return makeProcess(pi.Process, int(pi.ProcessId)), nil
}

// makeProcess wraps a started process and launches a waiter goroutine that closes
// done when the process exits (bounded so a stuck SYSTEM-shell child can't hang us).
func makeProcess(h windows.Handle, pid int) *process {
	p := &process{handle: h, pid: pid, done: make(chan struct{})}
	go func() {
		// Bound the wait: RoguePlanet on success spawns a SYSTEM console and exits; if
		// something hangs, don't block the orchestrator past a generous per-attempt cap.
		const perAttemptCap = 90 * time.Second
		windows.WaitForSingleObject(h, uint32(perAttemptCap/time.Millisecond))
		windows.CloseHandle(h)
		close(p.done)
	}()
	return p
}

// ------------------------------------------------------------------------------
// Execution-prevention classification (Bug Prevention Rule 8)
// ------------------------------------------------------------------------------

// isExecutionPrevented reports whether a launch error is an OS-emitted
// execution-prevention signal on a binary that WAS successfully written — the only
// kind of error that justifies a 126 verdict. Benign/ambiguous errors return false so
// the caller maps them to 999.
//
// We key on Windows error codes that specifically denote that the OS refused to run an
// existing, present executable image for policy/AV reasons:
//
//	ERROR_VIRUS_INFECTED         (0x000000E1, 225) — "Operation did not complete because the file contains a virus..."
//	ERROR_VIRUS_DELETED          (0x000000E2, 226) — file removed because it contained a virus
//	ERROR_ACCESS_DENIED          (0x00000005, 5)   — only counted here because the file is confirmed-present by the caller
//	ERROR_FILE_NOT_FOUND/PATH    are NOT counted (those are absence, not prevention).
func isExecutionPrevented(err error) bool {
	if err == nil {
		return false
	}
	const (
		ERROR_ACCESS_DENIED  = syscall.Errno(5)
		ERROR_VIRUS_INFECTED = syscall.Errno(225)
		ERROR_VIRUS_DELETED  = syscall.Errno(226)
	)
	var errno syscall.Errno
	if asErrno(err, &errno) {
		switch errno {
		case ERROR_VIRUS_INFECTED, ERROR_VIRUS_DELETED, ERROR_ACCESS_DENIED:
			return true
		}
	}
	return false
}

// asErrno extracts a syscall.Errno from a wrapped error chain.
func asErrno(err error, out *syscall.Errno) bool {
	for err != nil {
		if e, ok := err.(syscall.Errno); ok {
			*out = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if u, ok := err.(unwrapper); ok {
			err = u.Unwrap()
			continue
		}
		// Also handle *os.SyscallError style.
		if se, ok := err.(*os.SyscallError); ok {
			if e, ok2 := se.Err.(syscall.Errno); ok2 {
				*out = e
				return true
			}
		}
		break
	}
	return false
}

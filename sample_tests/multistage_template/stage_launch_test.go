package main

// Run from this directory: go test stage_launch.go stage_launch_test.go
// (explicit file list, like build_all.sh, so the template's other files and
// their Windows-only imports stay out of the build).

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLaunchErrnoCodeWindowsProtectionErrors(t *testing.T) {
	for _, errno := range []syscall.Errno{5, 225, 226, 1260, 4551} {
		code, why := launchErrnoCode("windows", errno)
		if code != 126 {
			t.Errorf("errno %d: got %d, want 126", errno, code)
		}
		if why == "" {
			t.Errorf("errno %d: missing reason", errno)
		}
	}
}

func TestLaunchErrnoCodeUnrelatedWindowsErrorIsError(t *testing.T) {
	// ERROR_FILE_NOT_FOUND / ERROR_BAD_EXE_FORMAT say nothing about protection.
	for _, errno := range []syscall.Errno{2, 193} {
		if code, _ := launchErrnoCode("windows", errno); code != 999 {
			t.Errorf("errno %d: got %d, want 999", errno, code)
		}
	}
}

func TestLaunchErrnoCodeNonWindowsNeverBlocks(t *testing.T) {
	// EACCES on Linux/macOS is usually a noexec mount, not a protection product.
	for _, goos := range []string{"linux", "darwin"} {
		for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EPERM, 5} {
			if code, _ := launchErrnoCode(goos, errno); code != 999 {
				t.Errorf("%s errno %d: got %d, want 999", goos, errno, code)
			}
		}
	}
}

func TestClassifyStageLaunchErrorVanishedBinaryIsQuarantine(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "stage.exe")
	code, why := classifyStageLaunchError(errors.New("launch failed"), missing)
	if code != 105 || why == "" {
		t.Fatalf("got %d %q, want 105 with a reason", code, why)
	}
}

func TestClassifyStageLaunchErrorWrappedErrno(t *testing.T) {
	present := filepath.Join(t.TempDir(), "stage.exe")
	if err := os.WriteFile(present, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// exec wraps the CreateProcess errno in *fs.PathError; errors.As must reach it.
	err := fmt.Errorf("start: %w", &os.PathError{Op: "fork/exec", Path: present, Err: syscall.Errno(225)})
	code, _ := classifyStageLaunchError(err, present)
	want := 999
	if launchGOOS == "windows" {
		want = 126
	}
	if code != want {
		t.Fatalf("got %d, want %d", code, want)
	}
}

func TestClassifyStageLaunchErrorExitErrorIsNotALaunchFailure(t *testing.T) {
	present := filepath.Join(t.TempDir(), "stage.exe")
	if err := os.WriteFile(present, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A process that ran and exited non-zero is the caller's business, never 126.
	if code, _ := classifyStageLaunchError(&exec.ExitError{}, present); code != 999 {
		t.Fatalf("got %d, want 999", code)
	}
}

func TestClassifyStageLaunchErrorTextIsIgnored(t *testing.T) {
	present := filepath.Join(t.TempDir(), "stage.exe")
	if err := os.WriteFile(present, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Rule 8: words like "access denied" in a message are never evidence.
	if code, _ := classifyStageLaunchError(errors.New("Access is denied. Acceso denegado."), present); code != 999 {
		t.Fatalf("got %d, want 999", code)
	}
}

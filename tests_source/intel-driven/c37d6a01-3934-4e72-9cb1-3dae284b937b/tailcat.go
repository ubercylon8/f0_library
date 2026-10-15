// tailcat.go — shared helpers for the Kothamine tailcat stages (1-3).
//
// Compiled into every stage binary (see STAGE_SHARED in build_all.sh). Provides:
//   - pinned tailcat v0.7.0 release asset URLs + SHA256 checksums
//     (resolved from https://api.github.com/repos/tailscale/tailcat/releases/latest
//     at authoring time, 2026-10-14)
//   - tailcat binary path helpers (stages 2-3 locate the binary stage 1 dropped)
//   - child-process execution with io.MultiWriter stdout/stderr capture to
//     LOG_DIR/<name>_output.txt (CLAUDE.md mandatory capture pattern)
//   - tailcat server lifecycle: start, parse the ephemeral address from stderr,
//     and a guaranteed kill (the no-auth-ssh server is an unauthenticated shell —
//     its lifetime must be seconds and it must die even on panic)
//   - exit-code classification helpers that NEVER default to a block code
//     (CLAUDE.md Bug Prevention Rules 1 and 8)
//
// No build tag: all logic is portable; platform differences resolve via
// runtime.GOOS at run time.

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Stage exit codes (per sample_tests/multistage_template contract).
const (
	StageSuccess     = 0   // technique executed unimpeded
	StageBlocked     = 126 // positive evidence of a protection action
	StageQuarantined = 105 // file quarantined on extraction
	StageQuarantinedOnExec = 127 // file quarantined during execution
	StageError       = 999 // prerequisite not met / ambiguous failure
)

// tailcat release pinning. Kothamine variants fetch tailcat/Tailscale
// components from the official GitHub releases at runtime; this test does the
// same from the pinned v0.7.0 release (2026-09-19).
const TailcatVersion = "0.7.0"

type tailcatAsset struct {
	URL    string
	SHA256 string
}

var tailcatAssets = map[string]tailcatAsset{
	"windows/amd64": {
		URL:    "https://github.com/tailscale/tailcat/releases/download/v0.7.0/tailcat_0.7.0_windows_amd64.zip",
		SHA256: "f04cac07e3bf6c700b0b543df0d3315a3b312cd5a05ee76714e1cc848e9b2dff",
	},
	"windows/arm64": {
		URL:    "https://github.com/tailscale/tailcat/releases/download/v0.7.0/tailcat_0.7.0_windows_arm64.zip",
		SHA256: "1c2d081375ade2365402f9fcf611e89dbb2c5c5ee06936aaff2b205dbe427578",
	},
	"linux/amd64": {
		URL:    "https://github.com/tailscale/tailcat/releases/download/v0.7.0/tailcat_0.7.0_linux_amd64.tar.gz",
		SHA256: "23c0b1887a5ec422f0d18a9c52b4f5357815febdaae738a1eb54036d10bd9ee6",
	},
	"linux/arm64": {
		URL:    "https://github.com/tailscale/tailcat/releases/download/v0.7.0/tailcat_0.7.0_linux_arm64.tar.gz",
		SHA256: "bbb1ab50f24f00effe1e1fd86d0501803fb80793a90785a2a16ff3428f03d8ef",
	},
}

// tailcatAssetForPlatform returns the pinned asset for the run-time platform.
func tailcatAssetForPlatform() (tailcatAsset, error) {
	key := runtime.GOOS + "/" + runtime.GOARCH
	asset, ok := tailcatAssets[key]
	if !ok {
		return tailcatAsset{}, fmt.Errorf("no pinned tailcat asset for platform %s", key)
	}
	return asset, nil
}

// tailcatBinaryName is the on-disk filename of the extracted tailcat binary.
func tailcatBinaryName() string {
	if runtime.GOOS == "windows" {
		return "tailcat.exe"
	}
	return "tailcat"
}

// tailcatPath is where Stage 1 drops the binary and Stages 2-3 find it.
func tailcatPath() string {
	return filepath.Join(LOG_DIR, tailcatBinaryName())
}

// tailcatAddrRe matches an ephemeral tailcat address on a server's stderr
// ("Server listening with new address: tc..."). Addresses are "tc" + base64url.
var tailcatAddrRe = regexp.MustCompile(`tc[A-Za-z0-9_-]{30,}`)

// sha256File returns the hex SHA256 of a file.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %v", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to read %s: %v", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sha256Bytes returns the hex SHA256 of a byte slice.
func sha256Bytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// classifyExecError maps a process start/run failure to an exit code. Only an
// OS-emitted denial on an operation that normally succeeds is positive block
// evidence (126). Everything else is an inconclusive test error (999) —
// Bug Prevention Rule 8: absence of success is NOT evidence of a block.
func classifyExecError(err error) int {
	if err == nil {
		return StageSuccess
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "access is denied") ||
		strings.Contains(s, "access denied") ||
		strings.Contains(s, "permission denied") ||
		strings.Contains(s, "operation not permitted") ||
		strings.Contains(s, "blocked by") ||
		strings.Contains(s, "cannot execute") && strings.Contains(s, "denied") {
		return StageBlocked
	}
	return StageError
}

// waitDelayBound caps how long cmd.Wait() may block after the child process
// exits when a grandchild keeps the captured stdout/stderr pipe handles open
// (observed on Windows: tailcat's ssh ProxyCommand child / no-auth-ssh shell
// children inherit the handles, so Wait never sees pipe EOF even though the
// evidence was already captured). Go 1.20+; applies to both process-exited and
// context-killed paths.
const waitDelayBound = 3 * time.Second

// runCaptured runs cmd with a timeout, teeing stdout+stderr to the console and
// to LOG_DIR/<logName>. Returns combined output, the process exit code, and any
// launcher error. A context timeout is reported as exit code 102.
//
// Wait is bounded by cmd.WaitDelay: if the process has exited but a descendant
// still holds the pipe handles, Wait returns exec.ErrWaitDelay after
// waitDelayBound and we honor the process's real exit code from ProcessState.
func runCaptured(ctx context.Context, name string, cmd *exec.Cmd, logName string) (string, int, error) {
	outPath := filepath.Join(LOG_DIR, logName)
	var buf threadSafeBuffer

	outFile, ferr := os.Create(outPath)
	if ferr == nil {
		defer outFile.Close()
		w := io.MultiWriter(os.Stdout, outFile, &buf)
		cmd.Stdout = w
		cmd.Stderr = w
	} else {
		w := io.MultiWriter(os.Stdout, &buf)
		cmd.Stdout = w
		cmd.Stderr = w
	}

	cmd.WaitDelay = waitDelayBound
	runErr := cmd.Run()

	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			LogProcessExecution(name, strings.Join(cmd.Args, " "), 0, false, 102, "execution timeout")
			return buf.String(), 102, fmt.Errorf("%s execution exceeded timeout", name)
		}
		// Process exited but a pipe-holding descendant outlived it: the
		// captured output is complete evidence; honor the real exit code.
		if errors.Is(runErr, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			code := cmd.ProcessState.ExitCode()
			LogProcessExecution(name, strings.Join(cmd.Args, " "), 0, code == 0, code, "pipe handles held by descendant past WaitDelay; using process exit code")
			return buf.String(), code, nil
		}
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			LogProcessExecution(name, strings.Join(cmd.Args, " "), 0, false, code, exitErr.Error())
			return buf.String(), code, nil
		}
		LogProcessExecution(name, strings.Join(cmd.Args, " "), 0, false, StageError, runErr.Error())
		return buf.String(), StageError, runErr
	}

	LogProcessExecution(name, strings.Join(cmd.Args, " "), 0, true, 0, "")
	return buf.String(), 0, nil
}

// threadSafeBuffer is a byte sink safe for concurrent writes from the
// stdout/stderr tee goroutines.
type threadSafeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *threadSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *threadSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// ==============================================================================
// tailcat server lifecycle
// ==============================================================================

// tailcatServer wraps a running `tailcat serve ...` / `tailcat recv ...` child.
type tailcatServer struct {
	cmd     *exec.Cmd
	addrCh  chan string
	errCh   chan error
	waitCh  chan error
	logPath string
	mu      sync.Mutex
	killed  bool
}

// startTailcatServer launches tailcat with args, tees its stdout/stderr to
// LOG_DIR/<logName> and the console, and scans stderr for the ephemeral tailcat
// address (delivered on addrCh). The caller MUST call srv.kill() when done —
// every stage wires that through defer so the server dies even on panic.
func startTailcatServer(logName string, args ...string) (*tailcatServer, error) {
	cmd := exec.Command(tailcatPath(), args...)

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open stderr pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open stdout pipe: %v", err)
	}

	srv := &tailcatServer{
		cmd:     cmd,
		addrCh:  make(chan string, 1),
		errCh:   make(chan error, 1),
		waitCh:  make(chan error, 1),
		logPath: filepath.Join(LOG_DIR, logName),
	}

	// Bound cmd.Wait() after exit/kill: on Windows the no-auth-ssh server's
	// shell children inherit the stderr/stdout pipe handles, so without
	// WaitDelay the wait goroutine would block on pipe EOF forever after the
	// server process is already dead.
	cmd.WaitDelay = waitDelayBound

	outFile, ferr := os.Create(srv.logPath)
	if ferr != nil {
		return nil, fmt.Errorf("failed to create server log %s: %v", srv.logPath, ferr)
	}

	if err := cmd.Start(); err != nil {
		outFile.Close()
		return nil, fmt.Errorf("failed to start tailcat server: %v", err)
	}

	// Tee server output to console + file; scan stderr lines for the address.
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)
			outFile.WriteString(line + "\n")
			if m := tailcatAddrRe.FindString(line); m != "" {
				select {
				case srv.addrCh <- m:
				default:
				}
			}
		}
	}()
	go func() {
		io.Copy(io.MultiWriter(os.Stdout, outFile), stdout)
	}()
	go func() {
		srv.waitCh <- cmd.Wait()
		outFile.Close()
	}()

	return srv, nil
}

// waitAddress blocks until the server publishes its address or the timeout
// fires. A timeout is NOT positive evidence of a protection action — DERP
// bootstrap involves internet egress whose failure is ambiguous (999-class).
func (srv *tailcatServer) waitAddress(timeout time.Duration) (string, error) {
	select {
	case addr := <-srv.addrCh:
		return addr, nil
	case err := <-srv.waitCh:
		if err != nil {
			return "", fmt.Errorf("tailcat server exited before publishing an address: %v", err)
		}
		return "", fmt.Errorf("tailcat server exited before publishing an address")
	case <-time.After(timeout):
		return "", fmt.Errorf("timed out after %v waiting for tailcat server address (network egress to DERP relays may be unavailable)", timeout)
	}
}

// kill terminates the server and waits for it to die (bounded). Safe to call
// more than once and on an already-dead process. The Wait goroutine is itself
// bounded by cmd.WaitDelay, so a Windows grandchild holding the server's pipe
// handles cannot stretch this past waitDelayBound.
func (srv *tailcatServer) kill() {
	if srv == nil || srv.cmd == nil || srv.cmd.Process == nil {
		return
	}
	srv.mu.Lock()
	if srv.killed {
		srv.mu.Unlock()
		return
	}
	srv.killed = true
	srv.mu.Unlock()

	srv.cmd.Process.Kill()
	select {
	case <-srv.waitCh:
	case <-time.After(waitDelayBound + 2*time.Second):
	}
}

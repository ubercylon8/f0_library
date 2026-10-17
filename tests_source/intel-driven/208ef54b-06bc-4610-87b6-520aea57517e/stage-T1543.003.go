//go:build windows
// +build windows

/*
STAGE 2: Windows Service Creation + Relay Attempt (T1543.003, supports T1219)

Verifies that the ScreenConnect install (Stage 1) created a Windows service named
`ScreenConnect Client (<instance-id>)` and that it is running, then generates the
outbound-relay telemetry an RMM agent produces on start — a DNS resolution and a
TCP connect attempt against an UNREACHABLE / controlled relay host. No live relay
is stood up; the destination is an RFC 2606 `.invalid` placeholder and no relay
secrets are shipped.

Exit-code discipline (CLAUDE.md Bug Prevention Rules 5 & 8):
  - Service found  => positive evidence the service was created (T1543.003 met).
  - Relay attempt FAILING against the unreachable host is EXPECTED and benign — it
    is NOT evidence of an EDR network block, so it never yields a block code.
  - Service absent => ambiguous (install did not land) => StageError (999). We do
    NOT infer a block from absence.
*/

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	TEST_UUID      = "208ef54b-06bc-4610-87b6-520aea57517e"
	TECHNIQUE_ID   = "T1543.003"
	TECHNIQUE_NAME = "Windows Service Creation"
	STAGE_ID       = 2

	// Controlled, UNREACHABLE relay placeholder. RFC 2606 reserves `.invalid`,
	// guaranteeing non-resolution. NO real relay/instance config or secret is
	// committed. If the user later opts into a live relay, that stays out-of-band.
	RELAY_HOST = "instance-placeholder.screenconnect.invalid"
	RELAY_PORT = "443"
)

// Standardized stage exit codes.
const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Verifying ScreenConnect service creation and simulating relay egress")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Verify ScreenConnect Windows service + attempt outbound relay")

	// Step 1: confirm the service was created (positive T1543.003 evidence).
	svcName, running, found := findScreenConnectService()
	if !found {
		msg := "no 'ScreenConnect Client (*)' service found — install did not land (ambiguous, not a block)"
		fmt.Printf("[STAGE %s] %s\n", TECHNIQUE_ID, msg)
		LogMessage("ERROR", TECHNIQUE_ID, msg)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", msg)
		os.Exit(StageError)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("Service created: %q (running=%v)", svcName, running))

	if !running {
		// Creation is the telemetry we need; a stopped service still proves it.
		// Attempt a single start to reach the intended running state, then re-query.
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Service %q not running — attempting start", svcName))
		exec.Command("sc", "start", svcName).Run()
		time.Sleep(3 * time.Second)
		if _, nowRunning, ok := findScreenConnectService(); ok && nowRunning {
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Service %q now running after start", svcName))
		} else {
			LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Service %q created but not running — proceeding (creation is the signal)", svcName))
		}
	}

	// Step 2: generate relay egress telemetry (DNS + TCP connect attempt).
	attemptRelay()

	LogMessage("SUCCESS", TECHNIQUE_ID, "Service creation confirmed and relay egress attempted")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", fmt.Sprintf("Service %q verified; relay egress attempted to %s:%s", svcName, RELAY_HOST, RELAY_PORT))
	os.Exit(StageSuccess)
}

// attemptRelay produces the outbound telemetry an RMM agent emits on start:
// a DNS resolution and a TCP connect to the (unreachable) relay endpoint.
// Both are EXPECTED to fail here — that is benign, logged, and NOT a block.
func attemptRelay() {
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Resolving relay host %s (DNS telemetry)", RELAY_HOST))
	if addrs, err := net.LookupHost(RELAY_HOST); err != nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("DNS resolution of %s failed as expected (unreachable placeholder): %v", RELAY_HOST, err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("DNS resolution of %s returned %v", RELAY_HOST, addrs))
	}

	target := net.JoinHostPort(RELAY_HOST, RELAY_PORT)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Attempting outbound relay TCP connect to %s (egress telemetry)", target))
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		// Unreachable placeholder — expected, benign. NOT an EDR block (Rule 8).
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Relay connect to %s did not establish (expected for unreachable placeholder): %v", target, err))
		return
	}
	// If a connection unexpectedly establishes, close it immediately — no session.
	_ = conn.Close()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Relay connect to %s established unexpectedly — closed immediately (no session)", target))
}

// findScreenConnectService returns the first service whose NAME matches the
// ScreenConnect Client pattern (service name, not display name).
func findScreenConnectService() (name string, running bool, found bool) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		"Get-Service -Name 'ScreenConnect Client*' -ErrorAction SilentlyContinue | "+
			"Select-Object -First 1 | ForEach-Object { \"$($_.Name)|$($_.Status)\" }")
	out, err := cmd.Output()
	if err != nil {
		return "", false, false
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return "", false, false
	}
	parts := strings.SplitN(line, "|", 2)
	name = parts[0]
	if len(parts) == 2 {
		running = strings.EqualFold(strings.TrimSpace(parts[1]), "Running")
	}
	return name, running, true
}

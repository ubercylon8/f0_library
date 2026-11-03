// Stage 5 — T1053.005 Scheduled Task + T1543.003 Windows Service + T1136.001 Local Account Creation
// F0RT1KA Security Testing Framework
// The Gentlemen (GOLD SHERWOOD) — Objective 5: redundant persistence
//
// The Gentlemen establishes redundant persistence: masqueraded scheduled
// tasks (Huntress: schtasks /create /tn WindowsConnSvc /tr
// C:\Windows\Temp\svchost32.exe client <C2> ... /sc minute /mo 2 /ru SYSTEM —
// task and binary both named to look like Windows components), services
// (Sophos CTU: Cloudflared agent installed as a Windows service for a covert
// channel; Trend Micro: legitimate-tool services abused), and NEW PRIVILEGED
// LOCAL ACCOUNTS (Sophos CTU: "net1 localgroup administrators itadmin /add",
// "net group \"domain admins\" ldap /add /domain").
//
// All three artifacts are created for REAL (the 4698/7045/4720 event
// telemetry is exactly what an EDR must catch), are test-owned, and are
// REMOVED with verified cleanup before the stage exits:
//
//   1. T1053.005 — scheduled task named WindowsConnSvc (the actor's
//      masqueraded task name; NOT a real Windows task) with the actor's
//      argument shape (/sc minute /mo 2 /ru SYSTEM /f). The task action is a
//      benign cmd echo into LOG_DIR — never a C2 address, never a real
//      binary. Existing tasks are never clobbered: a task found pre-existing
//      under this name is queried and left untouched (leg skipped).
//   2. T1543.003 — decoy service F0GentlemenSvc (test-unique name, zero
//      collision risk) whose display name masquerades as "Velociraptor
//      Client". binPath points at a text marker in LOG_DIR; the service is
//      NEVER STARTED (and could not start: marker is not a PE).
//   3. T1136.001 — clearly-marked local account f0_gentlemen_acct (random
//      password, never logged in plaintext) added to the local
//      Administrators group (the Sophos group-add shape), then removed from
//      the group and deleted. This leg runs LAST so the privileged account
//      exists for the shortest possible window.
//
// CLEANUP GUARANTEE: each leg's removal runs via defer inside the leg
// function, so it executes even when a later step in the leg fails. If any
// cleanup fails to verify, the stage exits 999 with a CRITICAL log — never
// silently, never as a fake block.
//
// CLASSIFICATION (Rule 8): blocked only on positive OS-emitted denial of an
// operation that normally succeeds in this elevated context (schtasks/sc/net
// access-denied, errno 5). Non-elevated denials are not attributable (999).
//
// EXIT CODES: 0 = all three persistence artifacts created, verified and
// cleaned up without prevention, 126 = positive denial evidence,
// 999 = prerequisite/test error (including failed cleanup).

//go:build windows
// +build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	TEST_UUID      = "7cc45d21-9a6e-4128-9f75-06e5167a4b80"
	TECHNIQUE_ID   = "T1136.001"
	TECHNIQUE_NAME = "Persistence: Masqueraded Task, Decoy Service, Privileged Account (T1053.005/T1543.003/T1136.001)"
	STAGE_ID       = 5
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Test-owned artifact names. The task name reproduces the actor's masqueraded
// name (WindowsConnSvc is not a real Windows task); the service and account
// names are test-unique (f0_ prefix) so collision with real artifacts is
// impossible and ownership is self-evident.
const (
	taskName       = "WindowsConnSvc"
	taskAction     = `cmd.exe /c echo F0RT1KA-GENTLEMEN-TASK >> C:\F0\gentlemen_task_marker.txt`
	serviceName    = "F0GentlemenSvc"
	serviceBinPath = `C:\F0\gentlemen_svc_marker.exe`
	serviceDisplay = "Velociraptor Client"
	accountName    = "f0_gentlemen_acct"
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	elevated := isAdmin() || isSystemContext()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Execution context: elevated=%v system=%v", elevated, isSystemContext()))

	if !elevated {
		// All three legs require elevation; denials would be ACL-shaped and
		// not attributable (Rule 8). Fail fast as a prerequisite miss.
		LogMessage("ERROR", TECHNIQUE_ID, "persistence legs require an elevated context (lab runs as admin/SYSTEM)")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Non-elevated context: persistence prerequisites not met")
		os.Exit(StageError)
	}

	exitCode := performTechnique()

	switch exitCode {
	case StageSuccess:
		fmt.Printf("[STAGE %s] All persistence artifacts created, verified and cleaned without prevention\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "Task/service/account legs all executed and cleaned up unimpeded")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "All persistence legs executed without prevention")
	case StageBlocked:
		fmt.Printf("[STAGE %s] Persistence prevented (positive denial evidence)\n", TECHNIQUE_ID)
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "A persistence operation was denied with OS-emitted denial in elevated context", StageBlocked)
	default:
		fmt.Printf("[STAGE %s] Stage error - prerequisites not met or cleanup failed\n", TECHNIQUE_ID)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error, inconclusive leg, or failed cleanup")
	}
	os.Exit(exitCode)
}

// legOutcome is one persistence leg's classification.
const (
	legOK      = 0
	legBlocked = 126
	legError   = 999
)

func performTechnique() int {
	outcomes := []int{
		taskLeg(),
		serviceLeg(),
		accountLeg(), // LAST: shortest privileged-account existence window
	}

	for _, o := range outcomes {
		if o == legBlocked {
			return StageBlocked
		}
	}
	for _, o := range outcomes {
		if o != legOK {
			return StageError
		}
	}
	return StageSuccess
}

// -----------------------------------------------------------------------
// Leg 1: Masqueraded scheduled task (T1053.005)
// -----------------------------------------------------------------------

func taskLeg() int {
	// Never clobber: if a task with this name already exists and does not run
	// OUR marker action, leave it alone and skip the leg.
	if existing := schtasksOutput("/query", "/tn", taskName); existing.ran {
		if !strings.Contains(existing.output, "F0RT1KA") {
			LogMessage("WARNING", "T1053.005", fmt.Sprintf("task %q already exists and is not ours - skipping leg (never clobber)", taskName))
			return legError
		}
		LogMessage("INFO", "T1053.005", "stale task from prior run found - removing first")
		schtasksOutput("/delete", "/tn", taskName, "/f")
	}

	LogMessage("WARN", "T1053.005", fmt.Sprintf("T1053.005: schtasks /create /tn %s (masqueraded name) /sc minute /mo 2 /ru SYSTEM", taskName))
	create := schtasksOutput("/create", "/f", "/tn", taskName, "/tr", taskAction, "/sc", "minute", "/mo", "2", "/ru", "SYSTEM")
	if !create.ran {
		if create.denied {
			LogMessage("WARN", "T1053.005", fmt.Sprintf("task creation denied in elevated context (positive evidence): %s", create.output))
			return legBlocked
		}
		LogMessage("ERROR", "T1053.005", fmt.Sprintf("task creation failed (prerequisite/inconclusive): %s", create.output))
		return legError
	}

	// Deferred cleanup — runs on every return path below.
	cleaned := false
	defer func() {
		if cleaned {
			return
		}
		removeTask()
	}()

	// Verify existence (positive query evidence).
	q := schtasksOutput("/query", "/tn", taskName)
	if !q.ran || !strings.Contains(strings.ToLower(q.output), strings.ToLower(taskName)) {
		LogMessage("ERROR", "T1053.005", "task creation reported success but query could not verify it - inconclusive")
		return legError
	}
	LogMessage("CRITICAL", "T1053.005", fmt.Sprintf("masqueraded scheduled task %s verified registered (4698-shape telemetry)", taskName))

	if !removeTask() {
		return legError
	}
	cleaned = true
	return legOK
}

// removeTask deletes the decoy task and verifies deletion. Returns true when
// the task is confirmed absent.
func removeTask() bool {
	del := schtasksOutput("/delete", "/tn", taskName, "/f")
	q := schtasksOutput("/query", "/tn", taskName)
	if q.ran {
		LogMessage("CRITICAL", "T1053.005", fmt.Sprintf("CLEANUP FAILED: task %s still present after delete (delete output: %s)", taskName, del.output))
		return false
	}
	LogMessage("INFO", "T1053.005", "cleanup: decoy task removed and absence verified")
	return true
}

// -----------------------------------------------------------------------
// Leg 2: Decoy service (T1543.003)
// -----------------------------------------------------------------------

func serviceLeg() int {
	// Stage the inert "service binary" (text marker, never a PE) in LOG_DIR.
	if err := os.WriteFile(serviceBinPath, []byte(serviceMarkerContent()), 0644); err != nil {
		LogMessage("ERROR", "T1543.003", fmt.Sprintf("service marker write failed: %v", err))
		return legError
	}

	LogMessage("WARN", "T1543.003", fmt.Sprintf("T1543.003: sc create %s DisplayName= %q (legitimate-tool masquerade), never started", serviceName, serviceDisplay))
	create := scOutput("create", serviceName, "binPath=", serviceBinPath, "DisplayName=", serviceDisplay, "start=", "demand")
	if !create.ran {
		if create.denied {
			LogMessage("WARN", "T1543.003", fmt.Sprintf("service creation denied in elevated context (positive evidence): %s", create.output))
			return legBlocked
		}
		LogMessage("ERROR", "T1543.003", fmt.Sprintf("service creation failed (prerequisite/inconclusive): %s", create.output))
		return legError
	}

	cleaned := false
	defer func() {
		if cleaned {
			return
		}
		removeService()
	}()

	// Verify existence: sc query on a stopped-but-registered service returns
	// its state (exit 0); a missing service returns error 1060.
	q := scOutput("query", serviceName)
	if !q.ran {
		LogMessage("ERROR", "T1543.003", fmt.Sprintf("service creation reported success but query could not verify it (1060?): %s", q.output))
		return legError
	}
	LogMessage("CRITICAL", "T1543.003", fmt.Sprintf("decoy service %s (%q) verified registered (7045-shape telemetry), never started", serviceName, serviceDisplay))

	if !removeService() {
		return legError
	}
	cleaned = true
	return legOK
}

func removeService() bool {
	scOutput("delete", serviceName)
	q := scOutput("query", serviceName)
	if q.ran {
		LogMessage("CRITICAL", "T1543.003", fmt.Sprintf("CLEANUP FAILED: service %s still present after delete", serviceName))
		return false
	}
	LogMessage("INFO", "T1543.003", "cleanup: decoy service removed and absence verified")
	return true
}

// -----------------------------------------------------------------------
// Leg 3: Privileged local account (T1136.001)
// -----------------------------------------------------------------------

func accountLeg() int {
	password := randomPassword()

	LogMessage("WARN", "T1136.001", fmt.Sprintf("T1136.001: net user %s ***REDACTED*** /add (clearly-marked decoy account)", accountName))
	create := netOutput("user", accountName, password, "/add")
	if !create.ran {
		if create.denied {
			LogMessage("WARN", "T1136.001", fmt.Sprintf("account creation denied in elevated context (positive evidence): %s", create.output))
			return legBlocked
		}
		LogMessage("ERROR", "T1136.001", fmt.Sprintf("account creation failed (prerequisite/inconclusive): %s", create.output))
		return legError
	}

	// Deferred cleanup — runs on every return path below, INCLUDING blocks
	// on the group-add: an account that exists must never be left behind.
	accountExists := true
	defer func() {
		if accountExists {
			removeAccount()
		}
	}()

	// Verify account exists.
	if q := netOutput("user", accountName); !q.ran {
		LogMessage("ERROR", "T1136.001", "account creation reported success but net user lookup could not verify it - inconclusive")
		return legError
	}
	LogMessage("CRITICAL", "T1136.001", fmt.Sprintf("decoy account %s verified created (4720-shape telemetry)", accountName))

	// The Sophos CTU privilege-escalation shape: add to local Administrators.
	LogMessage("WARN", "T1136.001", fmt.Sprintf("T1136.001/privilege shape: net localgroup administrators %s /add", accountName))
	groupAdd := netOutput("localgroup", "administrators", accountName, "/add")
	if !groupAdd.ran {
		if groupAdd.denied {
			LogMessage("WARN", "T1136.001", fmt.Sprintf("administrators group-add denied in elevated context (positive evidence): %s", groupAdd.output))
			return legBlocked
		}
		LogMessage("ERROR", "T1136.001", fmt.Sprintf("administrators group-add failed (prerequisite/inconclusive): %s", groupAdd.output))
		return legError
	}
	LogProcessExecution("net.exe", fmt.Sprintf("net localgroup administrators %s /add", accountName), 0, true, 0, groupAdd.output)
	LogMessage("CRITICAL", "T1136.001", fmt.Sprintf("decoy account %s elevated into local Administrators (4728-shape telemetry)", accountName))

	if !removeAccount() {
		return legError
	}
	accountExists = false
	return legOK
}

// removeAccount strips the account from Administrators (if present) and
// deletes it, verifying absence. Returns true when the account is gone.
func removeAccount() bool {
	// Group removal first (best-effort: account may not be in the group).
	netOutput("localgroup", "administrators", accountName, "/delete")

	del := netOutput("user", accountName, "/delete")
	q := netOutput("user", accountName)
	if q.ran {
		LogMessage("CRITICAL", "T1136.001", fmt.Sprintf("CLEANUP FAILED: account %s still resolvable after delete (delete output: %s)", accountName, del.output))
		return false
	}
	LogMessage("INFO", "T1136.001", "cleanup: decoy account removed from Administrators and deleted; absence verified")
	return true
}

// -----------------------------------------------------------------------
// Shared command runners
// -----------------------------------------------------------------------

// cmdResult carries the classification inputs for a LOLBin invocation:
// ran (exit 0 / recognized success), denied (OS-emitted access denial),
// and the (possibly truncated) output.
type cmdResult struct {
	ran    bool
	denied bool
	output string
}

// runTool executes argv and classifies: ran (nil error), denied (OS errno 5
// or an ExitError whose output carries an OS access-denial line — the output
// text is produced BY THE TOOL for an OS denial, not by us; see Rule 1), or
// plain failure.
func runTool(name string, display string, args ...string) cmdResult {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	outStr := truncateOut(strings.TrimSpace(string(out)))

	if err == nil {
		LogProcessExecution(name, display, 0, true, 0, outStr)
		return cmdResult{ran: true, output: outStr}
	}

	denied := false
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == 5 {
		denied = true // CreateProcess-level refusal — strongest evidence
	} else {
		low := strings.ToLower(outStr)
		if strings.Contains(low, "system error 5") || strings.Contains(low, "access is denied") {
			denied = true
		}
	}
	LogProcessExecution(name, display, 0, false, exitCodeOf(err), outStr)
	return cmdResult{ran: false, denied: denied, output: outStr}
}

func schtasksOutput(args ...string) cmdResult {
	display := "schtasks " + strings.Join(args, " ")
	// Redact nothing here: task actions are our own marker text.
	return runTool("schtasks.exe", display, args...)
}

func scOutput(args ...string) cmdResult {
	display := "sc " + strings.Join(args, " ")
	return runTool("sc.exe", display, args...)
}

func netOutput(args ...string) cmdResult {
	// Never log account passwords: in "net user <name> <password> /add" the
	// password sits at index 2; flags like /delete are never redacted.
	safe := make([]string, len(args))
	for i, a := range args {
		if i == 2 && args[0] == "user" && len(args) > 2 && !strings.HasPrefix(args[2], "/") {
			safe[i] = "***"
		} else {
			safe[i] = a
		}
	}
	display := "net " + strings.Join(safe, " ")
	return runTool("net.exe", display, args...)
}

func exitCodeOf(err error) int {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

// serviceMarkerContent is the inert "service binary": a text marker with an
// .exe name. It is NOT a PE; the service could not start even if asked.
func serviceMarkerContent() string {
	var sb strings.Builder
	sb.WriteString("F0RT1KA SECURITY TEST - INERT SERVICE BINARY MARKER\n")
	sb.WriteString("====================================================\n")
	sb.WriteString("The Gentlemen persistence emulation (T1543.003).\n")
	sb.WriteString("This file is a TEXT MARKER with an .exe name. It is not a PE\n")
	sb.WriteString("image and cannot execute. The decoy service is never started.\n")
	sb.WriteString(fmt.Sprintf("Test UUID: %s\n", TEST_UUID))
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().UTC().Format(time.RFC3339)))
	return sb.String()
}

// randomPassword produces a 12-char complex password (upper/lower/digit/sym)
// that satisfies default complexity policy. It is deliberately kept at or
// below 14 characters: longer passwords make net.exe prompt an interactive
// Y/N confirmation ("password longer than 14 characters...") which cannot be
// answered over non-interactive SSH and aborts the account creation. The
// password is never logged.
func randomPassword() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(i * 13)
		}
	}
	hexStr := hex.EncodeToString(b) // 8 chars [0-9a-f]
	return "F0g!" + strings.ToUpper(hexStr[:4]) + hexStr[4:] // 12 chars total
}

func truncateOut(s string) string {
	if len(s) > 400 {
		return s[:400] + " ...[truncated]"
	}
	if s == "" {
		return "(no output)"
	}
	return s
}

// isSystemContext reports whether the process runs as SYSTEM (Rule 2).
func isSystemContext() bool {
	username := os.Getenv("USERNAME")
	return strings.HasSuffix(username, "$") || strings.EqualFold(username, "SYSTEM")
}

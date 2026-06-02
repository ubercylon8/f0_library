//go:build linux
// +build linux

/*
STAGE 2: Execution Guardrails & Sandbox Evasion (T1480.001, T1497.001)
Simulates the campaign's pre-execution checks:
  - Locale evasion: skip execution on Russian-language systems (locale starts "ru").
  - CI/CD detection: GITHUB_ACTIONS / RUNNER_OS to switch to CI exfil targeting.
  - Daemonization decision: detach to background on non-CI developer workstations
    (__IS_DAEMON env marker) for sustained harvesting.
  - Duplicate-run canary: lock file (tmp.0987654321.lock).

SAFETY: This stage only READS environment variables and writes a benign marker
lock file under /tmp/F0. It does NOT actually daemonize/detach, does NOT spawn
background processes, and does NOT skip the killchain (locale skip is logged as a
decision, not enforced, so the test always produces full telemetry in the lab).
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	TEST_UUID      = "ae9002e4-3d82-4fcd-8b45-f7e0628f7375"
	TECHNIQUE_ID   = "T1480.001"
	TECHNIQUE_NAME = "Execution Guardrails & Sandbox Evasion"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "locale/CI/canary guardrail evaluation")

	if err := performTechnique(); err != nil {
		if isBlockedError(err) {
			fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)
			LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
			os.Exit(StageBlocked)
		}
		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		os.Exit(StageError)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Guardrail evaluation simulated")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	artifactDir := filepath.Join("/tmp/F0", "shaihulud_guardrails")
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create guardrail artifact directory: %v", err)
	}

	var report strings.Builder
	report.WriteString("=== Mini Shai-Hulud Execution Guardrail Evaluation (SIMULATED) ===\n\n")

	// Phase 1: Locale evasion check.
	fmt.Printf("[STAGE %s] Phase 1: Locale evasion check (skip if locale starts 'ru')...\n", TECHNIQUE_ID)
	locale := detectLocale()
	ruEvasion := strings.HasPrefix(strings.ToLower(locale), "ru")
	report.WriteString(fmt.Sprintf("Locale: %s\n", locale))
	report.WriteString(fmt.Sprintf("Russian-locale evasion would trigger: %v\n", ruEvasion))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Locale guardrail: locale=%q ru-evasion=%v (decision logged, not enforced in lab)", locale, ruEvasion))

	// Phase 2: CI/CD environment detection.
	fmt.Printf("[STAGE %s] Phase 2: CI/CD environment detection (GITHUB_ACTIONS / RUNNER_OS)...\n", TECHNIQUE_ID)
	isCI := os.Getenv("GITHUB_ACTIONS") != "" || os.Getenv("RUNNER_OS") != "" || os.Getenv("CI") != ""
	report.WriteString(fmt.Sprintf("GITHUB_ACTIONS=%q RUNNER_OS=%q CI=%q\n",
		os.Getenv("GITHUB_ACTIONS"), os.Getenv("RUNNER_OS"), os.Getenv("CI")))
	if isCI {
		report.WriteString("Detected CI runner -> would enable GitHub Actions secret/OIDC exfil targeting\n")
		LogMessage("INFO", TECHNIQUE_ID, "CI/CD runner detected -> CI exfil profile selected (simulated)")
	} else {
		report.WriteString("Developer workstation context -> would daemonize for sustained harvesting\n")
		LogMessage("INFO", TECHNIQUE_ID, "Workstation context -> daemonization profile selected (simulated, not detached)")
	}

	// Phase 3: Daemonization decision (logged only; we do NOT detach).
	fmt.Printf("[STAGE %s] Phase 3: Daemonization decision (__IS_DAEMON marker)...\n", TECHNIQUE_ID)
	isDaemon := os.Getenv("__IS_DAEMON") != ""
	report.WriteString(fmt.Sprintf("__IS_DAEMON set: %v\n", isDaemon))
	report.WriteString("Daemonization: SIMULATED ONLY - no background process spawned\n")
	LogMessage("INFO", TECHNIQUE_ID, "Daemonization simulated as a decision; no detached process spawned (safety)")

	// Phase 4: Duplicate-run canary lock file.
	fmt.Printf("[STAGE %s] Phase 4: Writing duplicate-run canary lock (tmp.0987654321.lock)...\n", TECHNIQUE_ID)
	lockPath := filepath.Join(artifactDir, "tmp.0987654321.lock")
	if _, err := os.Stat(lockPath); err == nil {
		report.WriteString("Lock file already present -> duplicate run would abort\n")
		LogMessage("INFO", TECHNIQUE_ID, "Canary lock already present (duplicate-run guard simulated)")
	} else {
		if err := os.WriteFile(lockPath, []byte(fmt.Sprintf("pid=%d\n", os.Getpid())), 0644); err != nil {
			return fmt.Errorf("failed to write canary lock file: %v", err)
		}
		LogFileDropped("tmp.0987654321.lock", lockPath, 0, false)
		report.WriteString("Canary lock written\n")
	}

	reportPath := filepath.Join(artifactDir, "guardrail_evaluation.txt")
	if err := os.WriteFile(reportPath, []byte(report.String()), 0644); err != nil {
		return fmt.Errorf("failed to write guardrail report: %v", err)
	}
	LogFileDropped("guardrail_evaluation.txt", reportPath, int64(report.Len()), false)

	fmt.Printf("[STAGE %s] Guardrail evaluation complete (all checks passed -> proceed).\n", TECHNIQUE_ID)
	return nil
}

func detectLocale() string {
	for _, env := range []string{"LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return "C"
}

func isBlockedError(err error) bool {
	errStr := strings.ToLower(err.Error())
	blockedPatterns := []string{
		"quarantined", "blocked by security", "blocked by endpoint",
		"malware detected", "threat detected", "security policy",
	}
	for _, pattern := range blockedPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}

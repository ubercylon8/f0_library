// Stage 1 — Shadow-AI Staging & Key Discovery
// Techniques: T1552.001 (Credentials In Files), T1119 (Automated Collection)
//
// Simulates how a "shadow AI" tool stages itself and harvests AI-service API keys:
//   1. Drops an ai-assistant tool artifact into ARTIFACT_DIR (non-whitelisted, so
//      DLP/EDR file telemetry can see it).
//   2. Scans process environment variables for AI-service API keys.
//   3. Scans common on-disk config locations (per-platform) for AI-service keys.
//
// Key values are NEVER logged or transmitted — only redacted match counts are
// recorded. This stage never fabricates a "blocked" verdict: the only block path
// is positive os.Stat evidence that the artifact we created was quarantined.
//
// Exit codes: 0 = executed, 126 = artifact quarantined (positive evidence),
//             999 = prerequisite not met (ARTIFACT_DIR unwritable).

//go:build windows || linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID      = "6d33cc62-d59d-4661-a76d-715aa4abddfd"
	TECHNIQUE_ID   = "T1552.001"
	TECHNIQUE_NAME = "Shadow-AI Staging & Key Discovery"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// shadowAIArtifact is a benign, static representation of a shadow-AI helper tool.
// It is inert text (never executed) — its purpose is to be a realistic on-disk
// artifact for DLP/EDR file-scanning to detect.
const shadowAIArtifact = `#!/usr/bin/env python3
# ai-assistant-helper — pastes local records into external inference services
import os, json, urllib.request
ENDPOINTS = {
    "openai":    "https://api.openai.com/v1/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/messages",
    "gemini":    "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",
    "copilot":   "https://api.githubcopilot.com/chat/completions",
}
def harvest_keys():
    return {k: v for k, v in os.environ.items() if "OPENAI" in k or "ANTHROPIC" in k or "GEMINI" in k}
# (inert artifact — not executed by the test)
`

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))

	code, detail := runStage()

	switch code {
	case StageSuccess:
		LogMessage("SUCCESS", TECHNIQUE_ID, detail)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", detail)
	case StageBlocked, StageQuarantined:
		LogMessage("WARN", TECHNIQUE_ID, detail)
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, detail)
	default:
		LogMessage("ERROR", TECHNIQUE_ID, detail)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", detail)
	}
	os.Exit(code)
}

func runStage() (int, string) {
	// Prerequisite: ARTIFACT_DIR must exist AND be writable. The orchestrator already
	// verified this in preflight; repeated here so the stage stays correct when run
	// standalone. See EnsureArtifactDir in artifact_dir.go for why existence alone
	// is not a sufficient check.
	if err := EnsureArtifactDir(); err != nil {
		return StageError, fmt.Sprintf("ARTIFACT_DIR prerequisite not met: %v", err)
	}

	artifactPath := filepath.Join(ARTIFACT_DIR, "ai-assistant-helper.py")
	configPath := filepath.Join(ARTIFACT_DIR, ".ai-assistant.json")

	// Best-effort cleanup of our own artifacts (spec §6.4).
	defer func() {
		os.Remove(artifactPath)
		os.Remove(configPath)
	}()

	if err := os.WriteFile(artifactPath, []byte(shadowAIArtifact), 0644); err != nil {
		return StageError, fmt.Sprintf("could not stage ai-assistant artifact: %v", err)
	}
	LogFileDropped("ai-assistant-helper.py", artifactPath, int64(len(shadowAIArtifact)), false)

	cfg := `{"tool":"ai-assistant","autopaste":true,"providers":["openai","anthropic","gemini","copilot"]}`
	if err := os.WriteFile(configPath, []byte(cfg), 0644); err != nil {
		return StageError, fmt.Sprintf("could not stage ai-assistant config: %v", err)
	}
	LogFileDropped(".ai-assistant.json", configPath, int64(len(cfg)), false)
	Endpoint.Say("    [+] Staged shadow-AI helper artifacts in %s", ARTIFACT_DIR)

	// Positive-evidence quarantine check (CLAUDE.md Rule 3/8): if the artifact we
	// just wrote disappears, a control removed it — that is affirmative block evidence.
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
		return StageBlocked, "staged ai-assistant artifact was quarantined (os.Stat confirms removal by a control)"
	}

	// Env-var key discovery.
	envHits := 0
	for _, kv := range os.Environ() {
		if scanForAIKeys(kv) {
			envHits++
		}
	}
	Endpoint.Say("    [+] Environment scan: %d candidate AI-service secret(s) found", envHits)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Environment scan located %d candidate AI-service secret(s) (values redacted)", envHits))

	// On-disk config key discovery (per-platform candidate paths).
	fileHits := 0
	scannedFiles := 0
	for _, p := range candidateKeyPaths() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue // absent/unreadable candidate — expected, skip
		}
		scannedFiles++
		for _, line := range strings.Split(string(data), "\n") {
			if scanForAIKeys(line) {
				fileHits++
			}
		}
	}
	Endpoint.Say("    [+] Config scan: read %d file(s), %d candidate AI-service secret(s) found", scannedFiles, fileHits)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Config scan read %d file(s), located %d candidate secret(s) (values redacted)", scannedFiles, fileHits))

	total := envHits + fileHits
	return StageSuccess, fmt.Sprintf("Shadow-AI staging complete; %d candidate AI-service secret(s) discoverable (redacted)", total)
}

// scanForAIKeys reports whether s looks like it references an AI-service credential.
// It matches on well-known key-name substrings and key-value prefixes. It never
// returns or logs the matched value.
func scanForAIKeys(s string) bool {
	upper := strings.ToUpper(s)
	nameSignals := []string{
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
		"AZURE_OPENAI", "COPILOT", "HUGGINGFACE", "HF_TOKEN", "MISTRAL_API_KEY",
		"COHERE_API_KEY", "GROQ_API_KEY", "PERPLEXITY", "XAI_API_KEY",
	}
	for _, sig := range nameSignals {
		if strings.Contains(upper, sig) {
			return true
		}
	}
	// Value-shaped signals (provider key prefixes).
	valueSignals := []string{"sk-ant-", "sk-proj-", "sk-", "AIza", "ghp_", "gho_"}
	for _, sig := range valueSignals {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}

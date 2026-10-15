// ARTIFACT_DIR provisioning and writability verification.
//
// Shared by the orchestrator (preflight, before any stage runs) and by the stages
// that drop simulation artifacts (T1552.001, T1005). Compiled into both the
// orchestrator and the stage binaries — see STAGE_SHARED / ORCH_SHARED in build_all.sh.
//
// No build tag: ARTIFACT_DIR itself comes from the per-platform test_logger_<os>.go
// file, and the operator-facing remediation text branches on runtime.GOOS rather
// than duplicating this file per platform.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// preflightProbeName is the throwaway file used to prove ARTIFACT_DIR is writable.
// It is written and removed immediately — it exists only long enough to answer
// "can this process actually drop files here?" and is not part of the simulation.
const preflightProbeName = ".f0-preflight"

// EnsureArtifactDir provisions ARTIFACT_DIR and proves this process can write to it.
//
// Existence is NOT a sufficient prerequisite check. os.MkdirAll returns nil for a
// directory that already exists but denies writes to the current user — the common
// lab and client-endpoint case (/home/fortika-test owned by root at 0755;
// c:\Users\fortika-test created by an admin without granting Users modify rights).
// Under that false pass the run proceeds and dies later, mid-stage, at the first
// os.WriteFile. So we write and remove a probe file to settle the question up front.
//
// Callers MUST treat a failure here as inconclusive (999 / UnexpectedTestError). An
// unprovisioned artifact directory is a test-setup problem, never evidence that a
// control blocked anything (CLAUDE.md Bug Prevention Rule 8).
func EnsureArtifactDir() error {
	if err := os.MkdirAll(ARTIFACT_DIR, 0755); err != nil {
		return fmt.Errorf("could not create %s: %w", ARTIFACT_DIR, err)
	}

	probe := filepath.Join(ARTIFACT_DIR, preflightProbeName)
	if err := os.WriteFile(probe, []byte("f0rt1ka preflight"), 0644); err != nil {
		return fmt.Errorf("%s is present but this process cannot write to it: %w", ARTIFACT_DIR, err)
	}
	if err := os.Remove(probe); err != nil {
		return fmt.Errorf("could not clean up preflight probe %s: %w", probe, err)
	}

	return nil
}

// ArtifactDirRemediation returns the operator-facing commands that provision
// ARTIFACT_DIR on the current platform. Printed when EnsureArtifactDir fails so a
// setup problem can be fixed at the console without going back to the docs.
func ArtifactDirRemediation() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			fmt.Sprintf(`mkdir "%s"`, ARTIFACT_DIR),
			fmt.Sprintf(`icacls "%s" /grant Users:(OI)(CI)M`, ARTIFACT_DIR),
		}
	default:
		return []string{
			fmt.Sprintf("sudo mkdir -p %s", ARTIFACT_DIR),
			fmt.Sprintf("sudo chmod 777 %s", ARTIFACT_DIR),
		}
	}
}

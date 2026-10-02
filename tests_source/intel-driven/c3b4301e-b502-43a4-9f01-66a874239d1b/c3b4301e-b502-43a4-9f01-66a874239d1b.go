//go:build windows
// +build windows

/*
ID: c3b4301e-b502-43a4-9f01-66a874239d1b
NAME: Star Blizzard RedFlick CosmicPulse Espionage Chain
TECHNIQUES: T1204.002, T1105, T1059.001, T1218.007, T1053.005, T1218.011, T1071.001
TACTICS: execution, command-and-control, defense-evasion, persistence
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: Star Blizzard
SUBCATEGORY: apt
TAGS: star-blizzard, seaborgium, redflick, cosmicpulse, lolbin, ssh-cradle, scheduled-tasks, cpl-execution, aes-payload, http-c2
SOURCE_URL: https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
UNIT: response
CREATED: 2026-09-30
AUTHOR: sectest-builder
*/

// Multi-stage simulation of the Star Blizzard (SEABORGIUM/Callisto, FSB-linked)
// "RedFlick" delivery technique and CosmicPulse backdoor persistence chain
// disclosed by Microsoft Threat Intelligence on 2026-09-29.
//
// Stage map (one ATT&CK technique per stage binary):
//   1. T1204.002  Event-invite LNK execution (conhost -> cmd -> BAT, decoy PDF)
//   2. T1105      ssh.exe PermitLocalCommand / curl.exe download cradle (loopback)
//   3. T1059.001  PowerShell base64 payload extraction from weaponized PDF (cAB magic header)
//   4. T1218.007  Silent MSI execution (msiexec /q /i decoy package)
//   5. T1053.005  Persistence task trio (real RedFlick task names)
//   6. T1218.011  CPL execution via Shell32 Control_RunDLL + .mollis AES-ECB registry staging
//   7. T1071.001  CosmicPulse-style beacon (UTF-16LE + Base64 host data over HTTP)
//
// SAFETY BOUNDS (Tier 1 gate):
//   - All decoy artifacts stay in ARTIFACT_DIR (c:\Users\fortika-test\StarBlizzardInvite)
//   - All binaries/logs stay in LOG_DIR (C:\F0)
//   - All network I/O is loopback-only (127.0.0.1) via an in-process HTTP server
//   - Scheduled tasks point at inert decoy placeholders and are removed by the
//     embedded cleanup utility on every exit path (pre-existing tasks are never
//     created over or deleted)
//   - Per-stage watchdog (180s) force-terminates hung stages
//
// FIDELITY DEVIATIONS (documented in <uuid>_info.md):
//   - ssh.exe cradle targets 127.0.0.1 and expects an auth refusal; the exact
//     PermitLocalCommand flag surface is what generates telemetry
//   - The "MSI" is a decoy package (no MSI toolchain on build host); msiexec
//     telemetry + the task-creation behavior it installs are the observables
//   - The .cpl is a decoy file; rundll32/control.exe command lines are the observables

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	cert_installer "github.com/preludeorg/libraries/go/tests/cert_installer"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/crypto/ssh"
)

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const (
	TEST_UUID = "c3b4301e-b502-43a4-9f01-66a874239d1b"
	TEST_NAME = "Star Blizzard RedFlick CosmicPulse Espionage Chain"

	// Real identifiers from the RedFlick disclosure (scheduled task names)
	TASK_NET_QUALITY  = "Internet Quality Test Connection"
	TASK_NET_CONFIG   = "Network Configuration Manager"
	TASK_SYS_HEALTH   = "System Health Monitor"
	MOLLIS_REG_PATH   = `Software\Classes\.mollis`
	INVITE_SUBDIR     = "StarBlizzardInvite"
	STAGE_TIMEOUT_SECS = 180
)

// Embed gzip-compressed signed stage binaries.
// Build sequence: build -> sign -> gzip -9 -> embed (see build_all.sh).

//go:embed c3b4301e-b502-43a4-9f01-66a874239d1b-T1204.002.exe.gz
var stage1Compressed []byte

//go:embed c3b4301e-b502-43a4-9f01-66a874239d1b-T1105.exe.gz
var stage2Compressed []byte

//go:embed c3b4301e-b502-43a4-9f01-66a874239d1b-T1059.001.exe.gz
var stage3Compressed []byte

//go:embed c3b4301e-b502-43a4-9f01-66a874239d1b-T1218.007.exe.gz
var stage4Compressed []byte

//go:embed c3b4301e-b502-43a4-9f01-66a874239d1b-T1053.005.exe.gz
var stage5Compressed []byte

//go:embed c3b4301e-b502-43a4-9f01-66a874239d1b-T1218.011.exe.gz
var stage6Compressed []byte

//go:embed c3b4301e-b502-43a4-9f01-66a874239d1b-T1071.001.exe.gz
var stage7Compressed []byte

//go:embed cleanup_utility.exe.gz
var cleanupCompressed []byte

// Genuine persistence MSI (realism lift 3): authored via Windows Installer
// COM automation (lab_assets/build_msi.ps1) and Authenticode-signed. Its
// CustomActions silently create the three RedFlick scheduled tasks — the
// exact mechanism the disclosure documents. ProductCode is pinned so the
// cleanup utility can uninstall the product after each run.
//
//go:embed lab_assets/redflick_persistence.msi
var persistenceMSI []byte

// KillchainStage represents one technique in the attack killchain
// (named KillchainStage to avoid clashing with test_logger.go's Stage type)
type KillchainStage struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
}

// ==============================================================================
// LOOPBACK SERVER (all "C2" and payload hosting stays on 127.0.0.1)
// ==============================================================================

type loopbackServer struct {
	server   *http.Server
	listener net.Listener
	port     string

	mu        sync.Mutex
	beaconLog []string
}

func startLoopbackServer() (*loopbackServer, error) {
	ls := &loopbackServer{}

	// Weaponized decoy PDF: benign invite text + base64 command after the
	// documented "cAB" magic header. The embedded command stages the fetched
	// PDF into ARTIFACT_DIR (mirrors the July RedFlick chain: PowerShell
	// extracts a base64 payload hidden inside a PDF and executes it).
	stagingCmd := fmt.Sprintf(`cmd /c copy "c:\F0\invite.pdf" "%s\staged_invitation.pdf"`, inviteDir())
	weaponizedPDF := []byte("%PDF-1.4\n" +
		"F0RT1KA DECOY - IISS Transatlantic Security Event Invitation\n" +
		"Dear colleague, please find attached the event materials.\n" +
		"This document is a sandbox simulation artifact. No real event.\n" +
		"cAB" + base64.StdEncoding.EncodeToString([]byte(stagingCmd)) + "\n%%EOF\n")

	decoyPythonZip := []byte("F0RT1KA-DECOY python-3.8.0-amd64 package placeholder\n")
	decoyBootstrapper := []byte("F0RT1KA-DECOY CosmicPulse bootstrapper placeholder\n")

	mux := http.NewServeMux()
	mux.HandleFunc("/assets/invite.pdf", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		w.Write(weaponizedPDF)
	})
	mux.HandleFunc("/assets/setup.msi", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(persistenceMSI)
	})
	mux.HandleFunc("/assets/python38.zip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(decoyPythonZip)
	})
	mux.HandleFunc("/assets/bootstrapper.zip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(decoyBootstrapper)
	})
	// CosmicPulse-style poll endpoint: records the beacon (host data arrives
	// in the id= parameter, UTF-16LE+Base64 encoded exactly as in the report)
	mux.HandleFunc("/agent/poll", func(w http.ResponseWriter, r *http.Request) {
		ls.mu.Lock()
		ls.beaconLog = append(ls.beaconLog,
			fmt.Sprintf("%s id=%s ua=%q", time.Now().UTC().Format(time.RFC3339), r.URL.Query().Get("id"), r.UserAgent()))
		ls.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("POLL_OK"))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("loopback listener creation failed: %v", err)
	}
	ls.listener = listener
	ls.port = fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
	ls.server = &http.Server{Handler: mux}

	go func() { _ = ls.server.Serve(listener) }()
	return ls, nil
}

func (ls *loopbackServer) persistBeaconLog() {
	if ls == nil {
		return
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	path := filepath.Join(LOG_DIR, "c2_beacons.log")
	_ = os.WriteFile(path, []byte(strings.Join(ls.beaconLog, "\n")+"\n"), 0644)
}

func inviteDir() string {
	return filepath.Join(ARTIFACT_DIR, INVITE_SUBDIR)
}

// ==============================================================================
// LOOPBACK SSH SERVER (realism lift 2)
// ==============================================================================

// sshSandbox runs a minimal in-process SSH server on 127.0.0.1 so the
// ssh.exe PermitLocalCommand cradle in Stage 2 can authenticate successfully
// and ACTUALLY execute its local command — the exact mechanism Microsoft
// documented for RedFlick — with zero OS mutation and zero non-loopback I/O.
// Host and client keys are generated per-run; the client key is written to
// LOG_DIR (never the user's .ssh directory) and removed by cleanup.
type sshSandbox struct {
	listener  net.Listener
	port      string
	clientKey string // path to the generated OpenSSH private key (for ssh.exe -i)
}

func startSSHSandbox() (*sshSandbox, error) {
	// Per-run host key
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ssh host key generation failed: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		return nil, fmt.Errorf("ssh host signer creation failed: %v", err)
	}

	// Per-run client keypair; the public half pins the only accepted identity
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ssh client key generation failed: %v", err)
	}
	acceptedKey, err := ssh.NewPublicKey(clientPub)
	if err != nil {
		return nil, fmt.Errorf("ssh client public key parse failed: %v", err)
	}

	// OpenSSH-format private key file for `ssh.exe -i` (x/crypto MarshalPrivateKey)
	keyBlock, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		return nil, fmt.Errorf("ssh client key encoding failed: %v", err)
	}
	keyPath := filepath.Join(LOG_DIR, "f0_ssh_key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), 0600); err != nil {
		return nil, fmt.Errorf("ssh client key write failed: %v", err)
	}
	// Windows OpenSSH refuses key files whose ACL allows other users
	// ("UNPROTECTED PRIVATE KEY FILE") — strip inheritance and grant only
	// the executing user (lab finding 2026-10-01).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	grant := fmt.Sprintf(`%s\%s:F`, os.Getenv("COMPUTERNAME"), os.Getenv("USERNAME"))
	if out, aclErr := exec.CommandContext(ctx, "icacls.exe", keyPath, "/inheritance:r", "/grant:r", grant).CombinedOutput(); aclErr != nil {
		return nil, fmt.Errorf("ssh client key ACL restriction failed: %v (%s)", aclErr, strings.TrimSpace(string(out)))
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), acceptedKey.Marshal()) {
				LogMessage("INFO", "SSH Sandbox", fmt.Sprintf("publickey accepted for %q from %s — PermitLocalCommand will fire client-side", meta.User(), meta.RemoteAddr()))
				return &ssh.Permissions{}, nil
			}
			LogMessage("WARN", "SSH Sandbox", fmt.Sprintf("identity not accepted for %q from %s", meta.User(), meta.RemoteAddr()))
			return nil, fmt.Errorf("identity not accepted for %q", meta.User())
		},
	}
	config.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("ssh loopback listener creation failed: %v", err)
	}

	sb := &sshSandbox{
		listener:  listener,
		port:      fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port),
		clientKey: keyPath,
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go sb.handleConn(conn, config)
		}
	}()
	return sb, nil
}

// handleConn completes the SSH handshake, tolerates the client's `exit`
// session (PermitLocalCommand runs client-side immediately after successful
// authentication, before the session channel closes). The connection is
// force-closed after the exec session completes — the single-purpose sandbox
// never hosts a second session, and some Windows OpenSSH builds otherwise
// linger waiting for the server to end the transport.
func (sb *sshSandbox) handleConn(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		LogMessage("WARN", "SSH Sandbox", fmt.Sprintf("handshake ended: %v", err))
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are handled")
			continue
		}
		channel, chanReqs, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go func(sconn *ssh.ServerConn, channel ssh.Channel, chanReqs <-chan *ssh.Request) {
			defer sconn.Close()
			defer channel.Close()
			for req := range chanReqs {
				switch req.Type {
				case "exec":
					// client runs `exit`; acknowledge, report success, and
					// end the transport so ssh.exe terminates promptly
					_ = req.Reply(true, nil)
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					LogMessage("INFO", "SSH Sandbox", "exec session answered — closing transport")
					return
				case "shell":
					_ = req.Reply(false, nil)
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}(sconn, channel, chanReqs)
	}
}

// ==============================================================================
// MAIN
// ==============================================================================

func main() {
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "defense_evasion",
		Severity:   "high",
		Techniques: []string{"T1204.002", "T1105", "T1059.001", "T1218.007", "T1053.005", "T1218.011", "T1071.001"},
		Tactics:    []string{"execution", "command-and-control", "defense-evasion", "persistence"},
		Score:      8.7,
		RubricVersion: "v2.1", // Safety gate + Realism 0-7 + Structure 0-3; telemetry sub-score capped pending SIEM rule-firing evidence
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8, // v2.1 2a 2.2 + 2b 1.2 (SSH cradle + genuine MSI are real executions; scaled into legacy field)
			TechnicalSophistication: 2.6, // real SSH transport + Installer transaction lineage, AES-ECB staging, loopback C2 protocol fidelity
			SafetyMechanisms:        1.5, // watchdog + cleanup on all paths + loopback-only egress + skip-if-exists tasks + pinned ProductCode uninstall
			DetectionOpportunities:  0.8, // v2.1 2c 1.5 (cap): full-chain protected-lab run + documented rule mapping; SIEM firing evidence pending
			LoggingObservability:    1.0, // schema v2.0 logger + per-stage bundle fan-out + pre/post snapshots + surviving verdict files
		},
		Tags: []string{"star-blizzard", "redflick", "cosmicpulse", "lolbin", "scheduled-tasks", "http-c2"},
	}

	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         600000,
			MultiStageEnabled: true,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			runCleanup()
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}()

	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Multi-Stage Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Threat Actor: Star Blizzard (SEABORGIUM/Callisto, FSB-linked)")
	Endpoint.Say("Technique basis: RedFlick delivery + CosmicPulse backdoor")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Pre-flight: trust certificate for the F0RT1KA code-signing chain
	if err := cert_installer.EnsureCertificateInstalled(); err != nil {
		Endpoint.Say("FATAL: certificate installation failed: %v", err)
		SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("certificate installation failed: %v", err))
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Provision the decoy workspace under ARTIFACT_DIR. The sandbox marker
	// gates the cleanup utility: the workspace is only ever removed when the
	// marker proves this run created it.
	if err := os.MkdirAll(inviteDir(), 0755); err != nil {
		Endpoint.Say("FATAL: artifact directory provisioning failed: %v", err)
		SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("artifact directory provisioning failed: %v", err))
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	if err := os.WriteFile(filepath.Join(inviteDir(), "F0RT1KA_SANDBOX_MARKER.txt"),
		[]byte(fmt.Sprintf("sandbox workspace of test %s created %s — safe for cleanup\n", TEST_UUID, time.Now().UTC().Format(time.RFC3339))), 0644); err != nil {
		Endpoint.Say("FATAL: sandbox marker write failed: %v", err)
		SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("sandbox marker write failed: %v", err))
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Pre-create the inert task-action decoys the persistence MSI's
	// CustomActions reference (they only append a log line if ever fired)
	for i, taskName := range []string{TASK_NET_QUALITY, TASK_NET_CONFIG, TASK_SYS_HEALTH} {
		decoyAction := filepath.Join(inviteDir(), fmt.Sprintf("task%d_action.cmd", i+1))
		script := fmt.Sprintf("@echo off\r\necho %%date%% %%time%% task '%s' fired >> \"%s\"\r\n", taskName, filepath.Join(LOG_DIR, "task_fire.log"))
		if err := os.WriteFile(decoyAction, []byte(script), 0755); err != nil {
			Endpoint.Say("FATAL: task action decoy write failed: %v", err)
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("task action decoy write failed: %v", err))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}

	// Snapshot whether any persistence task name already exists on the host:
	// Stage 5 merges this with post-install state so cleanup only ever
	// removes tasks this test (MSI or fallback) created.
	var precheckLines []string
	for _, taskName := range []string{TASK_NET_QUALITY, TASK_NET_CONFIG, TASK_SYS_HEALTH} {
		existed := taskNameExists(taskName)
		precheckLines = append(precheckLines, fmt.Sprintf("TASK=%s|EXISTED_BEFORE=%v", taskName, existed))
		if existed {
			Endpoint.Say("[!] NOTE: task '%s' already present on host — it will not be touched", taskName)
		}
	}
	if err := os.WriteFile(filepath.Join(LOG_DIR, "task_precheck.txt"), []byte(strings.Join(precheckLines, "\n")+"\n"), 0644); err != nil {
		Endpoint.Say("FATAL: task precheck write failed: %v", err)
		SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("task precheck write failed: %v", err))
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	writeSystemSnapshot("pre")

	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		Endpoint.Say("FATAL: log directory creation failed: %v", err)
		SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("log directory creation failed: %v", err))
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Loopback asset/C2 server — all stage network I/O targets 127.0.0.1
	ls, err := startLoopbackServer()
	if err != nil {
		Endpoint.Say("FATAL: %v", err)
		SaveLog(Endpoint.UnexpectedTestError, err.Error())
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	defer ls.server.Close()
	Endpoint.Say("[*] Loopback asset/C2 server listening on 127.0.0.1:%s", ls.port)

	// Loopback SSH sandbox (realism lift 2) — lets the Stage 2 cradle
	// authenticate and actually execute PermitLocalCommand
	sb, err := startSSHSandbox()
	if err != nil {
		Endpoint.Say("FATAL: %v", err)
		SaveLog(Endpoint.UnexpectedTestError, err.Error())
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	defer sb.listener.Close()
	Endpoint.Say("[*] Loopback SSH sandbox listening on 127.0.0.1:%s", sb.port)
	Endpoint.Say("")

	test(ls, sb)
}

// ==============================================================================
// TEST EXECUTION
// ==============================================================================

func test(ls *loopbackServer, sb *sshSandbox) {
	killchain := []KillchainStage{
		{
			ID: 1, Name: "Event-Invite LNK Execution", Technique: "T1204.002",
			BinaryName: fmt.Sprintf("%s-T1204.002.exe", TEST_UUID), BinaryData: stage1Compressed,
			Description: "Victim-style execution of LNK from event-invite archive: hidden conhost -> cmd -> BAT opening a decoy PDF",
		},
		{
			ID: 2, Name: "LOLBin Download Cradle", Technique: "T1105",
			BinaryName: fmt.Sprintf("%s-T1105.exe", TEST_UUID), BinaryData: stage2Compressed,
			Description: "ssh.exe PermitLocalCommand cradle attempt + curl.exe fetch of weaponized PDF and MSI from loopback host",
		},
		{
			ID: 3, Name: "PowerShell Embedded Payload Extraction", Technique: "T1059.001",
			BinaryName: fmt.Sprintf("%s-T1059.001.exe", TEST_UUID), BinaryData: stage3Compressed,
			Description: "PowerShell extracts base64 command after cAB magic header inside PDF and executes it (July RedFlick chain)",
		},
		{
			ID: 4, Name: "Silent MSI Execution", Technique: "T1218.007",
			BinaryName: fmt.Sprintf("%s-T1218.007.exe", TEST_UUID), BinaryData: stage4Compressed,
			Description: "msiexec.exe /q /i executes the fetched package (RedFlick delivers its persistence MSI silently)",
		},
		{
			ID: 5, Name: "Persistence Task Trio", Technique: "T1053.005",
			BinaryName: fmt.Sprintf("%s-T1053.005.exe", TEST_UUID), BinaryData: stage5Compressed,
			Description: "Creates the three RedFlick scheduled tasks by their real names, actions pointing at inert decoys",
		},
		{
			ID: 6, Name: "CPL Execution + Registry Key Staging", Technique: "T1218.011",
			BinaryName: fmt.Sprintf("%s-T1218.011.exe", TEST_UUID), BinaryData: stage6Compressed,
			Description: "rundll32 shell32.dll Control_RunDLL + control.exe launch a decoy CPL; AES-ECB key written to HKCU .mollis",
		},
		{
			ID: 7, Name: "CosmicPulse Beacon", Technique: "T1071.001",
			BinaryName: fmt.Sprintf("%s-T1071.001.exe", TEST_UUID), BinaryData: stage7Compressed,
			Description: "Installer-style staging of Python/bootstrapper decoys, then hostname/username UTF-16LE+Base64 beacon to loopback /agent/poll",
		},
	}

	// Phase 0: extract stage binaries + cleanup utility
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries + cleanup utility...", len(killchain))

	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("log dir creation failed: %v", err))
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	for i, stage := range killchain {
		Endpoint.Say("    [%d/%d] Extracting %s (%s)", i+1, len(killchain), stage.BinaryName, stage.Technique)
		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("extraction failed for %s: %v", stage.BinaryName, err))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("stage extraction failed: %v", err))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}
	if err := extractNamed("cleanup_utility.exe", cleanupCompressed); err != nil {
		SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("cleanup extraction failed: %v", err))
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	LogPhaseEnd(0, "success", fmt.Sprintf("extracted %d stages + cleanup utility", len(killchain)))
	Endpoint.Say("")

	// Per-stage results for ES fan-out
	stageSeverity := "high"
	stageTactics := []string{"execution", "command-and-control", "defense-evasion", "persistence"}
	stageResults := make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{
			Technique: stage.Technique,
			Name:      stage.Name,
			Severity:  stageSeverity,
			Tactics:   stageTactics,
			ExitCode:  0,
			Status:    "skipped",
		}
	}

	Endpoint.Say("[*] Executing %d-stage attack killchain...", len(killchain))
	Endpoint.Say("")

	for idx, stage := range killchain {
		LogPhaseStart(stage.ID, fmt.Sprintf("%s (%s)", stage.Name, stage.Technique))
		Endpoint.Say("=================================================================")
		Endpoint.Say("Stage %d/%d: %s", stage.ID, len(killchain), stage.Name)
		Endpoint.Say("Technique: %s", stage.Technique)
		Endpoint.Say("Description: %s", stage.Description)
		Endpoint.Say("=================================================================")

		exitCode, timedOut := executeStage(stage, ls.port, sb)

		if timedOut {
			// Watchdog: stage hung and was force-terminated (v2.1 Tier-1 gate)
			stageResults[idx].ExitCode = 102
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("unexpected_hang: %s exceeded %ds watchdog", stage.Technique, STAGE_TIMEOUT_SECS)
			LogStageEnd(stage.ID, stage.Technique, "error", "unexpected_hang: watchdog force-terminated stage")
			LogMessage("ERROR", "Watchdog", fmt.Sprintf("Stage %d (%s) hung — force-terminated after %ds", stage.ID, stage.Technique, STAGE_TIMEOUT_SECS))

			ls.persistBeaconLog()
			runCleanup()
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
			SaveLog(Endpoint.TimeoutExceeded, fmt.Sprintf("stage %d (%s) hung and was terminated by watchdog", stage.ID, stage.Technique))
			Endpoint.Stop(Endpoint.TimeoutExceeded)
		}

		if exitCode == 126 || exitCode == 105 || exitCode == 127 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("protection stopped %s (exit code %d)", stage.Technique, exitCode)
			LogPhaseEnd(stage.ID, "blocked", fmt.Sprintf("protection stopped %s (exit %d)", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("=================================================================")
			Endpoint.Say("FINAL EVALUATION: Stage %d Stopped", stage.ID)
			Endpoint.Say("=================================================================")
			Endpoint.Say("✅ RESULT: PROTECTED")
			Endpoint.Say("  • Technique: %s  • Stage: %s  • Exit Code: %d", stage.Technique, stage.Name, exitCode)
			Endpoint.Say("  • Completed: %d/%d  • Stopped at: stage %d", stage.ID-1, len(killchain), stage.ID)

			ls.persistBeaconLog()
			writeSystemSnapshot("post")
			runCleanup()
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("protection stopped the chain at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			Endpoint.Stop(Endpoint.ExecutionPrevented)
		}

		if exitCode != 0 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("stage error: exit code %d", exitCode)
			LogPhaseEnd(stage.ID, "error", fmt.Sprintf("stage %s failed with exit code %d", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("❌ ERROR: Stage %d (%s) failed with exit code %d", stage.ID, stage.Technique, exitCode)
			Endpoint.Say("    (999 = prerequisite not met — review stage output log)")

			ls.persistBeaconLog()
			writeSystemSnapshot("post")
			runCleanup()
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("stage %d (%s) failed with exit code %d", stage.ID, stage.Technique, exitCode))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed without prevention", stage.Technique)
		LogPhaseEnd(stage.ID, "success", fmt.Sprintf("stage %s completed without prevention", stage.Technique))
		Endpoint.Say("    ✓ Stage %d completed", stage.ID)
		Endpoint.Say("")
	}

	// All stages completed — full chain succeeded
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: All Stages Completed")
	Endpoint.Say("=================================================================")
	Endpoint.Say("❌ RESULT: VULNERABLE")
	Endpoint.Say("")
	Endpoint.Say("Complete RedFlick delivery + CosmicPulse persistence chain executed")
	Endpoint.Say("without any protection layer stopping it:")
	for _, stage := range killchain {
		Endpoint.Say("  • Stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique)
	}
	Endpoint.Say("")
	Endpoint.Say("Security Impact: HIGH — persistent espionage backdoor chain")
	Endpoint.Say("=================================================================")

	ls.persistBeaconLog()
	writeSystemSnapshot("post")
	runCleanup()
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
	SaveLog(Endpoint.Unprotected, fmt.Sprintf("all %d stages completed — full RedFlick/CosmicPulse chain succeeded", len(killchain)))
	Endpoint.Stop(Endpoint.Unprotected)
}

// ==============================================================================
// HELPERS
// ==============================================================================

func extractStage(stage KillchainStage) error {
	return extractNamed(stage.BinaryName, stage.BinaryData)
}

func extractNamed(name string, compressed []byte) error {
	binaryData, err := decompressGzip(compressed)
	if err != nil {
		return fmt.Errorf("gzip decompression of %s failed: %v", name, err)
	}
	stagePath := filepath.Join(LOG_DIR, name)
	if err := os.WriteFile(stagePath, binaryData, 0755); err != nil {
		return fmt.Errorf("write of %s failed: %v", name, err)
	}
	LogFileDropped(name, stagePath, int64(len(binaryData)), false)
	return nil
}

func decompressGzip(compressed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// executeStage runs a stage binary under the per-stage watchdog with its
// stdout/stderr captured to both console and LOG_DIR/<binary>_output.txt
// (io.MultiWriter per framework stdout-capture rule). The loopback server
// port is handed to the stage via F0_LOOPBACK_PORT; the loopback SSH
// sandbox (realism lift 2) via F0_SSH_PORT / F0_SSH_KEY.
func executeStage(stage KillchainStage, port string, sb *sshSandbox) (exitCode int, timedOut bool) {
	stagePath := filepath.Join(LOG_DIR, stage.BinaryName)
	ctx, cancel := context.WithTimeout(context.Background(), STAGE_TIMEOUT_SECS*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, stagePath)
	cmd.Env = append(os.Environ(),
		"F0_LOOPBACK_PORT="+port,
		"F0_SSH_PORT="+sb.port,
		"F0_SSH_KEY="+sb.clientKey,
	)

	outputPath := filepath.Join(LOG_DIR, fmt.Sprintf("%s_output.txt", stage.BinaryName))
	outFile, err := os.Create(outputPath)
	if err != nil {
		outFile = nil
	} else {
		defer outFile.Close()
	}

	var buf bytes.Buffer
	if outFile != nil {
		cmd.Stdout = io.MultiWriter(os.Stdout, outFile, &buf)
		cmd.Stderr = io.MultiWriter(os.Stderr, outFile, &buf)
	} else {
		cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
		cmd.Stderr = io.MultiWriter(os.Stderr, &buf)
	}

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))

	runErr := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 102, "watchdog timeout")
		return 102, true
	}

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, code, exitErr.Error())
			return code, false
		}
		// Stage failed to launch at all (not an EDR action — infrastructure error)
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, runErr.Error())
		return 999, false
	}
	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0, false
}

// runCleanup executes the embedded cleanup utility to restore the endpoint on
// every exit path (v2.1 Tier-1 gate: cleanup on success, block, error, panic,
// and watchdog paths).
func runCleanup() {
	cleanupPath := filepath.Join(LOG_DIR, "cleanup_utility.exe")
	if _, err := os.Stat(cleanupPath); os.IsNotExist(err) {
		LogMessage("WARN", "Cleanup", "cleanup_utility.exe not extracted yet — nothing to run")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, cleanupPath).CombinedOutput()
	if err != nil {
		LogMessage("WARN", "Cleanup", fmt.Sprintf("cleanup utility reported: %v (output: %s)", err, string(out)))
	} else {
		LogMessage("INFO", "Cleanup", fmt.Sprintf("cleanup complete (%s)", firstLine(string(out))))
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

// writeSystemSnapshot records Defender status, AV exclusions and recent
// hotfixes to LOG_DIR/<uuid>_system_snapshot_<phase>.json (v2.1 3c telemetry).
// taskNameExists reports whether a scheduled task with the given name is
// already registered on the host.
func taskNameExists(taskName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "schtasks.exe", "/Query", "/TN", taskName).CombinedOutput()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(out))) > 0
}

func writeSystemSnapshot(phase string) {
	script := `$o = [ordered]@{}; ` +
		`try { $o['defender'] = Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,RealTimeProtectionEnabled,AntivirusEnabled,QuickScanEndTime | ConvertTo-Json -Compress } catch { $o['defender'] = $_.Exception.Message }; ` +
		`try { $o['avExclusions'] = (Get-MpPreference | Select-Object -ExpandProperty ExclusionPath) -join '; ' } catch { $o['avExclusions'] = $_.Exception.Message }; ` +
		`try { $o['hotfixes'] = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID,InstalledOn | ConvertTo-Json -Compress) } catch { $o['hotfixes'] = $_.Exception.Message }; ` +
		`$o['capturedAt'] = (Get-Date).ToUniversalTime().ToString('o'); $o | ConvertTo-Json -Compress`

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).Output()

	snapshotPath := filepath.Join(LOG_DIR, fmt.Sprintf("%s_system_snapshot_%s.json", TEST_UUID, phase))
	payload := bytes.TrimSpace(out)
	if err != nil || len(payload) == 0 {
		payload = []byte(fmt.Sprintf(`{"phase":%q,"error":"collection failed: %v"}`, phase, err))
	}
	if writeErr := os.WriteFile(snapshotPath, payload, 0644); writeErr != nil {
		LogMessage("WARN", "Snapshot", fmt.Sprintf("snapshot write failed (%s): %v", phase, writeErr))
		return
	}
	LogMessage("INFO", "Snapshot", fmt.Sprintf("system snapshot written: %s", snapshotPath))
}

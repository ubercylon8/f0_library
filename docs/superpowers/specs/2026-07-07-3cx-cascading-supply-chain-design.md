# Design: 3CX 3CXDesktopApp Cascading Supply-Chain Compromise

- **Test UUID:** `56475cb3-febc-45ac-a0af-39bc5ca1c15f`
- **Category:** intel-driven
- **Date:** 2026-07-07
- **Author:** sectest-builder (design brainstormed with user)
- **Status:** Approved design — pending implementation

## 1. Purpose

Help organizations understand whether their **AV/EDR detects a trojanized, validly-signed
vendor application** — the third-party software supply-chain risk. In the March 2023 3CX
breach (DPRK Lazarus / UNC4736), a legitimately code-signed VoIP desktop client
(`3CXDesktopApp`) was trojanized at the vendor's build pipeline and pushed to customers as
a normal update. It was the first widely-documented **cascading** supply-chain compromise:
one vendor's breach (Trading Technologies' X_TRADER) was used to breach 3CX, whose signed
product then breached 3CX's customers.

The detection challenge — and the point of this test — is that every artifact the endpoint
sees is *trusted*: a signed parent process, a normal-looking DLL, HTTPS to GitHub. The test
validates whether controls flag the **anomalous behavior of a trusted binary**, not whether
they block a known-bad hash.

## 2. Scope & Key Decisions (from brainstorming)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Threat anchor | **3CX 3CXDesktopApp (Lazarus/UNC4736)** | Richest, most-recognized cascading supply-chain chain; signature detail is ICO-file steganography. |
| Trusted signed binary | **F0RT1KA-signed orchestrator mimicking `3CXDesktopApp`** | We do NOT hold (and will not forge) 3CX's cert, and distributing the real trojanized binary is neither legal nor necessary. Our own cert plays 3CX's role — the "trusted signed app" premise holds. |
| Second-stage retrieval | **Simulated egress + embedded 2nd stage** | Real DNS + HTTP GET to a benign/controlled host shaped like the GitHub raw-ICO URL; the ICO-with-appended-AES-config payload is embedded and decoded locally to a benign config. Real network + stego-decode telemetry, no real payload pulled. |
| Browser data collection | **Decoys staged in ARTIFACT_DIR** | ICONIC-style stealer file-ops are exercised against decoy credential/history files — EDR sees the access pattern; no real user secret is ever read or transmitted. |
| Platform | **Windows only** | `win` lab = real Defender detonation. 3CX trojan was Windows/macOS; Windows is the primary detection target. |
| Architecture | **Multi-stage** (4 techniques beyond the supply-chain framing) | Orchestrator + 4 signed, gzip-embedded stage binaries. |

## 3. Architecture

Multi-stage pattern per `sample_tests/multistage_template/` and the modern 8-step
`build_all.sh` (build stages → sign → gzip → embed → sign orchestrator).

```
orchestrator (56475cb3…)  — F0RT1KA-signed, named to mimic 3CXDesktopApp
 ├── stage-T1574.002  — DLL side-loading (trusted app loads untrusted DLL)
 ├── stage-T1497      — sandbox / dormancy evasion (represents 7-day sleep)
 ├── stage-T1027.003  — steganographic C2 config retrieval + local decode
 └── stage-T1555.003  — ICONIC-style browser data collection (decoys)
```

### Stages

| Stage | MITRE | Behavior |
|-------|-------|----------|
| 1 — DLL side-loading | T1574.002 (DLL Side-Loading) | Signed orchestrator drops a companion DLL to a writable app-dir path and side-loads it — mirrors the real `d3dcompiler_47.dll` + `ffmpeg.dll` shellcode chain. Detonation signal: a signed parent loading a non-system DLL from a user-writable path. |
| 2 — Dormancy / sandbox evasion | T1497 (Virtualization/Sandbox Evasion) | Environment checks (VM artifacts, system uptime, domain-join state) representing the real 7-day dormancy. Actual delay compressed to seconds; the *intended* 7-day sleep is logged, not slept. |
| 3 — Steganographic C2 config | T1027.003 (Steganography), T1071.001 (Web Protocols) | Real DNS lookup + HTTPS GET to a benign/controlled host shaped like `raw.githubusercontent.com/.../<icon>.ico`. The ICO-with-appended-AES-encrypted-config second stage is **embedded**; the config is decoded/decrypted locally to a benign C2 descriptor. Produces genuine egress + stego-decode telemetry. |
| 4 — Browser data collection | T1555.003 (Credentials from Web Browsers), T1217 (Browser Information Discovery) | Enumerates browser credential-store / history artifact paths (Chrome/Edge/Brave/Firefox) and reads **decoys pre-staged in ARTIFACT_DIR**, copying them into the collection buffer. Exercises the ICONIC stealer access pattern with zero real-credential exposure. |

**Supply-chain framing technique:** T1195.002 (Compromise Software Supply Chain) — carried in
metadata; the chain itself is the four stages above.
**Tactics:** initial-access, defense-evasion, command-and-control, credential-access.
**Severity:** critical. **Complexity:** medium. **Target:** windows-endpoint.
**Threat actor:** Lazarus (UNC4736). **Subcategory:** supply-chain.

## 4. Result Classification (load-bearing logic)

Per CLAUDE.md Bug Prevention Rule 8, a block code is returned ONLY on positive evidence of a
protection action. Each stage classifies independently and the orchestrator aggregates.

| Outcome | Positive evidence required | Code |
|---------|----------------------------|------|
| Blocked | DLL side-load denied by an OS-emitted error on a load that normally succeeds; stego-decode/child process terminated mid-run; a staged artifact quarantined (confirmed via `time.Sleep(3s)` + `os.Stat`, not `Endpoint.Quarantined()`). | 126 `ExecutionPrevented` (or 105 on quarantine) |
| Unprotected | All four stages complete; no intervention observed. | 101 `Endpoint.Unprotected` |
| Test error | Prerequisites unmet (ARTIFACT_DIR not provisioned, decoys absent, embedded stage failed to extract). Ambiguous/benign failures land here — NEVER defaulted to a block code. | 999 `UnexpectedTestError` |

**Banned:** any `default: return StageBlocked` catch-all. Absence of stage success is not
evidence of a block.

## 5. Safety & Realism

- **No real 3CX binary, no real malware.** The orchestrator is our own signed code; the
  embedded "second stage" is a benign config blob; browser collection touches decoys only.
- **Egress is benign.** DNS/HTTP go to a controlled/benign host; nothing is downloaded that
  executes.
- **Cleanup.** Staged DLL, decoys, and collection buffer removed from ARTIFACT_DIR/LOG_DIR on
  completion.
- **Lab.** Deploy to `win` (Defender ON) for detonation evidence. Provision ARTIFACT_DIR
  (`c:\Users\fortika-test`) with decoys before the run; `LOG_DIR` (`C:\F0`) is self-created.

## 6. Deliverables (full artifact suite)

Required file set per CLAUDE.md (orchestrator `.go`, 4 `stage-*.go`, `test_logger.go` +
`test_logger_windows.go`, `org_resolver.go`, `go.mod`, `build_all.sh`, `README.md`,
`<uuid>_info.md`, `<uuid>_references.md`) **plus** RubricVersion **v2.1** scoring, the
detection suite (KQL / YARA / Sigma / Elastic EQL / LimaCharlie D&R), defense guidance +
hardening PS1 + IR playbook, and a kill-chain diagram (mandatory for multi-stage tests).

## 7. Build / Size Notes

Go-only multi-stage test with an embedded benign second stage → expected 🟢 Green
(≤10 MB). Gzip-embed pattern mandatory. No third-party binary embedded.

## 8. Implementation Path

Built via `@agent-sectest-builder` (framework-native builder). This spec is the input
contract; sectest-builder orchestrates documentation, detection-rule, and defense-guidance
sub-agents and produces the signed multi-stage binary.

# Lumma-Style Infostealer: Browser Credential Theft via Process Injection

| Field | Value |
|-------|-------|
| **UUID** | `26a8b54e-b51c-489d-beae-295e1eecc524` |
| **Category** | intel-driven / infostealer |
| **Severity** | high |
| **Platform** | windows-endpoint |
| **Architecture** | multi-stage (4 stage binaries + orchestrator) |
| **Threat Actor** | LummaC2 / Water Kurita (Lumma Stealer, MITRE S1213; Microsoft: Storm-2477) |
| **Complexity** | high |
| **Rubric** | v2.1 |

**Test Score**: **9.2/10**

## Overview

End-to-end emulation of the **Lumma Stealer (LummaC2 / Water Kurita)** MaaS infostealer
chain, authored as representative of the Lumma / StealC / Vidar infostealer class. The
test reproduces the full ClickFix ("fake CAPTCHA") kill chain documented by NCC Group,
Seqrite, Netskope, ESET, Gen Digital and Microsoft (2023–2026): clipboard poisoning →
hidden encoded PowerShell download cradle, `MicrosoftEdgeUpdate.exe` → `chrome.exe`
remote-thread injection and thread execution hijacking, the complete Chromium
credential-theft crypto chain (Local State → DPAPI → AES-256-GCM v10 → SQLite), wholesale
wallet/2FA/KeePass/Gecko collection including an App-Bound-Elevation COM attempt, and
exfiltration over the LummaC2 panel protocol (`TeslaBrowser/5.5` UA, `/c2sock` `act=live`
handshake, multipart upload). All four stages execute independently regardless of
individual outcomes (LockBit-pattern stage independence) so every technique is attempted
and reported per-stage.

## Kill Chain

| Stage | Objective | Primary Technique | Behaviors |
|-------|-----------|-------------------|-----------|
| 1 | ClickFix delivery | T1204.002 / T1059.001 | Campaign-shaped cradle string written to the **real clipboard** via `SetClipboardData` (saved + restored, user-approved lift), then executed as `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand` with a WebClient download cradle fetching a synthetic stager from a loopback receiver; secondary `mshta.exe http://` fetch variant for LOLBin telemetry |
| 2 | Process injection | T1055.003 | Stage copies itself as `lumma_inj\MicrosoftEdgeUpdate.exe` (injector) and `chrome.exe` (idle host) — the NCC-documented EdgeUpdate→chrome pattern on test-owned decoys. Full Win32 chain: `OpenProcess → VirtualAllocEx(RWX) → WriteProcessMemory → CreateRemoteThread` with hand-written PEB-walking marker shellcode; then literal thread execution hijacking: `OpenThread → SuspendThread → GetThreadContext → SetThreadContext(RIP=cave) → ResumeThread`. Injection verified via marker files created **inside** the decoy `chrome.exe`; positive-evidence-only classification |
| 3 | Browser credential theft | T1555.003 / T1555 | (a) Read-only recon of **real** Chrome/Edge `Local State` if present (metadata logged, bytes discarded, real key never unwrapped — user-approved lift); (b) synthetic decoy Chromium/Gecko/KeePass profile in `ARTIFACT_DIR` with real file names and canary credentials; full real crypto chain: `os_crypt.encrypted_key` → strip `DPAPI` prefix → `CryptUnprotectData` → AES-256-GCM v10 decryption of SQLite `Login Data` + `Network\Cookies`; wholesale collection of `KeePass.kdbx`, `key4.db`, `logins.json`, MetaMask-style wallet and 2FA extension dirs; (c) ABE attempt (user-approved lift): `CoCreateInstance` on the real Chrome elevation-service CLSID with `CoSetProxyBlanket` (dynamic cloaking) and `IElevator::DecryptData` (vtable slot 5) carrying a **synthetic** APPB blob |
| 4 | Collection & exfiltration | T1041 / T1005 / T1071.001 | Collects Stage 3's loot if present, else self-generates canary loot (stage independence); in-memory zip (`archive/zip`); loopback LummaC2 panel emulation with real protocol anchors: fingerprint GET probe first (Gen Digital Remus), `act=live` handshake POST (ESET), LID identifier + `J` parameter, multipart upload — all with `User-Agent: TeslaBrowser/5.5`; byte-counted verification |

## MITRE ATT&CK

- **Techniques**: T1204.002, T1059.001, T1055.003, T1555.003, T1555, T1005, T1041, T1071.001
- **Tactics**: execution, defense-evasion, credential-access, collection, exfiltration

## Build & Sign

```bash
cd tests_source/intel-driven/26a8b54e-b51c-489d-beae-295e1eecc524
./build_all.sh              # default: F0RT1KA-cert signing
./build_all.sh --org sb     # dual-sign SB + F0RT1KA (only on request)
```

8-step modern build: stage builds (`-s -w`) → sign stages (fail-loud) → verify signatures
→ gzip-compress → orchestrator embed → sign orchestrator → SHA1 → cleanup.
Output: `build/26a8b54e-b51c-489d-beae-295e1eecc524/26a8b54e-b51c-489d-beae-295e1eecc524.exe`
(≈14.0 MB, Yellow tier — see info card Size Justification).

## Expected Results

| Exit | Meaning |
|------|---------|
| 101 | All 4 stages succeeded — endpoint unprotected against the full infostealer chain |
| 126 | At least one stage blocked with positive evidence — a critical protection layer fired |
| 105/127 | A stage binary quarantined on extraction/execution |
| 999 | Test error (prerequisite missing / inconclusive) — investigate output logs |

All stages execute regardless of individual outcomes; only extraction failure aborts.
Per-stage results are written to `C:\F0\bundle_results.json` for per-stage Elasticsearch
fan-out. Block classification is positive-evidence-only (Bug Prevention Rule 8): OS-emitted
denials on test-owned decoy objects, quarantine via `os.Stat`, numeric launch-failure

**Lab validation (2026-11-02, `win` — Windows 11 Pro, CrowdStrike Falcon active, Defender
passive):** exit **101 (VULNERABLE)** — all 4 stages executed without prevention. Stage 2's
remote-thread and thread-hijack markers both verified (code execution inside the decoy
`chrome.exe`), Stage 3's DPAPI→AES-GCM canary round-trip verified, Stage 4 received the
harvest byte-for-byte. Per-stage detail in the info card's Lab Evidence section.
errnos, or external termination of the idle decoy host.

## Detection Rules

Five formats included: KQL (`_detections.kql`), YARA (`_rules.yar`), Sigma
(`_sigma_rules.yml`), Elastic EQL (`_elastic_rules.ndjson`), LimaCharlie D&R
(`_dr_rules.yaml`). Rules are technique-focused — they detect real Lumma/infostealer
tradecraft (encoded PowerShell cradles, remote-thread injection into browser-named
processes, DPAPI unwrap of browser keys, elevation-service COM abuse, `TeslaBrowser/5.5`
C2 traffic), not this harness.

## Defense

- `26a8b54e-b51c-489d-beae-295e1eecc524_DEFENSE_GUIDANCE.md` — consolidated hardening + IR playbook
- `26a8b54e-b51c-489d-beae-295e1eecc524_hardening.ps1` — idempotent Windows hardening script with `-WhatIf`/`-Undo`

## Safety & Containment

Loopback-only egress everywhere (receivers bound to `127.0.0.1`, URLs derived from the
listener — external egress impossible by construction); decoy/canary data only (SSA-reserved
SSN range, test-BIN PAN, `.example.test`/`.invalid` identifiers, run-unique markers); the
real clipboard is saved and restored; **no real browser process is ever touched** (injection
targets test-owned decoys named after the adversary pattern); the real browser key is
**never** unwrapped or exfiltrated (read-only Local State recon logs metadata only); the
ABE COM call carries a synthetic blob, never real key material. Two user-approved realism
lifts (2026-11-02) are documented in the info card's containment matrix, and the stage-2
residue gap found during review was remediated pre-ship. See the info card
for the full containment matrix.

## References

See `26a8b54e-b51c-489d-beae-295e1eecc524_references.md` — primary source: NCC Group
"Fake CAPTCHA led to Lumma" (2026), plus ESET's Lumma C2-protocol teardown, Gen Digital
Remus research, Microsoft, Netskope, Seqrite, Darktrace, Picus Red Report 2025, MITRE
S1213 and the xaitax ABE research.

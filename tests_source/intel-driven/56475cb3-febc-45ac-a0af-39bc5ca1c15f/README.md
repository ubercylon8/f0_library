# 3CX 3CXDesktopApp Cascading Supply-Chain Compromise

**Test UUID**: `56475cb3-febc-45ac-a0af-39bc5ca1c15f`
**Category**: intel-driven / supply-chain
**Platform**: windows-endpoint
**Techniques**: T1195.002 (Compromise Software Supply Chain), T1574.002 (DLL Side-Loading), T1497 (Virtualization/Sandbox Evasion), T1027.003 (Steganography), T1071.001 (Web Protocols), T1555.003 (Credentials from Web Browsers)
**Tactics**: initial-access, defense-evasion, command-and-control, credential-access
**Severity**: critical
**Threat actor**: Lazarus / UNC4736 (DPRK)
**Rubric version**: v2.1 (tiered, realism-first; signal-quality-not-tenant-defense)

**Test Score**: **7.6/10**

> Not yet lab-detonated — Telemetry Signal Quality (2c) is capped at 1.5/2.0 per the v2.1 no-lab-evidence rule until this test is run end-to-end on an instrumented sensor stack. See `56475cb3-febc-45ac-a0af-39bc5ca1c15f_info.md` for the full Score Breakdown and Improvement Opportunities that would lift this score.

## Overview

This test recreates the 2023 **3CX 3CXDesktopApp** cascading supply-chain compromise (tracked by Mandiant as the work of **UNC4736 / Lazarus Group**, DPRK) — the first publicly documented case of one supply-chain compromise (the trojanized X_TRADER software) cascading into a second (the 3CX VoIP desktop client). The test is a 4-stage kill chain that reproduces the observable primitives of each phase: a trusted, validly-signed vendor application side-loading an untrusted companion DLL; sandbox/dormancy evasion; retrieval and decode of a steganographic (ICO-appended) AES-encrypted C2 configuration over real HTTPS to a GitHub CDN; and ICONIC-style browser credential-store collection.

All destructive or sensitive primitives are replaced with safe stand-ins: a benign Microsoft-signed binary plays the role of `3CXDesktopApp.exe`, companion DLLs are benign marker files, the "C2 config" is a locally-generated benign JSON descriptor never used to contact anything, and browser credential stores are pre-staged decoys — never real user data. Real, benign DNS + HTTPS egress to `raw.githubusercontent.com` (the actual 3CX IOC domain) is performed to produce authentic network telemetry; the response body is discarded and never used as a payload.

## MITRE ATT&CK Mapping

- **Tactic**: Initial Access, Defense Evasion, Command and Control, Credential Access
- **Technique**: T1195.002 - Compromise Software Supply Chain
- **Technique**: T1574.002 - Hijack Execution Flow: DLL Side-Loading
- **Technique**: T1497 - Virtualization/Sandbox Evasion
- **Technique**: T1027.003 - Obfuscated Files or Information: Steganography
- **Technique**: T1071.001 - Application Layer Protocol: Web Protocols
- **Technique**: T1555.003 - Credentials from Password Stores: Credentials from Web Browsers

## Test Execution

Simulates the 4-stage 3CX cascading supply-chain kill chain to evaluate defensive capabilities against each observable phase independently:

| Stage | Technique | What happens |
|-------|-----------|---------------|
| 1 | T1574.002 | A signed `3CXDesktopApp.exe` (a copy of the F0RT1KA-signed stage binary) is staged in `ARTIFACT_DIR` alongside real, benign Microsoft-signed DLLs planted under the 3CX companion names (`d3dcompiler_47.dll`, `ffmpeg.dll`), then relaunched in host mode where it `LoadLibrary`s them from its own directory — emitting a genuine side-load image-load event. |
| 2 | T1497 | Read-only VM-artifact (BIOS/disk/guest-service registry), CPU-count, uptime (`GetTickCount64`), and domain-join checks. The real implant's 7-day dormancy is logged as intended but compressed to seconds. |
| 3 | T1027.003 + T1071.001 | Real DNS lookup + HTTPS GET shaped like `https://raw.githubusercontent.com/IconStorages/images/main/icon0.ico` (body discarded). A real on-disk `.ico` is built locally with a valid ICONDIR/ICONDIRENTRY header plus AES-256-CBC ciphertext appended after the icon image, then decoded/decrypted to a benign C2 descriptor. |
| 4 | T1555.003 (+T1217) | Decoy Chrome/Edge/Brave/Firefox credential and history stores are staged under `ARTIFACT_DIR` in the real relative layout, then enumerated and copied to a collection buffer — mirroring the ICONIC stealer's access pattern. Real profile paths are logged as discovery targets but never opened. |

Exit-code discipline follows Bug Prevention Rule 8: every stage classifies "blocked" (126/105) only on positive evidence (a confirmed quarantine via `os.Stat`, or an OS-emitted access denial on an operation that normally succeeds); ambiguous, benign, or prerequisite failures map to 999, never to a block code.

## Expected Outcomes

- **Protected**: EDR/AV detects and blocks the technique at some stage in the kill chain — the orchestrator reports which stage was blocked and halts the remaining stages
- **Unprotected**: All 4 stages complete successfully — the full cascading supply-chain chain executes without prevention

## Size Justification

Final orchestrator: **13.62 MB** (Yellow tier, 10-25 MB). See `## Size Justification` in `56475cb3-febc-45ac-a0af-39bc5ca1c15f_info.md` for the full breakdown.

## Build Instructions

```bash
# Build single self-contained binary
./tests_source/intel-driven/56475cb3-febc-45ac-a0af-39bc5ca1c15f/build_all.sh

# Or manually:
./utils/gobuild build tests_source/intel-driven/56475cb3-febc-45ac-a0af-39bc5ca1c15f/
./utils/codesign sign build/56475cb3-febc-45ac-a0af-39bc5ca1c15f/56475cb3-febc-45ac-a0af-39bc5ca1c15f.exe
```

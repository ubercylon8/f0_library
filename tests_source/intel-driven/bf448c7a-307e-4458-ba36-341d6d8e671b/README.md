# TclBanker Brazilian Banking Trojan Full Killchain

**Test UUID**: `bf448c7a-307e-4458-ba36-341d6d8e671b`
**Test Score**: **9.25/10**
**Rubric**: v2.1 (Signal Quality — Tiered Realism-First)
**Architecture**: Multi-stage (6 stages, gzip-compressed)
**Platform**: Windows endpoint
**Threat Actor**: TclBanker (Brazilian banking trojan family)
**Source**: [Elastic Security Labs — TclBanker: A Brazilian Banking Trojan](https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan)

## Overview

End-to-end killchain simulation of TclBanker, a .NET-based Brazilian banking trojan
that masquerades as a signed Logitech update. The test exercises the full intrusion
path — MSI delivery, DLL sideloading via a renamed Microsoft binary, AES-decrypted
.NET payload + Brazilian locale gate, COM-based persistence via the
`RuntimeOptimizeService` scheduled task, WPF-style overlay + UI Automation polling
of browser address bars, and Cloudflare Workers C2 with HMAC-SHA256-signed
WebSocket handshakes.

The test is designed to produce real telemetry on the exact identifiers Elastic
observed in the wild — task name, CLSID, campaign GUID, Cloudflare account ID,
install-path shape, file-name shapes — so detection rules written against
TclBanker indicators fire against this test.

## Killchain (6 Stages)

| # | Stage | MITRE Techniques | Realism Lift |
|---|-------|------------------|--------------|
| 1 | Delivery — `Logitech_Update_*.msi` in ZIP | T1218.007 + T1566.001 | MSI shape + CFB header + ZIP wrapper |
| 2 | DLL Side-Loading — `screen_retriever_plugin.dll` via `LogiAiPromptBuilder.exe` | T1574.002 | **LIFT 1: real `LoadLibraryW`** on renamed Microsoft `version.dll` |
| 3 | Deobfuscate + Brazilian Locale Gate | T1140 + T1027 + T1497.001 + T1497.003 | AES-256-CBC + `GetUserDefaultUILanguage` + QPC timing |
| 4 | Persistence — `RuntimeOptimizeService` COM Task | T1053.005 | **LIFT 2: real `CoCreateInstance(CLSID_TaskScheduler)`** + XML registration + triple cleanup |
| 5 | Overlay + Browser Address-Bar Monitoring | T1056.003 + T1010 + T1185 | Real overlay window + `CoCreateInstance(CUIAutomation)` + brief no-data `WH_KEYBOARD_LL` hook |
| 6 | C2 Beacon — Cloudflare Workers `ef971a42` | T1071.001 + T1102 | DNS observation for `*.workers.dev` + loopback WebSocket handshake with real HMAC-SHA256 bearer |

## Real Identifiers Used (Detection Fidelity)

These come from the Elastic article and are baked into the binary verbatim:

- Task name: `RuntimeOptimizeService`
- Task Scheduler CLSID: `0F87369F-A4E5-4CFC-BD3E-73E6154572DD`
- Campaign GUID: `70e4f943-e323-4484-97d7-35401bf6812c`
- Cloudflare Workers account: `ef971a42`
- DLL filename: `screen_retriever_plugin.dll`
- Host EXE name: `LogiAiPromptBuilder.exe`
- Install-path shape: `%LocalAppData%\LogiAI\`
- WebSocket path: `/ws`
- Portuguese vishing string: `Estamos entrando em contato`
- MSI prefix: `Logitech_Update_*.msi`
- Debug-artifact path (logged as string): `C:\temp\tcl-debug.txt`

## Safety Posture

All writes routed through `c:\F0` (LOG_DIR) and `c:\Users\fortika-test` (ARTIFACT_DIR)
per CLAUDE.md rules 1 + 2. No network egress beyond DNS lookup + 127.0.0.1 loopback.
The scheduled task action targets a benign `cmd /c echo` to a file in LOG_DIR — even
if cleanup leaks, the worst outcome is a logon-trigger task writing one line to disk.
Triple cleanup: deferred deletion + watchdog goroutine + final `schtasks /delete`
fallback. Sandbox sideload host EXE and renamed DLL deleted on stage exit. Overlay
window is non-modal, auto-dismiss within 3 seconds, watermarked "F0RT1KA TEST", and
WDA_EXCLUDEFROMCAPTURE-protected. Keyboard hook installed for under 500 ms with the
callback explicitly ignoring `KBDLLHOOKSTRUCT` (no key data captured, logged, or
persisted). Sideloaded DLL is an unmodified copy of Microsoft `version.dll` (the
real signed binary) — what's suspicious is the renamed pair pattern, not the DLL
contents.

## Build

```bash
./build_all.sh
# Output: build/bf448c7a-307e-4458-ba36-341d6d8e671b/bf448c7a-307e-4458-ba36-341d6d8e671b.exe
```

Final binary: ~10 MB (GREEN tier per CLAUDE.md Binary Size Budget).

## Scoring (Rubric v2.1)

| Dimension | Weight | Score |
|-----------|--------|-------|
| **Tier 1: Safety Gate** | pass/fail | PASS |
| **Tier 2: Realism (7.0)** | | **6.75** |
| — API Fidelity (2.5) | | 2.5 |
| — Identifier Fidelity (1.5) | | 1.5 |
| — Telemetry Signal Quality (2.0) | | 1.75 |
| — Execution-Context Fidelity (1.0) | | 1.0 |
| **Tier 3: Structure (3.0)** | | **2.5** |
| — Schema Compliance (1.0) | | 1.0 |
| — Docs (1.0) | | 1.0 |
| — Logging (0.5) | | 0.5 |
| — Operational Hygiene (0.5) | | 0.0 (capped — no lab evidence yet) |
| **Total** | | **9.25** |

Why not 10: 0.25 deducted from telemetry signal quality (rules authored but not yet
fired in a lab tenant), 0.5 deducted from operational hygiene (no production-lab
deployment evidence yet — see v2.1 lab-bound observability schema).

## Files

- `bf448c7a-307e-4458-ba36-341d6d8e671b.go` — Main orchestrator
- `stage-T*.go` — 6 stage source files
- `sideload_host/main.go` — Sandbox `LogiAiPromptBuilder.exe` source (LIFT 1)
- `build_all.sh` — 8-step build with sign + gzip + tier check
- `test_logger.go`, `test_logger_windows.go`, `org_resolver.go` — Schema v2.0 logger
- `bf448c7a-307e-4458-ba36-341d6d8e671b_info.md` — Detailed info card
- `bf448c7a-307e-4458-ba36-341d6d8e671b_references.md` — Source provenance

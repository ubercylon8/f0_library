# BlueHammer Early-Stage Behavioral Pattern (Nightmare-Eclipse)

**Test UUID**: `5e59dd6a-6c87-4377-942c-ea9b5e054cb9`
**Category**: intel-driven / apt
**Platform**: windows-endpoint
**Techniques**: T1211 (Exploitation for Defense Evasion), T1562.001 (Impair Defenses), T1003.002 (OS Credential Dumping: SAM), T1134.001 (Token Manipulation: Token Impersonation/Theft)
**Tactics**: defense-evasion, credential-access, privilege-escalation
**Severity**: high
**Threat actor**: Nightmare-Eclipse (BlueHammer PoC, 2026)
**Rubric version**: v2 (tiered, realism-first)

**Test Score**: **7.0/10**

> Pre-lab cap. v2's Detection-Rule Firing Fidelity is capped at 0.5 until lab evidence lands. Post-lab projection: **9.2/10** assuming ≥80% rule firing.

## Overview

This test exercises the **observable API surface of BlueHammer's full kill-chain primitives** — including the SAM-hive read API surface that BlueHammer's PoC ultimately uses, but executed against a **synthetic sandbox hive** rather than any real Windows hive. Defenders can measure EDR/AV detection coverage on every primitive BlueHammer touches, with strict safety guarantees ensuring no real credential material is ever accessed.

All operations target a sandbox directory under `C:\Users\fortika-test\BlueHammerSandbox\` (the F0RT1KA non-whitelisted artifact dir) — no system-sensitive path is ever touched.

## What the test simulates

| Stage | Technique | Primitive |
|-------|-----------|-----------|
| 1 | T1211 | `CfRegisterSyncRoot` with non-vendor provider + `CfConnectSyncRoot` with `CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS` callback + Mimikatz-named EICAR drop |
| 2 | T1562.001 | `DeviceIoControl(FSCTL_REQUEST_BATCH_OPLOCK)` on a sandbox file, released within 5s |
| 3 | T1211 | `NtOpenDirectoryObject(\Device)` enumeration + WMI Win32_ShadowCopy enum + `CreateFileTransactedW` against sandbox |
| 4 | T1003.002 + T1134.001 | `AdjustTokenPrivileges` (SeBackup/SeRestore) telemetry + synthetic SAM-hive load via `RegLoadKey` + `RegOpenKeyEx` (Admin only; sandbox hive only; watchdog-protected) |

## What the test does NOT do (hard safety boundaries)

The test never:

- Opens, reads, copies, or parses **any real SAM, SECURITY, or SYSTEM hive**
- Loads any real registry hive — stage 4 only loads a **synthetic sandbox hive** generated at runtime via `RegSaveKey`
- Opens any file on a VSS shadow-copy path (stages enumerate VSS but never open shadows)
- Calls `Win32_ShadowCopy.Create()` or `.Delete()` (stage 3B is enumeration-only via `Get-WmiObject`)
- Loads or uses `offreg` or `samlib.dll`
- Reads, parses, decrypts, or derives any credential material
- Calls any user-account modification API
- Duplicates tokens or impersonates other accounts
- Calls `CreateService`, `StartService`, or spawns processes in another session
- Actually freezes Defender (oplock always released within 5s)
- Downloads any real Defender definition update

**Stage 4 safety guarantees** are particularly strict — see the info card for the full list (synthetic hive, unique mount name, watchdog goroutine, defer-driven cleanup, standard-user short-circuit).

## Architecture

Multi-stage (4 techniques). Each stage is compiled and signed independently, gzip-compressed, and embedded in the main orchestrator.

```
<uuid>.go                       — orchestrator (with X1 system-snapshot helpers)
stage-T1211-cfapi.go            — Stage 1: Cloud Files + Mimikatz-named EICAR
stage-T1562.001-oplock.go       — Stage 2: Batch oplock on sandbox file
stage-T1211-vssenum.go          — Stage 3: NT enum + WMI Win32_ShadowCopy enum + transacted-open
stage-T1003.002-samsim.go       — Stage 4: Privilege-enable + synthetic SAM-hive load (sandbox-only)
```

## Exit codes

- **101** — all four primitives executed without EDR detection (UNPROTECTED)
- **126** — EDR blocked the test at one of the four stages (PROTECTED)
- **999** — prerequisites not met (e.g., Cloud Files API unavailable on the SKU)

Stage 4 short-circuits with a clean success on standard-user execution (privilege-denial telemetry is the value; no hive load attempted).

## Build

```bash
./build_all.sh                 # unsigned
./build_all.sh --org sb        # signed with org cert
```

Output: `build/5e59dd6a-6c87-4377-942c-ea9b5e054cb9/5e59dd6a-6c87-4377-942c-ea9b5e054cb9.exe`

## Score breakdown (Rubric v2)

| Tier | Sub-dimension | Score | Notes |
|------|---------------|-------|-------|
| 1 | Safety Gate | PASS | Synthetic sandbox hive only, watchdog, sandbox writes only, no service start/stop |
| 2a | API Fidelity | 2.7/3 | Stages 1, 2, 4 mirror PoC API sequence exactly; stage 3B uses PowerShell wrapper for WMI (justified deviation) |
| 2b | Identifier Fidelity | 1.5/2 | Mimikatz-named EICAR + uniquely-named hive mount; Defender path identifiers not yet runtime-extracted |
| 2c | Detection Firing | **0.5 (cap)** | Pre-lab; post-lab projection ≥1.5 with rule cross-reference |
| 3a | Schema & Metadata | 1.0/1 | RubricVersion: v2; full TestMetadata; signed |
| 3b | Documentation | 1.0/1 | README + info.md scorecard + references.md |
| 3c | Logging & Plumbing | 1.0/1 | test_logger v2 + per-stage bundles + pre/post system snapshots |
| | **Total (capped)** | **7.0/10** | Realism: 4.7/7. Structure: 3.0/3. **Post-lab projection: 9.2/10**. |

## Lift history

- **2026-04-24**: v1.0 (score 9.0/10 under v1 rubric) — stages 1–3 only
- **2026-04-25**: v2.0 — added stage 4 (T1003.002 SAM-sim) per lift items B4+B5; B2 (Mimikatz-named EICAR drop), B3 (WMI shadow enum), X1 (system snapshots) applied. Re-scored under realism-first rubric v2.

## Reference

- PoC source: <https://github.com/Nightmare-Eclipse/BlueHammer>
- Phase walkthrough: see `5e59dd6a-6c87-4377-942c-ea9b5e054cb9_references.md`
- Score-lift analysis: `docs/SCORE_LIFT_ANALYSIS_NIGHTMARE_ECLIPSE_2026-04-24.md`
- Rubric definition: `docs/PROPOSED_RUBRIC_V2_REALISM_FIRST.md` and `.claude/agents/sectest-documentation.md`

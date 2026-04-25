# Nightmare-Eclipse RedSun Cloud Files Rewrite Primitive Chain

**UUID**: `0d7e7571-45e2-426a-ac8e-bdb000439761`
**Category**: `intel-driven`
**Target**: `windows-endpoint`
**Threat Actor**: Nightmare-Eclipse (RedSun PoC, 2026)
**Severity**: high
**Architecture**: multi-stage (4 stages)
**Rubric version**: v2.1 (tiered, realism-first; signal-quality-not-tenant-defense)

**Test Score**: **8.7/10**

> Lab-verified 2026-04-25 — all 4 stages reached, exit 101 (107 s wallclock, 79.5 s execution; R1-R5 all uncontested). Context-independent by design (T1574/T1006/T1559.001 not privilege-bounded), which keeps 2d Execution-Context Fidelity at 0.5/1.

## Purpose

This test gives EDR/AV products a safe, controlled workload that exercises the
same API surface as the Nightmare-Eclipse RedSun PoC, including the COM-broker
activation primitive that's central to RedSun's file-replacement chain.

It does **not** reproduce the end-to-end exploit — no privilege escalation
occurs, no real Windows system files are touched, no service is started.
Stage 4's COM activation has a **hard pre-check guard** that aborts without
activation if `TieringEngineService` is in any state other than `STOPPED`,
preventing inadvertent service-start behavior on systems where it's already
running.

What it does do is invoke each observable primitive the real PoC chains
together, against sandboxed targets under `c:\Users\fortika-test\RedSunSandbox\`,
so defenders can measure their detection coverage for:

- Non-OneDrive Cloud Files sync-root registration (`CfRegisterSyncRoot`)
- EICAR test-string drop in a cloud-synced directory
- `\Device` object-manager enumeration (`NtOpenDirectoryObject` / `NtQueryDirectoryObject`) filtered for `HarddiskVolumeShadowCopy*`
- Batch oplock request (`FSCTL_REQUEST_BATCH_OPLOCK`) on a sandbox file
- Mount-point reparse-point creation (`FSCTL_SET_REPARSE_POINT`) — sandbox to sandbox
- Reparse-point read-back (`FSCTL_GET_REPARSE_POINT`) — **v2 R3**
- Pre-race file-info probe (`NtQueryInformationFile(FileStandardInformation)`) — **v2 R4**
- `FILE_SUPERSEDE` / `CREATE_ALWAYS` race loop against a sandbox target file
- TieringEngineService state query + COM activation against the CFAPI Sync Root Manager broker CLSID (`{829BD7DA-5F60-4B8B-A82C-C7B4DF0E2DB8}`) — **v2 R5**, **only fires when service is STOPPED**

## Stages

| # | Technique | Name | Primitive |
|---|-----------|------|-----------|
| 1 | T1211 | Cloud Files Sync Root + EICAR Provocation | `CfRegisterSyncRoot` with provider `F0RT1KA-REDSUNSIM`; drop EICAR; unregister |
| 2 | T1006 | VSS Device Enumeration + Batch Oplock | `\Device` enumeration filtered for `HarddiskVolumeShadowCopy*`; `FSCTL_REQUEST_BATCH_OPLOCK` on sandbox file |
| 3 | T1574 | Reparse + Read-Back + Pre-Race Probe + FILE_SUPERSEDE | `FSCTL_SET_REPARSE_POINT` (sandbox→sandbox) + **`FSCTL_GET_REPARSE_POINT` read-back** + **`NtQueryInformationFile(FileStandardInformation)` probe** + `CREATE_ALWAYS` race loop |
| 4 | T1559.001 | TieringEngineService Pre-Check + CFAPI Broker COM Activation | `sc.exe query TieringEngineService` — only proceeds if STOPPED. Then `CoInitializeEx + CoCreateInstance(CLSCTX_LOCAL_SERVER, CFAPI broker CLSID, IID_IUnknown)` — activation telemetry only. Post-activation safety check verifies state didn't change. |

## MITRE ATT&CK Mapping

- **T1211 — Exploitation for Defense Evasion** (stages 1, 2): Cloud Files API abuse + VSS reconnaissance.
- **T1006 — Direct Volume Access** (stage 2): `\Device` enumeration + batch oplock on a sandbox file mirrors the PoC's VSS-attack surface.
- **T1574 — Hijack Execution Flow** (stage 3): Mount-point reparse + supersede race is the hijack mechanism in the PoC.
- **T1559.001 — Inter-Process Communication: Component Object Model** (stage 4 — new in v2): The `CoCreateInstance` call against the CFAPI Sync Root Manager broker is the IPC primitive RedSun uses to trigger the broker-mediated rewrite.

## Safety Boundaries (Tier 1 v2 Gate)

- All writes confined to `LOG_DIR` / `ARTIFACT_DIR`
- Reparse targets always inside `ARTIFACT_DIR`; never reference real system paths
- All oplocks / reparse-points / handles released within the same stage function
- Stage 4 `CoCreateInstance` only fires when `TieringEngineService` reports `STOPPED`; refuses to drive service-start behavior
- Post-activation safety check verifies `TieringEngineService` state didn't change
- No service start/stop ever attempted by the test
- No network egress; no privilege escalation

## Architecture

Multi-stage (4 stages, gzip-compressed embedded binaries).

```
<uuid>.go                       — orchestrator (with X1 system-snapshot helpers)
stage-T1211.go                  — Stage 1: Cloud Files + EICAR
stage-T1006.go                  — Stage 2: VSS device enum + batch oplock
stage-T1574.go                  — Stage 3: Reparse + read-back + NtQuery probe + supersede race
stage-T1559.001-com.go          — Stage 4: CFAPI broker COM activation w/ pre-check guard (NEW in v2)
```

## Score breakdown (Rubric v2)

| Tier | Sub-dimension | Score | Notes |
|------|---------------|-------|-------|
| 1 | Safety Gate | PASS | Sandbox-only writes, reparse hard boundary, TieringEngine pre-check |
| 2a | API Fidelity | 2.7/3 | All 4 stages mirror the PoC API sequence |
| 2b | Identifier Fidelity | 1.5/2 | Real CFAPI CLSID + real service name; sandbox file-name still generic |
| 2c | Detection Firing | **0.5 (cap)** | Pre-lab; post-lab projection ≥1.5 |
| 3a | Schema & Metadata | 1.0/1 | RubricVersion: v2; all metadata-header fields present |
| 3b | Documentation | 1.0/1 | README + info.md scorecard + references |
| 3c | Logging & Plumbing | 1.0/1 | test_logger v2 + per-stage bundles + pre/post system snapshots (incl. TieringEngine state) |
| | **Total (capped)** | **7.0/10** | Realism: 4.7/7. Structure: 3.0/3. **Post-lab projection: 9.0/10**. |

## Lift history

- **2026-04-24**: v1.0 (score 8.4/10 under v1 rubric) — stages 1–3
- **2026-04-25**: v2.0 — added stage 4 (T1559.001 COM activation w/ pre-check guard) per R5 lift; R3 (reparse read-back), R4 (NtQuery pre-race probe), X1 (system snapshots) applied. Re-scored under realism-first rubric v2.

## Build & Run

```bash
cd tests_source/intel-driven/0d7e7571-45e2-426a-ac8e-bdb000439761/
./build_all.sh                 # unsigned
./build_all.sh --org sb        # signed with org cert
```

Output: `build/0d7e7571-45e2-426a-ac8e-bdb000439761/0d7e7571-45e2-426a-ac8e-bdb000439761.exe`

## Exit Codes

- **101** — all four primitives executed without EDR detection (UNPROTECTED)
- **126** — EDR blocked the test at one of the four stages (PROTECTED)
- **105** — a stage binary was quarantined on extraction
- **999** — prerequisite failure (e.g., Cloud Files feature not installed)

Stage 4 short-circuits with success code 0 if `TieringEngineService` is in any state other than `STOPPED` — the pre-check guard fires before any COM activation. State-query telemetry is the value of the stage in that case.

## Reference

- PoC source: <https://github.com/Nightmare-Eclipse/RedSun>
- See `0d7e7571-45e2-426a-ac8e-bdb000439761_references.md` for primitive-to-PoC line-level mapping
- Score-lift analysis: `docs/SCORE_LIFT_ANALYSIS_NIGHTMARE_ECLIPSE_2026-04-24.md`
- Rubric definition: `docs/PROPOSED_RUBRIC_V2_REALISM_FIRST.md` and `.claude/agents/sectest-documentation.md`

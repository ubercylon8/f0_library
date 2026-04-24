# BlueHammer Early-Stage Behavioral Pattern (Nightmare-Eclipse)

**Test UUID**: `5e59dd6a-6c87-4377-942c-ea9b5e054cb9`
**Category**: intel-driven / apt
**Platform**: windows-endpoint
**Techniques**: T1211 (Exploitation for Defense Evasion), T1562.001 (Impair Defenses: Disable or Modify Tools)
**Tactics**: defense-evasion
**Severity**: high
**Threat actor**: Nightmare-Eclipse (BlueHammer PoC, 2026)

**Test Score**: **9.0/10**

## Overview

This test exercises the **observable API surface** of BlueHammer's initial phases (1-3) so defenders can measure EDR/AV detection coverage on the detectable primitives of the technique — BEFORE the damaging credential-access phases occur. It is a detection-opportunity test, not a credential-theft exploit.

The primitives exercised are a distinctive behavioral fingerprint that an EDR can use to stop the full attack chain early. All operations target a sandbox directory under `C:\Users\fortika-test\BlueHammerSandbox\` (the F0RT1KA non-whitelisted artifact dir) — no system-sensitive path is ever touched.

## What the test simulates

| Stage | Technique | Primitive |
|-------|-----------|-----------|
| 1 | T1211 | `CfRegisterSyncRoot` with a non-standard provider (`F0RT1KA-BLUEHAMMER-SIM`) + `CfConnectSyncRoot` with `CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS` callback + EICAR drop in sandbox |
| 2 | T1562.001 | `DeviceIoControl(FSCTL_REQUEST_BATCH_OPLOCK)` on a benign sandbox file, released within 5 seconds regardless of whether the oplock fires |
| 3 | T1211 | `NtOpenDirectoryObject(\Device)` + enumeration of `HarddiskVolumeShadowCopy*` entries (read-only, nothing opened) + `CreateTransaction` + `CreateFileTransactedW` against a benign sandbox file |

## What the test does NOT do (hard boundaries)

The test stops at exercising the observable primitives. It **never**:

- Opens a handle to the SAM hive or any file under `\Windows\System32\Config\`
- Opens any file on a VSS shadow-copy path
- Loads or uses `offreg` or `samlib.dll`
- Reads `SAM\Domains\Account` or `SYSTEM\CurrentControlSet\Control\Lsa` for decryption purposes
- Attempts to read, parse, decrypt, or derive any credential (NTLM, password hash, boot key)
- Calls any user-account modification API or changes any password via any API
- Calls `LogonUserEx`, duplicates tokens, changes session IDs, or enables `SE_TCB_NAME`, `SE_ASSIGNPRIMARYTOKEN_NAME`, `SE_IMPERSONATE_NAME`, `SE_DEBUG_NAME`
- Calls `CreateService`, `StartService`, or spawns processes in another session
- Actually freezes Defender — the oplock is always released within 5 seconds
- Downloads the real Defender definition update (the update URL is referenced in the info card only)

## Architecture

Multi-stage (3 techniques ≥ threshold). Each stage is compiled and signed independently, gzip-compressed, and embedded in the main orchestrator.

```
<uuid>.go                    — orchestrator
stage-T1211-cfapi.go         — Stage 1: Cloud Files + EICAR
stage-T1562.001-oplock.go    — Stage 2: Batch oplock on sandbox file
stage-T1211-vssenum.go       — Stage 3: VSS enumeration + transacted-open on sandbox file
```

## Exit codes

- **101** — all three primitives executed without EDR detection (UNPROTECTED)
- **126** — EDR blocked the test at one of the three stages (PROTECTED)
- **999** — prerequisites not met (e.g., Cloud Files API unavailable on the SKU)

## Build

```bash
./build_all.sh                 # unsigned
./build_all.sh --org sb        # signed with org cert
```

Output: `build/5e59dd6a-6c87-4377-942c-ea9b5e054cb9/5e59dd6a-6c87-4377-942c-ea9b5e054cb9.exe`

## Score breakdown

| Axis | Score | Notes |
|------|-------|-------|
| Real-world accuracy | 2.7/3 | Mirrors authentic BlueHammer phases 1-3 APIs — CfRegisterSyncRoot + CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS + FSCTL_REQUEST_BATCH_OPLOCK + NtOpenDirectoryObject. Out-of-scope phases (SAM access) deliberately omitted. |
| Technical sophistication | 2.8/3 | Native Cloud Files API, NT Object Manager, KTM transactions. |
| Safety mechanisms | 2.0/2 | Hard 5s oplock cap; sandbox-only targets; SAM/VSS/credential surface fully excluded by design. |
| Detection opportunities | 0.7/1 | 3 distinct telemetry clusters (Cloud Files, oplock, VSS-enum + transacted-open). |
| Logging / observability | 0.8/1 | Schema v2.0, per-stage bundle results, JSON+TXT logs. |

## Reference

- PoC source: <https://github.com/Nightmare-Eclipse/BlueHammer>
- Phase walkthrough: see `5e59dd6a-6c87-4377-942c-ea9b5e054cb9_references.md`

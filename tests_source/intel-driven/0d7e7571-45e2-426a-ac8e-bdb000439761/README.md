# Nightmare-Eclipse RedSun Cloud Files Rewrite Primitive Chain

**UUID**: `0d7e7571-45e2-426a-ac8e-bdb000439761`
**Category**: `intel-driven`
**Target**: `windows-endpoint`
**Threat Actor**: Nightmare-Eclipse (RedSun PoC, 2026)
**Severity**: high
**Architecture**: multi-stage (3 stages)

**Test Score**: **8.4/10**

## Purpose

This test gives EDR/AV products a safe, controlled workload that exercises the
same API surface as the Nightmare-Eclipse RedSun PoC. It does **not** reproduce
the end-to-end exploit — no privilege escalation occurs, no real Windows
system files are touched, no COM activation happens. What it does do is invoke
each of the observable primitives the real PoC chains together, against
sandboxed targets under `c:\Users\fortika-test\RedSunSandbox\`, so defenders
can measure their detection coverage for:

- Non-OneDrive Cloud Files sync-root registration (`CfRegisterSyncRoot`)
- The agreed-upon safe AV-provocation primitive: EICAR test string in a
  cloud-synced directory
- `\Device` object-manager enumeration (`NtOpenDirectoryObject` /
  `NtQueryDirectoryObject`) filtered for `HarddiskVolumeShadowCopy*`
- Batch oplock request (`FSCTL_REQUEST_BATCH_OPLOCK`) on a sandbox file
- Mount-point reparse point (`FSCTL_SET_REPARSE_POINT`) — sandbox source to
  sandbox target (never to a real system path)
- `FILE_SUPERSEDE` / `CREATE_ALWAYS` race loop against a sandbox target file

## Stages

| # | Technique | Name | Primitive |
|---|-----------|------|-----------|
| 1 | T1211 | Cloud Files Sync Root + EICAR Provocation | `CfRegisterSyncRoot` with provider name `F0RT1KA-REDSUNSIM` against sandbox dir; drop EICAR string to `FakeTarget.exe`; observe AV reaction; unregister sync root |
| 2 | T1006 | VSS Device Enumeration + Batch Oplock | Read-only enumeration of `\Device` via `NtOpenDirectoryObject` + `NtQueryDirectoryObject`; filter for `HarddiskVolumeShadowCopy*` entries; request `FSCTL_REQUEST_BATCH_OPLOCK` on `OplockTarget.dat` (sandbox file) |
| 3 | T1574 | Mount-Point Reparse + FILE_SUPERSEDE Race | Create mount-point reparse point `ReparseSource` -> `ReparseTarget` (both inside sandbox dir); tear down via `FSCTL_DELETE_REPARSE_POINT`; loop 20x `CreateFile(CREATE_ALWAYS)` against `FakeTarget.exe` |

## MITRE ATT&CK Mapping

**Chosen (2 primary + 1 characterizing)**:

- **T1211 — Exploitation for Defense Evasion**: The Cloud Files API primitive
  is the defining characteristic of the RedSun technique. Abusing `CfApi` to
  tag files so Defender's cloud-rewrite pathway kicks in is the core defense-
  evasion mechanism. Detecting non-OneDrive/non-enterprise sync-root
  registration is where EDRs should focus.
- **T1006 — Direct Volume Access**: The `\Device` enumeration + VSS-name
  scanning + batch oplock pattern maps cleanly. The PoC uses object-manager
  enumeration to find VSS paths, which sits right at the DVA boundary.
- **T1574 — Hijack Execution Flow**: The mount-point reparse + `FILE_SUPERSEDE`
  race is a classic execution-flow hijack primitive. The real PoC uses it to
  redirect writes from a cloud-tagged placeholder into System32; even without
  the System32 target, the primitive itself is T1574-shaped.

**Rejected**:

- **T1068 (Exploitation for Privilege Escalation)**: The real PoC's endgame is
  SYSTEM-level code execution, but this sim explicitly does not escalate
  privileges — no System32 write, no COM activation. Mapping to T1068 would
  mislead defenders about what behavior they should expect to detect.

## Safety Boundaries

All primitives are scoped to `c:\Users\fortika-test\RedSunSandbox\`:

- No writes to `C:\Windows\`, `C:\Program Files\`, `C:\ProgramData\Microsoft\`
- No reparse point target ever references a real system path
- No `CoCreateInstance` on any CLSID
- No elevation attempts — runs as the invoking user
- Oplocks are released within the same function that requested them
- VSS enumeration is read-only; no VSS device handle is opened
- Sync root is unregistered before stage completion
- Reparse point is deleted before stage completion
- Supersede race is capped at 20 iterations (50ms sleep) — exercises the
  primitive without behaving like a DoS

## Build

```bash
cd tests_source/intel-driven/0d7e7571-45e2-426a-ac8e-bdb000439761/
./build_all.sh
```

Produces a signed, gzip-compressed-stage multi-stage orchestrator at
`build/0d7e7571-45e2-426a-ac8e-bdb000439761/0d7e7571-45e2-426a-ac8e-bdb000439761.exe`.

## Exit Codes

- **101** — All 3 primitives ran unimpeded (endpoint UNPROTECTED against
  RedSun pattern)
- **126** — At least one stage was blocked/flagged (endpoint PROTECTED)
- **105** — Orchestrator stage binary quarantined on disk
- **999** — Prerequisite failure (e.g., CldApi.dll not loadable on this
  Windows edition)

## Scoring Rationale

**Test Score: 8.4/10**

| Dimension | Score | Notes |
|---|---|---|
| Real-world accuracy | 2.6/3 | Same API surface as the RedSun PoC (CfApi, NtOpen/QueryDirectoryObject, FSCTL_REQUEST_BATCH_OPLOCK, FSCTL_SET_REPARSE_POINT, FILE_SUPERSEDE); primitive sequencing preserved. Loses 0.4 for not completing the end-to-end exploit (intentional safety limit). |
| Technical sophistication | 2.8/3 | Direct ntdll syscalls via LoadDLL/FindProc, hand-built `REPARSE_DATA_BUFFER`, correct UNICODE_STRING layout, overlapped IOCTL with `ERROR_IO_PENDING` handling. |
| Safety mechanisms | 2.0/2 | All writes scoped to `ARTIFACT_DIR`; reparse points explicitly sandbox-to-sandbox; oplocks/reparse points torn down in-function; supersede loop bounded; no COM activation; no privilege escalation path. |
| Detection opportunities | 0.5/1 | Exercises primitives that multiple detection layers can catch (AMSI via EICAR, behavior monitoring for CfRegisterSyncRoot provider, ETW for NtOpenDirectoryObject, fileless detection for oplock/reparse). |
| Logging & observability | 0.5/1 | Schema v2.0 structured logging, per-stage `WriteStageBundleResults()`, per-stage stdout capture; loses 0.5 for no ETW trace replay. |

## References

See `0d7e7571-45e2-426a-ac8e-bdb000439761_references.md`.

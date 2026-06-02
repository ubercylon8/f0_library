# KslKatz LSASS Credential Dumping Framework (BYOVD PPL Bypass)

**Test UUID**: `7ba6c119-df44-4cda-8045-b3700c31ba5e`
**Category**: intel-driven
**Architecture**: Multi-stage (4 stages)
**Platform**: Windows
**Severity**: critical
**Test Score**: **9.0/10**

## Overview

This test simulates the prerequisite and access-primitive chain of **KslKatz**, a
Bring-Your-Own-Vulnerable-Driver (BYOVD) credential-dumping framework that combines
**KslDump** and **GhostKatz** to read LSASS memory through a no-fix, Microsoft-signed
Microsoft Defender kernel driver (**KslD.sys**). KslKatz uses the driver's
`MmCopyMemory` physical-read wrapper to bypass LSASS PPL (Protected Process Light)
protection entirely — credential material is read from kernel mode, where PPL does
not apply.

Source: [Ghost in LSASS — Detecting KslKatz Credential Dumping Framework](https://detect.fyi/ghost-in-lsass-detecting-kslkatz-credential-dumping-framework-8645f246aec9) (detect.fyi).

## Kill Chain (4 stages)

| Stage | Technique | Tactic | Behavior |
|-------|-----------|--------|----------|
| 1 | T1543.003 | Persistence | Reconfigure a KslD-shaped Defender kernel service `ImagePath` toward a vulnerable driver (sandbox-owned key) |
| 2 | T1112 | Defense Evasion | Write `AllowedProcessName` under the KslD service key to defeat the driver's plain-string actor check (**primary detection signal**) |
| 3 | T1068 | Privilege Escalation | Drop a `vKslD.sys` artifact and open the `\\.\KslD` kernel device (open-only, no IOCTL) |
| 4 | T1003.001 | Credential Access | Enumerate handles to `lsass.exe` and open it for `PROCESS_VM_READ` (access primitive only, **no memory read**) |

## Safety Posture

Realism-first with a hard safety gate. The test exercises the exact telemetry surface
EDR keys on, while never crossing into harmful behavior:

- **Stage 1/2** write the identical KslD value names (`ImagePath`, `AllowedProcessName`)
  under a **sandbox-owned** service key — never the real Defender-associated KslD
  service. Registry telemetry (value names + NT-device-path payload shape) is identical.
- **Stage 3** opens `\\.\KslD` (the open attempt is the signal) but issues **no**
  memory-read IOCTL and loads **no** real driver. The dropped `vKslD.sys` is an inert
  placeholder.
- **Stage 4** locates `lsass.exe` and attempts `OpenProcess(PROCESS_VM_READ)` — the
  access event fires telemetry — but issues **no** `ReadProcessMemory` /
  `MiniDumpWriteDump`, parses **no** secrets, and writes **no** dump file. The handle
  is closed immediately.

No real credentials are ever exposed. All registry mutations are reversible and
sandbox-scoped; no real system services, drivers, or LSASS memory are touched.

## Expected Outcomes

- **Exit 126 (ExecutionPrevented)**: EDR blocked a stage (e.g., denied the
  `AllowedProcessName` write or the `OpenProcess(lsass, VM_READ)` handle). Endpoint
  protected — kill chain interrupted.
- **Exit 101 (Unprotected)**: All four stages completed without prevention. The
  KslKatz prerequisite chain and the LSASS read-access primitive are unprotected.
- **Exit 999 (UnexpectedTestError)**: Prerequisites not met (e.g., insufficient
  privileges to snapshot processes).

## Build

```bash
./build_all.sh                 # F0RT1KA-signed (default)
./build_all.sh --org sb        # dual-signed for an org
```

Output: `build/7ba6c119-df44-4cda-8045-b3700c31ba5e/7ba6c119-df44-4cda-8045-b3700c31ba5e.exe`

## Files

- `7ba6c119-df44-4cda-8045-b3700c31ba5e.go` — multi-stage orchestrator (embeds 4 `.exe.gz` stages)
- `stage-T1543.003.go`, `stage-T1112.go`, `stage-T1068.go`, `stage-T1003.001.go` — stage binaries
- `test_logger.go`, `test_logger_windows.go`, `org_resolver.go` — shared boilerplate
- `build_all.sh` — 8-step multi-stage build (build → sign → gzip → embed → sign)
- `7ba6c119-df44-4cda-8045-b3700c31ba5e_info.md` — detailed info card
- `7ba6c119-df44-4cda-8045-b3700c31ba5e_references.md` — source provenance

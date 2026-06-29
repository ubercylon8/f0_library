# RoguePlanet — Windows Defender Remediation TOCTOU LPE (wermgr.exe SYSTEM hijack)

**UUID**: `aa764293-94ed-4b25-a7fb-7d6fc14ac9a4`
**Category**: intel-driven
**Subcategory**: apt (vulnerability-exploit PoC)
**CVE**: CVE-2026-50656 — **unpatched as of 2026-06-29** (Microsoft acknowledged, patch in development, no timeline)
**Target**: windows-endpoint
**Severity**: critical
**Architecture**: standard single-binary (prebuilt-payload deployment)
**Test Score**: **9.5/10**

> ⚠️ **REAL DETONATION.** This test does not simulate the attack — it embeds and
> detonates a prebuilt local-privilege-escalation PoC ("RoguePlanet") that
> overwrites `C:\Windows\System32\wermgr.exe` and spawns an interactive
> `NT AUTHORITY\SYSTEM` console. **Run ONLY on a disposable / snapshot Windows VM
> with Defender real-time protection enabled, logged in as a standard (non-admin)
> user.** See the Safety section below before running.

---

## What this test does

RoguePlanet is a TOCTOU (time-of-check / time-of-use) race against Windows
Defender's **SYSTEM-privileged remediation ("clean") path**. Using an NTFS junction
(reparse point), an oplock for precise timing, a Volume Shadow Copy, and a mounted
ISO containing an EICAR-flagged `wermgr.exe`, the exploit causes a SYSTEM-level write
to land attacker-chosen bytes at `C:\Windows\System32\wermgr.exe`. It then triggers
the built-in WER scheduled task
`\Microsoft\Windows\Windows Error Reporting\QueueReporting`, which runs `wermgr.exe`
as SYSTEM — yielding an interactive SYSTEM console in the user's session.

This F0RT1KA test is a **prebuilt-binary deployment**: the Go orchestrator does NOT
reimplement the exploit. It:

1. Validates prerequisites (Defender on, not a Server SKU, non-elevated interactive
   user context obtainable).
2. Captures a **baseline SHA256** of `System32\wermgr.exe` **before** detonation.
3. Drops the embedded, F0RT1KA-signed `RoguePlanet.exe` (gzip-decompressed in memory)
   to `C:\F0`.
4. Detonates it in a **non-elevated interactive user context** (handling the
   Prelude/Achilles SYSTEM case via `WTSQueryUserToken` + `CreateProcessAsUser`),
   capturing stdout/stderr to `C:\F0\RoguePlanet_output.txt`.
5. Runs a **bounded retry loop** (the race is "hit or miss") and classifies the
   outcome on **positive evidence only**.
6. Verifies `wermgr.exe` self-restored, warns if not, and cleans up dropped
   artifacts.

## MITRE ATT&CK Mapping

| Technique | Name | Role |
|-----------|------|------|
| **T1068** | Exploitation for Privilege Escalation | Primary — TOCTOU race against Defender's SYSTEM remediation path |
| **T1036.005** | Masquerading: Match Legitimate Name or Location | Planting an attacker binary as `System32\wermgr.exe` |
| **T1053.005** | Scheduled Task/Job: Scheduled Task | Triggering the built-in `QueueReporting` WER task to run the planted binary as SYSTEM |

**Tactics**: privilege-escalation, defense-evasion, execution

## Result Classification (exit codes)

| Exit | Meaning | Required positive evidence |
|------|---------|----------------------------|
| **101** UNPROTECTED | Exploit succeeded | **BOTH**: captured stdout contains `Exploit succeeded.` **AND** `System32\wermgr.exe` SHA256 observed to deviate from baseline during the run |
| **105** PROTECTED (quarantine) | Dropped payload quarantined on extraction | Dropped `RoguePlanet.exe` removed from `C:\F0` (confirmed via `time.Sleep(3s)` + `os.Stat`) |
| **126** PROTECTED (prevented) | Execution prevented on a written binary | OS-emitted execution-prevention/AV error (`ERROR_VIRUS_INFECTED/DELETED`, or access-denied on a confirmed-present binary) at launch |
| **999** INCONCLUSIVE | Lost race or prerequisite gap | No success markers and no positive block evidence. **A lost race is NOT a block.** |

The orchestrator has **no `default → blocked` path** — the zero-value verdict is `999`
(CLAUDE.md Bug Prevention Rule 8).

## Safety

- **Real system mutation**: overwrites `System32\wermgr.exe`. The upstream-modified
  PoC self-restores it after ~30s and leaves `System32\wermgr.exe.rp_old` until the
  next reboot. The orchestrator verifies restoration and warns (with manual-restore
  guidance from `%TEMP%\RP_wbk_*`) if it did not happen.
- **Spawns a real SYSTEM console** on success (persists; out of scope to kill).
- **Requires Defender ON** (it is the target) and a **standard user** that can mount
  an ISO (fails on Windows Server).
- **Use a disposable / snapshot VM.** Revert after each run.

## Build

```bash
cd tests_source/intel-driven/aa764293-94ed-4b25-a7fb-7d6fc14ac9a4
./build_all.sh                 # F0RT1KA-only signing (recommended)
./build_all.sh --org sb        # dual-sign with org cert for ASR compatibility
```

Output: `build/aa764293-94ed-4b25-a7fb-7d6fc14ac9a4/aa764293-94ed-4b25-a7fb-7d6fc14ac9a4.exe`
(**2.72 MB — GREEN tier**).

## Files

| File | Purpose |
|------|---------|
| `aa764293-94ed-4b25-a7fb-7d6fc14ac9a4.go` | Orchestrator: drop, detonate, classify |
| `launcher_windows.go` | Context-aware launcher (SYSTEM→user token drop), exec-prevention classification |
| `RoguePlanet.exe` | Prebuilt PoC payload (embedded gzip-compressed at build time) |
| `test_logger.go`, `test_logger_windows.go` | Schema v2.0 logging |
| `org_resolver.go` | Organization UUID resolution |
| `go.mod`, `build_all.sh` | Build configuration |
| `aa764293-94ed-4b25-a7fb-7d6fc14ac9a4_info.md` | Detailed info card |
| `aa764293-94ed-4b25-a7fb-7d6fc14ac9a4_references.md` | Source provenance |
| `aa764293-94ed-4b25-a7fb-7d6fc14ac9a4_detections.*` etc. | Detection rules (5 formats) |
| `aa764293-94ed-4b25-a7fb-7d6fc14ac9a4_DEFENSE_GUIDANCE.md`, `_hardening.ps1` | Defense artifacts |

## Lab note

The active F0RT1KA lab endpoint is `debian` (Linux, no Defender) — this Windows-only
Defender test **cannot** be validated there. Lab detonation requires a disposable
Windows VM with Defender enabled, run as a standard user.

# LockBit 3.0 Double Extortion Kill Chain (SB-PC-2026-001) — Info Card

| Field | Value |
|-------|-------|
| **UUID** | `298cc137-ea39-4cf0-9b2d-b1c59a3cbacb` |
| **Name** | LockBit 3.0 Double Extortion Kill Chain (SB-PC-2026-001) |
| **Category** | intel-driven |
| **Subcategory** | ransomware |
| **Severity** | critical |
| **Target** | windows-endpoint |
| **Architecture** | multi-stage (5 stages) |
| **Threat Actor** | LockBit 3.0 (S1202) |
| **Complexity** | high |
| **Tags** | lockbit, ransomware, double-extortion, sb-pc-2026-001, assume-breach |
| **Source** | SB-PC-2026-001 [LOCKBIT] v3.0 — Superintendencia de Bancos (RD), 2026-10 |
| **Created** | 2026-10-01 |
| **Author** | sectest-builder |

## Test Score: 8.8/10

Scored under **Rubric v2.1** (tiered realism-first). Safety gate: **PASS**.
**Lab-verified on 2026-10-01** against the protected `win` lab (Windows 11 Pro,
Defender real-time protection + Tamper Protection ON, MDE Sense present): all five
stages executed, telemetry signal confirmed end-to-end, and one stage was positively
prevented by defense. Criterion 2c is fully earned (2.0/2.0) — the pre-lab 1.5 cap no
longer applies. Lab-Bound Observability documentation: not required — every stage
reached execution (the blocked stage ran its primitives and was denied at the API
level; it was not made unreachable by an upstream defense action).

### Score Breakdown

| Dimension | Score | Max | Justification |
|-----------|-------|-----|---------------|
| **Tier 1 — Safety gate** | PASS | — | All writes confined to `LOG_DIR`/`ARTIFACT_DIR`; loopback-only network; recovery-tamper commands target non-existent objects; degradation attempts verified by read-back and restored; cleanup on every exit path incl. watchdog/panic |
| 2a — API Fidelity | 2.0 | 2.5 | Real LockBit API/command surface: `OpenProcess(PROCESS_VM_READ)` on lsass + `rundll32 comsvcs.dll, MiniDump` (documented LockBit LOLBin), `reg.exe save HKLM\SAM`, `sc.exe stop/config` on real security service names, `Set-MpPreference`, `vssadmin/bcdedit/wevtutil` command lines, AES-256-GCM encryption loop, `net use \\ADMIN$`, rclone-signature POST. Deductions: lateral movement is loopback-contained (no real remote host); T1490/T1070.001 execute against fail-harmless non-existent targets rather than live recovery state |
| 2b — Identifier Fidelity | 1.0 | 1.5 | Production identifiers: real service names (WinDefend, WdNisSvc, Sense, EventLog), real LOLBins, `.lockbit` extension, `Restore-My-Files.txt` (real LockBit 3.0 note name), `rclone/v1.61.1` User-Agent (real LockBit exfil tooling). Deduction: sandbox markers (`LockBitSim` key, `lbsvc.exe` non-PE marker, `lockbit_target`/`lockbit_staging` dirs) are test-specific rather than actor artifacts |
| 2c — Telemetry Signal Quality | 2.0 | 2.0 | Signal richness ✓ (every stage fires process/cmdline/registry/file/network telemetry — see mapping below); sensor mapping documented ✓ (this card); rule artifacts in 5 parseable formats ✓; **lab execution verified** ✓ (2026-10-01 on `win`: all 5 stages reached, stage 2 positively blocked by Defender/MDE — see Lab Evidence) |
| 2d — Execution-Context Fidelity | 1.0 | 1.0 | Runtime context branching: `isSystemContext()` drives HKLM vs HKCU selection; denial evidence only counted when running elevated (ACL-vs-protection honesty per Bug Rule 8); SeDebugPrivilege enabled before LSASS access (tradecraft + evidence integrity); baseline-aware service tamper classification |
| 3a — Schema & Metadata | 1.0 | 1.0 | Schema v2.0 `InitLogger` with metadata + executionContext; `RubricVersion: v2.1`; complete v2.0 metadata header (all required fields) for ProjectAchilles ingestion |
| 3b — Documentation | 1.0 | 1.0 | README + info card + references complete; per-stage behavior and containment documented; SB-PC-2026-001 objective mapping explicit |
| 3c — Logging | 0.5 | 0.5 | Dual logging (stdout + structured) in all stage binaries; per-stage MultiWriter capture to `C:\F0\<binary>_output.txt`; `bundle_results.json` per-stage ES fan-out before every exit |
| 3d — Operational Hygiene | 0.3 | 0.5 | Orchestrator 23.5 MB < 25 MB ✓; per-stage watchdogs ✓; documented size justification ✓. Deduction: stage 4 binary 11 MB signed (> 5 MB stage budget) due to embedded `net/http` loopback listener |
| **Total** | **8.8** | 10.0 | Realism 6.0/7 + Structure 2.8/3 — no cap remaining (lab evidence earned) |

## Lab Evidence

**Detonation record** — host `win` (Windows 11 Pro 10.0.26200, Defender real-time
protection + Tamper Protection ON, MDE Sense present but not onboarded; executed via
SSH as `jimx`, local admin), 2026-10-01:

| Stage | Objective | Result | Evidence |
|-------|-----------|--------|----------|
| 1 | Execution & Defense Degradation | success (not prevented) | WinDefend + WdNisSvc stop attempts denied (services still RUNNING — tamper protection); RTP disable attempt blocked (read-back `False`); **EventLog stop succeeded** (restored in-code, verified RUNNING post-run); `DisableAntiSpyware=1` write succeeded (deleted immediately); Sense not evaluable (stopped at baseline — MDE not onboarded) |
| 2 | Privileged Credential Access | **blocked (126)** | `OpenProcess(PROCESS_VM_READ)` on lsass **denied with SeDebugPrivilege enabled** — positive Defender credential-theft protection evidence; comsvcs.dll MiniDump produced no dump; `reg.exe save HKLM\SAM` produced no file without denial text (inconclusive per Rule 8, not counted either way) |
| 3 | Lateral Movement & Propagation | success | Loopback `ADMIN$` session + marker tool transfer unimpeded |
| 4 | Pre-Encryption Exfiltration | success | 2 MB synthetic archive POSTed to the loopback listener unimpeded (expected — loopback is not egress-filtered) |
| 5 | Impact | success | All 10 sandbox documents AES-256-GCM encrypted to `.lockbit` + ransom note dropped; `vssadmin`/`bcdedit`/`wevtutil` telemetry fired (fail-harmless targets); sandbox encryption not intercepted (no Controlled Folder Access / ASR ransomware protection on the lab host) |

- **Final exit code: 126 (PROTECTED)** — `bundle_results.json`: 1 blocked / 4 succeeded / 0 skipped.
- Defense verdict: LSASS credential-theft protection is effective on this host; gaps
  demonstrated for EventLog service tamper, registry-based Defender policy tamper, and
  ransomware-style encryption of user-writable directories.
- Post-run host state verified at baseline: EventLog RUNNING, WinDefend RUNNING, RTP
  enabled, `DisableAntiSpyware` absent, Sense at its Manual/stopped baseline, all test
  artifacts removed (`C:\F0`, ARTIFACT_DIR).
- Two consecutive full-chain runs produced identical verdicts. An earlier run exposed
  (and drove fixes for) four defects: abort-on-stage-error (SB coverage requires all 5
  objectives attempted), vendored-library `Endpoint.UnexpectedTestError == 1` vs the
  F0 999 convention, LSASS denial ambiguity without SeDebugPrivilege, and a service
  stop/restore race — all verified fixed in the final run.
- Archived artifacts: `staging/298cc137-ea39-4cf0-9b2d-b1c59a3cbacb/`
  (`test_execution_log.json`, `bundle_results.json`, stage output captures).

## Size Justification

Final orchestrator: **24,638,064 bytes (23.5 MB) — Yellow tier** (10–25 MB band).
Justification: five dual-signed stage binaries are gzip-embedded (Authenticode is per-file;
dual signing for ASR compatibility is mandatory per framework). The largest contributor is
stage 4 (`stage-T1567.002`, 11 MB signed / 6.3 MB gz), which embeds Go's `net/http` stack to
run a real loopback HTTP listener for byte-counted exfiltration classification with a genuine
rclone client signature — required to match LockBit's StealBit/cloud-exfil tradecraft rather
than a print-only simulation. Gzip compression is wired (build step 4/8). Refactor recipes
evaluated: `lab_assets/` runtime fetch rejected (would break single-binary deployment and the
agent `MaxDownloadTimeout` envelope is unaffected at 23.5 MB); stage trim rejected (all 5
stages are anchored to mandatory SB-PC-2026-001 objectives).

## Stage Details

### Stage 1 — Execution & Defense Degradation (T1059.001, T1562.001, T1112)

- Drops `lockbit_recon.ps1` to `C:\F0` and executes `powershell.exe -ExecutionPolicy Bypass -File`; the script performs LockBit-style host recon (hostname, whoami, domain, AV product enumeration via `Get-CimInstance / root\SecurityCenter2`). Output captured to `lockbit_recon_output.txt`.
- `sc.exe stop` + `sc.exe config <svc> start= disabled` against **WinDefend, WdNisSvc, Sense, EventLog** (registry service names, Bug Rule 6). Classification by re-query: service still RUNNING after the attempt = positive block evidence (Rules 5/6). Any service actually stopped is immediately restored (original start type + start).
- `Set-MpPreference -DisableRealtimeMonitoring $true` via PowerShell, read back with `Get-MpPreference`; restored to `$false` if it stuck. Unchanged value / denial = blocked.
- Sandbox registry marker under `HKCU\Software\LockBitSim` (HKLM when SYSTEM, Rule 2); then `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1` write attempt with read-back and **immediate delete**.
- Verdict: any degradation landing → stage success (vulnerable); all evaluable attempts positively prevented (elevated context) → blocked (126); insufficient evidence → 999.

### Stage 2 — Privileged Credential Access (T1003.001, T1003.002)

- Locates `lsass.exe` PID via Toolhelp32; `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)` (handle closed immediately); then the LockBit-documented LOLBin dump: `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid> C:\F0\lsass.dmp full`.
- `reg.exe save HKLM\SAM C:\F0\sam.save` (SeBackupPrivilege path). A registry-API open of `HKLM\SAM` is logged as telemetry only — its denial is the default Windows SAM ACL, never counted as protection evidence (Rule 8).
- Both `lsass.dmp` and `sam.save` are deleted in cleanup. Any success → vulnerable; both positively denied while elevated → 126; else 999.

### Stage 3 — Lateral Movement & Propagation (T1021.002, T1570)

- Loopback-only: `net use \\127.0.0.1\ADMIN$`, writes a 4 KB **non-executable** text marker (`lbsvc.exe`) into `ADMIN$\Temp`, verifies via `os.Stat`, deletes it, tears down the session. No service creation/execution.
- Blocked only on positive denial (system error 5 / access denied in elevated context); error 53/67 (Server service off) → 999 prerequisite, never a block.

### Stage 4 — Pre-Encryption Exfiltration (T1567.002)

- Generates 4×512 KB synthetic PII CSVs (every row marked SYNTHETIC, `example.test` domains) in `ARTIFACT_DIR\lockbit_staging`; `Compress-Archive` to `C:\F0\lockbit_exfil.zip`.
- Binds an HTTP listener on `127.0.0.1` (ephemeral port) and POSTs the archive with `User-Agent: rclone/v1.61.1` + cloud-upload headers — the StealBit/rclone-to-cloud pattern documented for LockBit. Classification: bytes received == archive size. The URL is derived from the listener's own address — external egress is impossible by construction.

### Stage 5 — Impact: Encryption & Recovery Inhibition (T1486, T1490, T1070.001)

- Creates `ARTIFACT_DIR\lockbit_target\` (prefix-guarded before every write/delete) with 10 synthetic documents; AES-256-GCM encrypts them in place to `.lockbit`; drops a LockBit 3.0-style double-extortion ransom note (`Restore-My-Files.txt`) inside the sandbox only.
- T1490 fail-harmless telemetry: `vssadmin delete shadows /for=\\?\Volume{00000000-0000-0000-0000-000000000000}\ /quiet` and `bcdedit /set {00000000-0000-0000-0000-000000000000} recoveryenabled no` — real command lines against non-existent targets; cannot touch real shadow copies, backup catalogs, or boot configuration. `wbadmin delete catalog` deliberately omitted (no harmless form exists).
- T1070.001: `wevtutil el` enumeration + `wevtutil cl F0RT1KA-LockBitSim-NonExistent` (non-existent channel; never clears a real log).
- Verdict driven by T1486 only: encrypt writes positively denied (elevated) with zero successes → 126; ≥1 file encrypted → vulnerable; else 999.

## Telemetry Signal Mapping

| Stage | Behavior | Primary sensors (expected events) |
|-------|----------|-----------------------------------|
| 1 | PS recon (`-ExecutionPolicy Bypass`) | Sysmon EID 1 (process), PS 4104 (script block), AMSI |
| 1 | `sc.exe stop/config` security services | Sysmon EID 1 cmdline, Security 4697/7040/7036, service-control ETW |
| 1 | `Set-MpPreference` RTP disable | PS 4104, Defender Operational log (5007), registry EID 13 |
| 1 | `DisableAntiSpyware` policy write | Sysmon EID 13, Security 4657, Defender 5007 |
| 2 | LSASS handle + comsvcs MiniDump | Sysmon EID 10 (ProcessAccess lsass), EID 1 (rundll32 cmdline), EID 11 (dump file), Credential Guard/EDR LSASS alerts |
| 2 | `reg.exe save HKLM\SAM` | Sysmon EID 1 cmdline, Security 4663 (SAM object access w/ SACL) |
| 3 | `net use \\*\ADMIN$` + write to `ADMIN$\Temp` | Sysmon EID 3 (SMB session), Security 5140/5145 (share access), EID 11 |
| 4 | `Compress-Archive` + rclone-UA POST | PS 4104, EID 11 (zip), EID 3/proxy (UA string), DNS |
| 5 | Mass `.lockbit` rename + ransom note | Sysmon EID 11/23, USN-journal burst, CFA (Controlled Folder Access) events |
| 5 | `vssadmin delete shadows` / `bcdedit` / `wevtutil cl` | EID 1 cmdline (canonical T1490/T1070.001 signatures), System 7036, Security 1102 |

## Containment Matrix (Safety Gate Evidence)

| Risk surface | Containment |
|--------------|-------------|
| File writes | `C:\F0` (LOG_DIR) and `c:\Users\fortika-test` (ARTIFACT_DIR) only; stage 5 enforces a literal prefix guard on the sandbox path |
| Encryption | Synthetic docs in `lockbit_target` only; per SB-PC-2026-001 Aclaración 2 |
| Network | Loopback only (stages 3–4); no external egress possible by construction |
| Recovery tamper | Non-existent volume/BCD/log targets — telemetry without mutation |
| Defense degradation | Read-back verification + immediate restore (services restarted, RTP re-enabled, policy value deleted) |
| Credential artifacts | `lsass.dmp` / `sam.save` deleted in cleanup; lab VM is revertible (snapshot recommended pre-detonation) |
| Process/watchdog | Per-stage watchdogs (3–5 min); panic handler finalizes bundle results; cleanup on every exit path |

## Execution

```bash
# Lab deploy (Windows target, SSH alias `win`):
scp build/298cc137-ea39-4cf0-9b2d-b1c59a3cbacb/298cc137-ea39-4cf0-9b2d-b1c59a3cbacb.exe win:'c:\F0\'
ssh win 'c:\F0\298cc137-ea39-4cf0-9b2d-b1c59a3cbacb.exe & echo EXIT_CODE: %ERRORLEVEL%'
```

Orchestrator exit semantics: any stage 126/105 → **126** (protected); all stages 0 → **101**
(unprotected); unresolved errors → **999**. Per-stage detail: `C:\F0\bundle_results.json`,
`C:\F0\<binary>_output.txt`, and the Schema v2.0 `test_execution_log.json`.

## SB-PC-2026-001 Compliance Mapping

| SB Objective | Requirement | This test |
|--------------|-------------|-----------|
| 1 — Ejecución y degradación | ≥2 TTPs incl. ≥1 T1059; T1562.001 recommended | T1059.001 + T1562.001 + T1112 ✓ |
| 2 — Credenciales privilegiadas | ≥2 TTPs | T1003.001 + T1003.002 ✓ |
| 3 — Movimiento lateral | ≥1 TTP | T1021.002 + T1570 ✓ (loopback per Aclaración 3) |
| 4 — Exfiltración | ≥1 TTP, synthetic data only | T1567.002 ✓ (synthetic PII, loopback) |
| 5 — Impacto | T1486 mandatory + ≥1 of T1490/T1489/T1485/T1070.001 | T1486 + T1490 + T1070.001 ✓ (isolated test dir) |

The per-stage `bundle_results.json` rows map 1:1 to the SB report's `executions[]` entries
(`stage`/`stageLabel` 1–5, techniques, outcome PREVENTED/DETECTED/MISSED/EXPOSED ← stage exit
codes). A converter from bundle results to the SB `{meta, executions[]}` JSON envelope is a
reporting-layer follow-up, not part of this test binary.

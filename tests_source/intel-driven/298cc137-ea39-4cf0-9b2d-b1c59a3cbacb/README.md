# LockBit 3.0 Double Extortion Kill Chain (SB-PC-2026-001)

| Field | Value |
|-------|-------|
| **UUID** | `298cc137-ea39-4cf0-9b2d-b1c59a3cbacb` |
| **Category** | intel-driven / ransomware |
| **Severity** | critical |
| **Platform** | windows-endpoint |
| **Architecture** | multi-stage (5 stage binaries + orchestrator) |
| **Threat Actor** | LockBit 3.0 (LockBit Black) — MITRE S1202 |
| **Complexity** | high |
| **Rubric** | v2.1 |

**Test Score**: **8.8/10**

## Overview

Post-compromise (assume-breach) emulation of the LockBit 3.0 double-extortion kill chain,
implementing the five attacker objectives defined by the **Superintendencia de Bancos
(República Dominicana)** continuous-testing package **SB-PC-2026-001 [LOCKBIT]**, v3.0
(October 2026). Initial access is out of scope per the supervisory package; execution
starts from an already-compromised corporate workstation.

The orchestrator extracts five dual-signed, gzip-compressed stage binaries to `C:\F0` and
executes them sequentially, evaluating per-stage protection effectiveness. Each stage maps
1:1 to an SB-PC-2026-001 observable objective, so per-stage results (via
`bundle_results.json`) translate directly into the supervisory reporting structure.

## Kill Chain

| Stage | Objective (SB-PC-2026-001) | Primary Technique | Behaviors |
|-------|---------------------------|-------------------|-----------|
| 1 | Ejecución y degradación de defensas | T1059.001 | PowerShell recon (`-ExecutionPolicy Bypass`, AV enumeration); `sc.exe stop/config` on WinDefend, WdNisSvc, Sense, EventLog with re-query + auto-restore; `Set-MpPreference -DisableRealtimeMonitoring` attempt with read-back + restore (T1562.001); registry marker + `DisableAntiSpyware=1` write attempt with immediate delete (T1112) |
| 2 | Acceso a credenciales privilegiadas | T1003.001 | LSASS handle open + `rundll32 comsvcs.dll, MiniDump` attempt (LockBit LOLBin pattern); `reg.exe save HKLM\SAM` attempt (T1003.002); artifacts deleted in cleanup |
| 3 | Movimiento lateral y propagación | T1021.002 | Loopback-only `\\127.0.0.1\ADMIN$` session + marker tool transfer to `ADMIN$\Temp` (T1570), verify + delete; no service creation |
| 4 | Exfiltración previa al cifrado | T1567.002 | Synthetic PII CSVs staged in `ARTIFACT_DIR`, `Compress-Archive`, HTTP POST to a `127.0.0.1` listener with `rclone` client signature (StealBit/cloud pattern); byte-counted classification; zero external egress |
| 5 | Impacto por cifrado y bloqueo de recuperación | T1486 | AES-256-GCM encryption of a sandboxed directory to `.lockbit` + `Restore-My-Files.txt` ransom note; fail-harmless `vssadmin delete shadows` / `bcdedit` against non-existent targets (T1490); `wevtutil cl` against a non-existent log (T1070.001) |

## MITRE ATT&CK

- **Techniques**: T1059.001, T1562.001, T1112, T1003.001, T1003.002, T1021.002, T1570, T1567.002, T1486, T1490, T1070.001
- **Tactics**: execution, defense-evasion, credential-access, lateral-movement, exfiltration, impact

## Build & Sign

```bash
cd tests_source/intel-driven/298cc137-ea39-4cf0-9b2d-b1c59a3cbacb
./build_all.sh            # default org: sb (dual-sign SB + F0RT1KA)
./build_all.sh --org sb   # explicit
```

8-step modern build: stage builds → dual sign → verify → gzip → orchestrator embed → dual sign → SHA1 → cleanup.
Output: `build/298cc137-ea39-4cf0-9b2d-b1c59a3cbacb/298cc137-ea39-4cf0-9b2d-b1c59a3cbacb.exe` (23.5 MB, Yellow tier — see info card).

## Expected Results

| Exit | Meaning |
|------|---------|
| 101 | All 5 stages succeeded — endpoint unprotected against the full chain |
| 126 | At least one stage blocked/quarantined — a critical protection layer fired |
| 105/127 | A stage binary quarantined on extraction/execution |
| 999 | Test error (prerequisite missing) — investigate output logs |

**Lab validation (2026-10-01, `win` — Windows 11 Pro, Defender RTP + Tamper Protection ON, MDE Sense present):**
exit **126 (PROTECTED)** — Stage 2 positively blocked (LSASS `OpenProcess` denied with
SeDebugPrivilege enabled = Defender/MDE credential-theft protection); stages 1, 3, 4, 5
executed without prevention. Per-stage detail in the info card's Lab Evidence section.

Per-stage results are written to `C:\F0\bundle_results.json` for per-stage Elasticsearch fan-out.

## Detection Rules

Five formats included: KQL (`_detections.kql`), YARA (`_rules.yar`), Sigma (`_sigma_rules.yml`),
Elastic EQL (`_elastic_rules.ndjson`), LimaCharlie D&R (`_dr_rules.yaml`). All rules are
technique-focused (they detect real LockBit tradecraft, not this harness).

## Defense

- `298cc137-ea39-4cf0-9b2d-b1c59a3cbacb_DEFENSE_GUIDANCE.md` — consolidated hardening + IR playbook (financial-sector CISO audience)
- `298cc137-ea39-4cf0-9b2d-b1c59a3cbacb_hardening.ps1` — idempotent Windows hardening script with `-WhatIf`/`-Undo`

## Safety & Containment

All destructive actions are sandbox-confined: encryption targets only
`c:\Users\fortika-test\lockbit_target` (synthetic data, per SB-PC-2026-001 Aclaración 2);
exfiltration and lateral movement use loopback only (no external egress); recovery-tamper
commands run against non-existent targets (telemetry without mutation); defense-degradation
attempts are verified by read-back and restored immediately. See the info card for the full
containment matrix.

## References

See `298cc137-ea39-4cf0-9b2d-b1c59a3cbacb_references.md` — primary source SB-PC-2026-001 v3.0
plus CISA AA23-165A / AA23-075A, MITRE S1202/S1199, Europol Operation Cronos.

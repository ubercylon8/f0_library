# The Gentlemen: GPO-Driven, Living-off-the-Land Intrusion

| Field | Value |
|-------|-------|
| **UUID** | `7cc45d21-9a6e-4128-9f75-06e5167a4b80` |
| **Category** | intel-driven / ransomware |
| **Severity** | critical |
| **Platform** | windows-endpoint |
| **Architecture** | multi-stage (5 stage binaries + orchestrator) |
| **Threat Actor** | The Gentlemen RaaS — GOLD SHERWOOD (Sophos CTU designation) |
| **Complexity** | high |
| **Rubric** | v2.1 |

**Test Score**: **8.1/10**

## Overview

Post-compromise (assume-breach) emulation of **The Gentlemen** ransomware-as-a-service
operation, tracked by Sophos CTU as **GOLD SHERWOOD**. The actor's signature is
**living off legitimate tooling**: it repurposes Velociraptor (a legitimate, signed DFIR
tool) as its C2 channel, moves laterally with WMI/PsExec/NetExec/RDP instead of custom
malware, pushes payloads domain-wide by abusing Group Policy, and persists through
masqueraded scheduled tasks, decoy services, and newly created privileged local accounts.
Primary intel: Trend Micro (2025-09-09), corroborated by Sophos CTU (2026-09, 15 incidents)
and Huntress (2026-05-21).

The orchestrator extracts five signed, gzip-compressed stage binaries to `C:\F0` and
executes them sequentially. The stages are **independent** — every stage executes
regardless of prior stage outcomes (continue-on-block), because per-stage coverage
requires every objective attempted and a real human-operated crew does not stop after
one failed primitive. Per-stage results fan out via `bundle_results.json`.

**Out of scope by design**: BYOVD (ThrottleBlood.sys/All.exe — owned by the Qilin test)
and data-encryption impact (T1486 — owned by the LockBit 3.0 test).

## Kill Chain

| Stage | Objective | Primary Technique | Behaviors |
|-------|-----------|-------------------|-----------|
| 1 | Reconnaissance: defenses, accounts, AD context | T1518.001 (+T1087, T1082) | `wmic /namespace:\root\SecurityCenter2 path AntiVirusProduct` (PowerShell `Get-CimInstance` fallback for Win11 24H2 wmic removal); `sc.exe query` probes of WinDefend, Sense, CSFalconService, SepMasterService, SophosMMS, WdNisSvc (query-only); `tasklist` EDR process hunt; the actor's 1.bat-shape mass enumeration (`net user /domain`, `net user administrator /domain`, `net group "domain admins" /domain`, `net group "Enterprise admins" /domain`, `net localgroup administrators`, `net localgroup __vmware__*`); `whoami /all`, `systeminfo`, computer domain; encoded PowerShell PDC probe (`powershell -noni -nop -w 1 -enc <UTF16LE-B64 (Get-ADDomain).PDCEmulator>`) |
| 2 | Masqueraded remote-access deployment (**star stage**) | T1036 (+T1219) | `Velociraptor.exe` decoy (a **text marker, never a PE**) staged in a PerfLogs-named directory inside ARTIFACT_DIR — trusted-path identifier preserved, sandbox-contained; real Velociraptor deployment artifacts beside it (`client.config.yaml` with loopback frontend URL + client nonce + CA block, `client.writeback`); in-process loopback HTTP frontend on `127.0.0.1:8000` (Velociraptor default, fallback 8800) receiving 3 Velociraptor-shaped beacons (`POST /control?v=1&client_id=C.<hex>&nonce=<hex>`, UA `Velociraptor 0.74.1 (windows amd64)`); 3 s `os.Stat` quarantine sweep |
| 3 | LOLBin lateral movement | T1047 (+T1021.002, T1021.001) | WMI remote process creation against `127.0.0.1` (`wmic /node:` shape, PowerShell DCOM `New-CimSession -Protocol DCOM` + `Invoke-CimMethod Win32_Process.Create` fallback) writing a benign marker to `C:\F0`; NetExec `nxc smb 127.0.0.1` command-shape probe (non-gating); loopback SMB `\\127.0.0.1\ADMIN$` session + benign marker transfer into `ADMIN$\Temp` with `os.Stat` verification, delete, session teardown (PsExec prerequisite, LockBit stage-3 pattern); read-only RDP context beat (`reg query fDenyTSConnections` + loopback 3389 TCP probe, never a write) |
| 4 | Enterprise deployment via Group Policy (sandboxed) | T1484.001 | Fake `{GUID}` GPO tree inside `ARTIFACT_DIR\gpo_sandbox\SYSVOL\lab.local\Policies\{...}\` with real `gpt.ini` content and binary PReg-format `Machine\Registry.pol` (the SYSVOL-write file telemetry); `New-GPO` PowerShell command-shape (fails fast without RSAT — fail-harmless); loopback NETLOGON deployment shape (`\\127.0.0.1\NETLOGON\gentlemen_deploy_marker.exe --password ***`, share absent on non-DC, non-gating). **Real Group Policy is never touched** |
| 5 | Redundant persistence | T1136.001 (+T1053.005, T1543.003) | Three real-but-reversible artifacts with verified cleanup: (a) `schtasks /create /tn WindowsConnSvc` (the actor's masqueraded task name) `/tr "cmd echo marker to C:\F0" /sc minute /mo 2 /ru SYSTEM /f`, query-verify then delete + absence-verify; (b) `sc create F0GentlemenSvc binPath= C:\F0\gentlemen_svc_marker.exe` (text marker, not a PE) `DisplayName= "Velociraptor Client"` (masquerade), `start= demand`, **never started**, query-verify then delete; (c) `net user f0_gentlemen_acct <random> /add` + `net localgroup administrators f0_gentlemen_acct /add` (Sophos CTU shape), verify, then group-remove + account-delete + absence-verify. Runs last for the shortest privileged-account window; failed cleanup = CRITICAL log + exit 999, never silent |

## MITRE ATT&CK

- **Techniques**: T1518.001, T1087, T1082, T1036, T1219, T1047, T1021.002, T1021.001, T1484.001, T1053.005, T1543.003, T1136.001
- **Tactics**: discovery, defense-evasion, command-and-control, execution, lateral-movement, persistence

## Build & Sign

```bash
cd tests_source/intel-driven/7cc45d21-9a6e-4128-9f75-06e5167a4b80
./build_all.sh            # default: F0RT1KA-cert signing
./build_all.sh --org sb   # explicit dual-sign (SB + F0RT1KA)

# Or via the framework wrappers:
./utils/gobuild build tests_source/intel-driven/7cc45d21-9a6e-4128-9f75-06e5167a4b80/
./utils/codesign sign build/7cc45d21-9a6e-4128-9f75-06e5167a4b80/7cc45d21-9a6e-4128-9f75-06e5167a4b80.exe
```

8-step modern build: stage builds → sign (fail-loud, before embedding) → verify →
gzip -9 → orchestrator embed → sign → SHA1 → cleanup.
Output: `build/7cc45d21-9a6e-4128-9f75-06e5167a4b80/7cc45d21-9a6e-4128-9f75-06e5167a4b80.exe`
(25,092,944 bytes ≈ 23.9 MiB, Yellow tier — see the info card's Size Justification).

## Expected Results

| Exit | Meaning |
|------|---------|
| 101 | All 5 stages executed without prevention — endpoint exposed to the full LOLBin chain |
| 126 | At least one stage positively blocked/quarantined — a critical protection layer fired |
| 105/127 | A stage binary quarantined on extraction/execution |
| 999 | Test error (prerequisite missing, watchdog timeout, or failed stage-5 cleanup) — investigate output logs |

The chain is **continue-on-block**: a blocked stage is recorded (per-stage exit 126/105)
and execution proceeds, so all five Gentlemen objectives are always attempted. Exit-code
integrity throughout: blocks require positive evidence (OS-emitted denial in elevated
context, launch-refusal errno, or verified file disappearance); benign failures — missing
AD, removed `wmic`, absent RSAT/NETLOGON, missing `nxc` — map to prerequisites (999),
never to block codes.

**Lab validation: PENDING (not yet run).** Planned first detonation on the `win` lab
(Windows 11 Pro protected by CrowdStrike Falcon, Defender passive). Per-stage detail
will be recorded in the info card's Lab Evidence section; rubric 2c is capped until
this run lands.

Per-stage results are written to `C:\F0\bundle_results.json` for per-stage Elasticsearch
fan-out; raw stage output to `C:\F0\<binary>_output.txt`.

## Detection Rules

Five formats included: KQL (`_detections.kql`), YARA (`_rules.yar`), Sigma
(`_sigma_rules.yml`), Elastic EQL (`_elastic_rules.ndjson`), LimaCharlie D&R
(`_dr_rules.yaml`). All rules are technique-focused — they detect real Gentlemen
tradecraft (security-product recon, masqueraded remote-access deployment, WMI/SMB
LOLBin lateral movement, GPO abuse, redundant persistence), not this harness.

## Defense

- `7cc45d21-9a6e-4128-9f75-06e5167a4b80_DEFENSE_GUIDANCE.md` — consolidated hardening + IR playbook
- `7cc45d21-9a6e-4128-9f75-06e5167a4b80_hardening.ps1` — idempotent Windows hardening script with `-WhatIf`/`-Undo`

## Safety & Containment

All lateral movement and C2 are confined to `127.0.0.1` (no external egress by
construction); all file writes are confined to `LOG_DIR` (`C:\F0`) and `ARTIFACT_DIR`
(`c:\Users\fortika-test`); every staged "binary" is a text marker with an `.exe` name —
never a PE, never executed. Real Group Policy is never read or modified (sandbox
`{GUID}` tree inside ARTIFACT_DIR only). The only real system mutations are stage 5's
task/service/account — test-owned names, created-verified-deleted with deferred cleanup
and absence verification; failed cleanup is a CRITICAL error (999), never silent. See
the info card for the full containment matrix.

## References

See `7cc45d21-9a6e-4128-9f75-06e5167a4b80_references.md` — primary source Trend Micro
(2025-09-09) plus Sophos CTU (GOLD SHERWOOD, 15 incidents), Huntress, Dark Reading,
GuidePoint GRIT Q3 2026, and the Velociraptor/NetExec tool documentation.

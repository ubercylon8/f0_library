# Defense Guidance — RoguePlanet Windows Defender Remediation TOCTOU LPE

**UUID**: `aa764293-94ed-4b25-a7fb-7d6fc14ac9a4`
**Techniques**: T1068 (Exploitation for Privilege Escalation), T1036.005 (Masquerading), T1053.005 (Scheduled Task)
**Target**: windows-endpoint
**Severity**: critical

## Threat summary

RoguePlanet abuses a TOCTOU race in Windows Defender's SYSTEM-privileged remediation
("clean") path. Using an NTFS junction, an oplock for timing, a Volume Shadow Copy, and
a mounted ISO holding an EICAR-flagged `wermgr.exe`, it causes a SYSTEM write to plant an
attacker binary at `C:\Windows\System32\wermgr.exe`, then triggers the built-in WER
`QueueReporting` scheduled task to execute it as SYSTEM — yielding an interactive SYSTEM
console from a standard user. The attacker needs **no admin rights** and creates **no new
persistence**; it reuses a built-in task and self-restores the patched file after ~30s.

## Why this is hard to stop with prevention alone

The vulnerability is in Defender's own remediation logic — the security product is the
exploited component. Prevention therefore centers on **patching**, **reducing the
attacker's primitives** (ISO mount, junction abuse), and **rapid detection of the file
plant**, rather than on a single config toggle.

## Detection priorities (highest value first)

1. **`System32\wermgr.exe` integrity change** — a protected System32 binary being
   modified/replaced by a non-servicing process is the single strongest signal.
   Watch for `wermgr.exe.rp_old` too (the PoC's restore leftover).
2. **`MpClient.dll` loaded by a non-Defender process** — programmatic
   `MpScanStart`/`MpCleanStart` from a random user process.
3. **`wermgr.exe` (SYSTEM) parenting an interactive console** (`conhost`/`cmd`/
   `powershell`) in a non-zero session — the payoff, a process-tree anomaly.
4. **ISO staged in `%TEMP%` and mounted (no drive letter)** by a non-elevated process;
   **junction create/delete/recreate** racing a SYSTEM service; **oplock + `LockFile`**
   around a Defender operation; a **transient new Volume Shadow Copy**.

See the bundled detection rules:
- `*_detections.kql` (Sentinel / Defender XDR)
- `*_rules.yar` (YARA)
- `*_sigma_rules.yml` (Sigma)
- `*_elastic_rules.ndjson` (Elastic EQL)
- `*_dr_rules.yaml` (LimaCharlie D&R)

## Mitigations (MITRE)

| Mitigation | Action |
|-----------|--------|
| **M1051 Update Software** | Apply the latest Windows/Defender platform updates — the remediation-path TOCTOU is fixed by vendor patching. Keep Defender platform (`MsMpEng`) current. |
| **M1038 Execution Prevention** | WDAC/AppLocker policy that constrains where unsigned/unknown executables can run; ASR "Block executable files from running unless they meet a prevalence/age/trusted-list criterion." |
| **M1028 OS Configuration** | Restrict non-admin ISO/VHD mounting (a hard prerequisite of this PoC). Audit/monitor `Microsoft-Windows-VHDMP` virtual-disk attach. |
| **M1040 Behavior Prevention on Endpoint** | Enable Defender tamper protection and cloud-delivered/behavioral protection. |
| **M1047 Audit** | Enable SACL auditing on `C:\Windows\System32\wermgr.exe` and process-creation + image-load logging (Sysmon 11/7/1) to feed the detections above. |
| **M1018 User Account Management** | Standard users should run with least privilege; this exploit specifically targets standard-user → SYSTEM, so robust EDR + patching matters more than removing local-user rights. |

## Hardening script

`aa764293-94ed-4b25-a7fb-7d6fc14ac9a4_hardening.ps1` (Windows). It:

1. Enables Defender tamper protection, cloud protection, and PUA protection (best-effort).
2. Enables the relevant ASR rules (block executable files by prevalence/age; block
   process creations from PSExec/WMI; block credential stealing from LSASS) in **Audit**
   mode first so you can baseline before enforcing.
3. Adds a SACL audit ACE on `System32\wermgr.exe` so writes generate 4663 events.
4. Enables process-creation auditing with command line, and image-load-relevant policy.
5. Optionally restricts non-admin VHD/ISO mounting via a Mounted Devices policy note.

Run as Administrator. Use `-WhatIf` to preview, `-Undo` to revert. The script never
disables Defender real-time protection (which would *enable* the attack surface, not
reduce it).

## Incident response playbook

**If a detection fires (wermgr.exe integrity change / SYSTEM console from wermgr):**

1. **Isolate** the host (network-contain via EDR).
2. **Confirm the plant**: compare `C:\Windows\System32\wermgr.exe` SHA256 against a
   known-good (same build/patch level). Check for `wermgr.exe.rp_old`.
3. **Restore integrity**: if `wermgr.exe` is not the legitimate binary, restore it from a
   trusted source / `sfc /scannow` / servicing. (The PoC self-restores after ~30s, so a
   late hash check may look clean — rely on the *event*, not just the current hash.)
4. **Hunt the SYSTEM console**: enumerate processes parented by `wermgr.exe` running as
   SYSTEM in interactive sessions; kill any illegitimate SYSTEM `conhost`/`cmd`.
5. **Scope**: search for `MpClient.dll` loads by non-Defender processes, `%TEMP%\RP_*`
   ISO artifacts, transient shadow copies, and junction activity around the event time.
6. **Eradicate & recover**: remove dropped tooling, reboot to clear the `.rp_old`
   leftover and any planted in-memory state, re-image if SYSTEM execution is confirmed.
7. **Patch**: ensure the host's Windows/Defender platform is fully updated before
   returning it to service.

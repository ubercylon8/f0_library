# Defense Guidance: KslKatz LSASS Credential Dumping Framework (BYOVD PPL Bypass)

## Executive Summary

KslKatz is an open-source offensive framework that weaponizes a **no-fix, Microsoft-signed Defender kernel driver (KslD.sys)** as a Bring-Your-Own-Vulnerable-Driver (BYOVD) vehicle to read LSASS memory from kernel mode, bypassing LSA Protection (PPL) entirely. The critical insight for defenders is that **PPL is precisely the control this attack defeats** — enabling PPL is necessary hardening but is not sufficient to stop KslKatz. The attack chain requires four steps: service reconfiguration (T1543.003), registry trust tampering (T1112), driver load and device open (T1068), and finally LSASS credential access (T1003.001). Each step has a distinct, high-confidence detection signal. Defenses must prioritize HVCI/Memory Integrity, the Microsoft Vulnerable Driver Blocklist, and WDAC driver policies — these are the primary BYOVD countermeasures. Credential Guard, which was OFF on the verified lab host, is the complementary PPL-equivalent for kernel-mode reads and should be treated as a priority remediation.

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | `7ba6c119-df44-4cda-8045-b3700c31ba5e` |
| **Test Name** | KslKatz LSASS Credential Dumping Framework (BYOVD PPL Bypass) |
| **MITRE ATT&CK** | [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1112](https://attack.mitre.org/techniques/T1112/), [T1068](https://attack.mitre.org/techniques/T1068/), [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| **Severity** | Critical |
| **Threat Actor** | N/A (open-source offensive framework: vergamota/KslKatz) |
| **Source Intel** | [Ghost in LSASS — Detecting KslKatz Credential Dumping Framework](https://detect.fyi/ghost-in-lsass-detecting-kslkatz-credential-dumping-framework-8645f246aec9) (Omar Tarek Zayed) |
| **Platform** | Windows Endpoint |
| **Architecture** | Multi-stage (4 stages) |

## MITRE ATT&CK Mapping

| Stage | Technique | Tactic | Applicable Mitigations |
|-------|-----------|--------|------------------------|
| 1 | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) — Create or Modify System Service | Persistence (TA0003) | M1040, M1045, M1028, M1018, M1047 |
| 2 | [T1112](https://attack.mitre.org/techniques/T1112/) — Modify Registry | Defense Evasion (TA0005) | M1024 |
| 3 | [T1068](https://attack.mitre.org/techniques/T1068/) — Exploitation for Privilege Escalation (BYOVD) | Privilege Escalation (TA0004) | M1040, M1038, M1050, M1051 |
| 4 | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) — OS Credential Dumping: LSASS Memory | Credential Access (TA0006) | M1025, M1043, M1040, M1028, M1026 |

## The BYOVD PPL-Bypass Chain Explained

Understanding the attack chain is essential for hardening prioritization:

1. **Stage 1 — Service Reconfiguration (T1543.003).** KslKatz modifies the `KslD` Defender kernel service entry under `HKLM\SYSTEM\CurrentControlSet\Services\KslD` using `ChangeServiceConfigW`, redirecting `ImagePath` toward a vulnerable 333 KB `KslD.sys` dropped outside the protected `\drivers\wd\` path. This service key is **not covered by Defender tamper protection** and is writable by any local admin — a critical gap.

2. **Stage 2 — Trust Tampering (T1112).** The KslD driver gates access with a plain-string comparison against an `AllowedProcessName` registry value (stored as an NT device path). KslKatz writes its own process image path to `AllowedProcessName`, defeating the actor check without further verification. **This is the highest-confidence detection signal**: a non-Defender executable writing `AllowedProcessName` under any `Services\KslD` key is essentially unambiguous malicious intent.

3. **Stage 3 — Driver Load and Device Open (T1068).** KslKatz starts the service and opens the `\\.\KslD` kernel device via `CreateFileW` to access its `SubCmd 12` `MmCopyMemory` wrapper. The driver is Microsoft-signed and loads cleanly under Driver Signature Enforcement. HVCI/Memory Integrity blocks this stage by enforcing the Vulnerable Driver Blocklist.

4. **Stage 4 — LSASS Kernel Read (T1003.001).** Using the kernel primitive, KslKatz performs **physical memory reads of LSASS from ring 0** via `MmCopyMemory`, then parses credential material. **PPL is completely bypassed** because the read originates in kernel mode — PPL only gates user-mode handle access. This is the core BYOVD threat.

> **Critical note on PPL:** LSA Protection (RunAsPPL) blocks naive *user-mode* reads of LSASS (e.g., a standard `OpenProcess(PROCESS_VM_READ)` from an unprivileged binary). KslKatz bypasses PPL because its read occurs in kernel mode via the signed driver. Enabling PPL is correct baseline hardening — it stops most commodity credential-dumping tools — but it does not stop KslKatz. Do not interpret a test exit code of 126 at Stage 4 as evidence that the endpoint detects or prevents kslkatz.

## Hardening Recommendations

### The Central Priority: BYOVD Countermeasures

The three controls that directly counter the BYOVD mechanism are:

| Control | What it stops | Priority |
|---------|---------------|----------|
| HVCI (Memory Integrity) + Vulnerable Driver Blocklist | Prevents KslD.sys from loading in kernel | **P0 — Immediate** |
| WDAC driver block policy | Explicit kernel-mode policy; complements blocklist | **P0 — Immediate** |
| Credential Guard (VBS) | Isolates LSASS secrets from kernel-mode reads | **P1 — High** |

### Quick Wins (Immediate — Low Operational Impact)

1. **Enable Microsoft Vulnerable Driver Blocklist.** Since Windows 11 2022 Update, this is on by default for new devices. Verify it is active: `Windows Security > Device Security > Core Isolation > Memory Integrity`. On older systems or Server SKUs, deploy the blocklist binary (`SiPolicy.p7b`) via App Control for Business (see the hardening script).

2. **Enable HVCI (Memory Integrity) if not already enabled.** HVCI enforces the vulnerable driver blocklist and prevents unsigned/untrusted kernel code from executing. Enable via Windows Security app, Intune (`VirtualizationBasedSecurity` CSP), or Group Policy (`Computer Configuration > Administrative Templates > System > Device Guard`).

3. **Enable LSA Protection (RunAsPPL).** While PPL does not stop the BYOVD kernel read path, it stops commodity credential dumpers that do not use BYOVD. Set `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = DWORD 1` (or `2` for Secure Boot enforcement). Verify activation via WinInit Event ID 12: `LSASS.exe was started as a protected process with level: N`.

4. **Enable Attack Surface Reduction rules.** Two ASR rules are directly relevant:
   - `56a863a9-875e-4185-98a7-b882c64b5ce5` — Block abuse of exploited vulnerable signed drivers (prevents writing KslD.sys to disk)
   - `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0` — Block credential stealing from the Windows local security authority subsystem (lsass.exe)
   - Deploy in Audit mode first, then Enforce after validating no false-positive impact.

5. **Restrict service key write access.** The `KslD` service key and Defender-related service keys should not be writable by non-SYSTEM processes. Monitor `HKLM\SYSTEM\CurrentControlSet\Services\KslD` for `ImagePath` and `AllowedProcessName` changes by non-Defender processes (see IR Playbook for event sources).

6. **Enforce least privilege for local admin.** BYOVD service load requires local admin. Reduce local admin surface via LAPS (Local Admin Password Solution), privileged access workstations (PAWs), and Just-In-Time (JIT) admin access.

### Medium-Term (1–2 Weeks — Moderate Implementation Effort)

1. **Enable Windows Defender Credential Guard.** This is the most impactful control against the BYOVD kernel-read path once deployed. Credential Guard runs an isolated LSASS instance (`LSAIso.exe`) inside VBS — kernel-mode reads of the isolated process do not expose the actual credential secrets. Requirements: UEFI Secure Boot, TPM 2.0, VBS-capable hardware (most endpoints from 2017+). Enable via Intune (`CredentialGuard` CSP) or GPO (`Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security`). Verify with: `Get-CimInstance Win32_DeviceGuard | Select-Object SecurityServicesRunning`.

2. **Deploy WDAC App Control driver block policy.** Apply the Microsoft recommended driver block list as an App Control for Business policy (`SiPolicy.p7b`). This provides explicit driver-level blocking independent of the OS-default blocklist update cadence. Test in Audit mode first (`Event Viewer > Applications and Services Logs > Microsoft > Windows > CodeIntegrity > Operational`, filter Event ID 3077 for audit blocks, 3076 for enforced blocks).

3. **Audit `HKLM\SYSTEM\CurrentControlSet\Services` write permissions.** Enumerate all service keys writable by non-SYSTEM users or non-Defender processes. The `KslD` service key in particular should be locked to SYSTEM. Use `Get-Acl` on the key and tighten ACEs. Apply as a GPO Security Baseline item.

4. **Deploy Tamper Protection for Defender service keys.** Although Microsoft Defender Tamper Protection does not currently cover the `KslD` service key `AllowedProcessName`/`ImagePath` values (a gap this test explicitly exercises), verify that tamper protection is enabled broadly for all other Defender registry paths: `HKLM\SOFTWARE\Microsoft\Windows Defender`. Enable via Intune or directly in Windows Security.

5. **Configure advanced audit policy.** Enable `Audit Registry` (Success + Failure) under `Object Access` in Advanced Audit Policy Configuration, applied via GPO. Set a SACL on `HKLM\SYSTEM\CurrentControlSet\Services\KslD` to audit write operations (Event ID 4657). Pipe to SIEM for alerting.

6. **Implement NTLM restriction where feasible.** Rotate local admin passwords immediately if exit 101 was observed on any host (assume credential exposure). Begin NTLM restriction (disable NTLMv1, restrict NTLMv2 scope) to limit the blast radius of LSASS-sourced credential theft.

### Strategic (1–3 Months — Requires Planning and Testing)

1. **Harden local admin account posture organization-wide.** BYOVD attack chains require local admin. Implement Microsoft's tiered admin model: no Domain Admin accounts on endpoints, Tier 0 accounts never touch Tier 1/2 assets, and LAPS for every workstation. This raises the cost of the attack rather than blocking the driver directly.

2. **Deploy Windows Hello for Business (WHfB).** WHfB eliminates reusable password credentials from LSASS memory by using asymmetric cryptography (TPM-backed private keys). Even if LSASS is read, there are no replayable NTLM hashes or Kerberos TGTs to harvest from WHfB-authenticated sessions.

3. **Consider AppLocker / WDAC for application control.** Restrict which user-mode binaries can open handles to LSASS using WDAC Protected Process policies, or monitor via AppLocker audit-mode rules. This does not stop the BYOVD kernel path but reduces the user-mode attack surface and improves detection fidelity.

4. **Establish a Vulnerable Driver Blocklist management process.** Microsoft updates the blocklist quarterly. Establish a process to: (a) review quarterly blocklist releases, (b) deploy updated App Control policies to endpoints, (c) monitor for new BYOVD threats via MSRC advisories and the LOLBAS/LOLDrivers databases.

5. **Evaluate EDR kernel tamper-protection coverage.** Confirm with your EDR vendor whether their solution includes `ObRegisterCallbacks`-based handle stripping for LSASS access AND kernel integrity monitoring for the KslD BYOVD chain specifically. Run this test quarterly to validate coverage as vendor detections evolve.

## Hardening Scripts

> **Note:** Only a Windows hardening script is provided — this test targets `windows-endpoint` exclusively.

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `7ba6c119-df44-4cda-8045-b3700c31ba5e_hardening.ps1` | PowerShell with -Undo and -WhatIf support; idempotent; requires admin |

## Incident Response Playbook

### Understanding the Exit Code Before Responding

Before executing IR procedures, corroborate what a 126 result means on this specific host. A Stage 4 exit 126 has three distinct causes:

| Cause | Registry / Event Indicator | Operational Meaning |
|-------|---------------------------|---------------------|
| **LSA Protection (PPL)** | `RunAsPPL > 0` in LSA registry key AND/OR WinInit Event 12 | Platform config blocked naive user-mode read. PPL does NOT stop the BYOVD kernel path. |
| **Credential Guard** | `LsaCfgFlags > 0` AND VBS active in `Win32_DeviceGuard` | VBS-based isolation contributed to denial. More resistant to kernel-mode reads than PPL alone. |
| **EDR handle-stripping** | PPL = 0, no WinInit Event 12, no Credential Guard | EDR actively prevented the handle. Investigate EDR telemetry to confirm. |

Corroboration commands (run on the affected host):
```powershell
# 1. Check WinInit Event 12 (most authoritative PPL indicator)
wevtutil qe System "/q:*[System[Provider[@Name='Microsoft-Windows-Wininit'] and (EventID=12)]]" /c:1 /rd:true /f:text

# 2. Check LSA registry for PPL
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPLBoot

# 3. Check Credential Guard status
Get-CimInstance Win32_DeviceGuard | Select-Object -Property SecurityServicesRunning, VirtualizationBasedSecurityStatus

# 4. Check HVCI / Memory Integrity status
Get-CimInstance -ClassName Win32_DeviceGuard | Select-Object -Property CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus
```

### Detection Triggers

| Detection Name | Signal | Source | Confidence | Priority |
|----------------|--------|--------|------------|----------|
| KslD AllowedProcessName write by non-Defender process | Non-Defender process writing `AllowedProcessName` (NT device path value) under `Services\KslD` | DeviceRegistryEvents / Sysmon EID 13 | **Critical** | P1 |
| KslD service ImagePath redirect | `ImagePath` value under `Services\KslD` rewritten to non-`\drivers\wd\` path | DeviceRegistryEvents / Sysmon EID 13 | High | P1 |
| KslD.sys / vKslD.sys drop outside wd\ path | `.sys` file matching `KslD` or `vKslD` written outside `%SystemRoot%\System32\drivers\wd\` | DeviceFileEvents / Sysmon EID 11 | High | P1 |
| CreateFile open of `\\.\KslD` device by user-mode process | User-mode process opening the `KslD` device object | EDR device open telemetry | High | P1 |
| OpenProcess to lsass.exe with PROCESS_VM_READ | Non-whitelisted process requesting `VM_READ` on lsass | Sysmon EID 10 / DeviceEvents (OpenProcessApiCall) | High | P1 |
| Kernel driver load from non-standard service path | Driver load event for a Microsoft-signed Defender driver from a service config with unusual `ImagePath` | Sysmon EID 6 / DeviceEvents driver load | Medium | P2 |
| New service creation with kernel driver type | Service type = 0x1 (SERVICE_KERNEL_DRIVER) created under a non-standard service name | Windows Event 7045 / DeviceRegistryEvents | Medium | P2 |

### Containment (First 15 Minutes)

- [ ] Isolate the affected host from the network (EDR isolation / switch port shutdown)
- [ ] Preserve a volatile-memory snapshot if forensically feasible before isolation (RAM dump for credential inventory)
- [ ] Terminate any non-system process holding a handle to lsass.exe or `\\.\KslD`
- [ ] Stop and disable any service with a non-standard `KslD`-named registry key
- [ ] Block the hash of the attacking binary at the EDR/AV layer
- [ ] Alert the Active Directory/identity team: assume all LSASS-resident secrets on this host may be compromised (see Credential Rotation below)

```powershell
# Check for open handles to lsass or KslD device (run as admin on affected host)
Get-Process | Where-Object { $_.Handles -gt 0 } | ForEach-Object {
    $handles = $_.Handles
    Write-Host "$($_.Name) (PID $($_.Id)): $handles handles"
}

# Check for suspicious service with KslD key shape
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\KslD" -ErrorAction SilentlyContinue

# Stop and disable any suspicious KslD-associated service
Stop-Service -Name "KslD" -Force -ErrorAction SilentlyContinue
Set-Service -Name "KslD" -StartupType Disabled -ErrorAction SilentlyContinue
```

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Security Event Log | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | `wevtutil epl Security C:\IR\Security.evtx` |
| System Event Log (WinInit EID 12) | `%SystemRoot%\System32\winevt\Logs\System.evtx` | `wevtutil epl System C:\IR\System.evtx` |
| CodeIntegrity Event Log | `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-CodeIntegrity%4Operational.evtx` | `wevtutil epl "Microsoft-Windows-CodeIntegrity/Operational" C:\IR\CodeIntegrity.evtx` |
| KslD service registry key | `HKLM\SYSTEM\CurrentControlSet\Services\KslD` | `reg export "HKLM\SYSTEM\CurrentControlSet\Services\KslD" C:\IR\KslD_service.reg` |
| LSA registry values | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" C:\IR\Lsa.reg` |
| Dropped driver artifact | `c:\Users\fortika-test\vKslD.sys` (or other staging paths) | `Copy-Item <path> C:\IR\` |
| Process list at time of incident | Memory/EDR telemetry | `Get-Process | Export-Csv C:\IR\processes.csv` |
| Driver load events | Sysmon / EDR | EDR Advanced Hunting: `DeviceEvents where ActionType == "DriverLoad"` |
| OpenProcess events | EDR telemetry | `DeviceEvents | where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"` |

### Determining Whether Credentials Were Exposed

A Stage 4 exit 101 (all stages completed) means the LSASS access primitive was unblocked. Whether actual kernel-mode credential extraction occurred depends on whether the real KslD.sys was loaded:

- **If no KslD.sys driver load event appears in CodeIntegrity/Sysmon EID 6 logs:** The test was F0RT1KA (which loads no real driver). The user-mode OpenProcess handle was acquired unblocked but no kernel read occurred.
- **If a KslD.sys or vKslD.sys driver load event IS in the logs from a non-test process:** Treat as a real attack; assume full credential exposure and rotate all secrets immediately.

```powershell
# Check for KslD driver load events
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" |
    Where-Object { $_.Message -match "KslD" } |
    Format-List TimeCreated, Message
```

### Eradication (After Evidence Collection)

- [ ] Remove modified registry keys (AFTER export):
  ```powershell
  Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KslD" -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -Path "HKLM:\SYSTEM\F0RT1KA-Sandbox" -Recurse -Force -ErrorAction SilentlyContinue
  ```
- [ ] Remove dropped driver artifacts:
  ```powershell
  Remove-Item "c:\Users\fortika-test\vKslD.sys" -Force -ErrorAction SilentlyContinue
  # Scan all staging paths for .sys files dropped by non-OS processes
  Get-ChildItem -Path "C:\F0", "C:\Users\fortika-test" -Filter "*.sys" -ErrorAction SilentlyContinue
  ```
- [ ] Stop and delete any rogue service created under the `KslD` name
- [ ] Re-image the host if a real KslD.sys kernel driver load is confirmed (kernel-mode compromise)

### Credential Rotation (Execute in Parallel with Eradication)

Assume all LSASS-resident secrets on the affected host are compromised if Stage 3 or 4 completed unblocked on a real attack (not a test run):

1. **Rotate the local Administrator password immediately** (LAPS rotation: `Reset-LapsPassword`)
2. **Disable all user accounts that were logged on to the host** during the attack window
3. **Revoke all Kerberos TGTs** for affected accounts: `klist purge` on client; domain controllers issue `netdom /resetpwd`
4. **Rotate all service account credentials** associated with services running on the compromised host
5. **Invalidate all NTLM hashes** by forcing password resets for any domain accounts that authenticated to the host
6. **Check for Pass-the-Hash / Pass-the-Ticket lateral movement** in authentication logs from the time of incident onwards

### Recovery

- [ ] Verify all driver artifacts removed from disk
- [ ] Verify KslD service key is absent or locked down in registry
- [ ] Enable HVCI (Memory Integrity) before returning host to production
- [ ] Enable Credential Guard before returning host to production
- [ ] Verify LSA Protection (RunAsPPL) active via WinInit Event 12
- [ ] Verify ASR rules are in Enforce (not Audit) mode
- [ ] Re-enable network connectivity and monitor for outbound C2 activity
- [ ] Re-run the F0RT1KA test to confirm the controls block the chain

### Corroborating PPL vs EDR in MDE Advanced Hunting

To determine whether a Stage 4 block was PPL (platform config) or active EDR detection:

```kusto
// MDE Advanced Hunting — OpenProcess events to lsass
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !~ "MsMpEng.exe"
    and InitiatingProcessFileName !~ "svchost.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          ActionType, AdditionalFields
| order by Timestamp desc

// MDE Advanced Hunting — Driver load events
DeviceEvents
| where ActionType == "DriverLoad"
| where FileName has_any ("KslD", "vKslD")
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, SHA256
| order by Timestamp desc

// Registry writes to KslD service key
DeviceRegistryEvents
| where RegistryKey has "Services\\KslD"
| where RegistryValueName in~ ("AllowedProcessName", "ImagePath")
| where InitiatingProcessFileName !~ "MsMpEng.exe"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName,
          RegistryValueData, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Post-Incident Questions

1. At which stage was the attack detected/blocked, and by which layer (PPL / Credential Guard / EDR)? If PPL, was HVCI enabled? If not, the BYOVD kernel-read path was not protected.
2. Was Credential Guard active on the affected host? If not, what is the rollout timeline?
3. Was HVCI / Memory Integrity enabled? If not, what prevented KslD.sys from loading?
4. Were the ASR rules for vulnerable signed drivers and LSASS protection in Enforce mode?
5. What was the time between the first detection signal (AllowedProcessName write) and isolation?
6. Were any credentials actually harvested? (Requires confirming no real KslD.sys load.)
7. How did the attacker obtain local admin access to initiate the BYOVD chain?

## References

| Source | Link |
|--------|------|
| Source intelligence — Ghost in LSASS | https://detect.fyi/ghost-in-lsass-detecting-kslkatz-credential-dumping-framework-8645f246aec9 |
| MITRE T1543.003 — Create or Modify System Service | https://attack.mitre.org/techniques/T1543/003/ |
| MITRE T1112 — Modify Registry | https://attack.mitre.org/techniques/T1112/ |
| MITRE T1068 — Exploitation for Privilege Escalation | https://attack.mitre.org/techniques/T1068/ |
| MITRE T1003.001 — LSASS Memory | https://attack.mitre.org/techniques/T1003/001/ |
| MITRE M1040 — Behavior Prevention on Endpoint | https://attack.mitre.org/mitigations/M1040/ |
| MITRE M1025 — Privileged Process Integrity (PPL) | https://attack.mitre.org/mitigations/M1025/ |
| MITRE M1043 — Credential Access Protection (Credential Guard) | https://attack.mitre.org/mitigations/M1043/ |
| MITRE M1024 — Restrict Registry Permissions | https://attack.mitre.org/mitigations/M1024/ |
| Microsoft — Recommended Driver Block Rules | https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules |
| Microsoft — Enable HVCI (Memory Integrity) | https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity |
| Microsoft — Windows Defender Credential Guard | https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/ |
| Microsoft — ASR Rules Reference | https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference |
| Microsoft — LSA Protection (RunAsPPL) | https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection |
| LOLDrivers — vulnerable driver database | https://www.loldrivers.io/ |
| CISA Advisory — BYOVD | https://www.cisa.gov/news-events/cybersecurity-advisories |

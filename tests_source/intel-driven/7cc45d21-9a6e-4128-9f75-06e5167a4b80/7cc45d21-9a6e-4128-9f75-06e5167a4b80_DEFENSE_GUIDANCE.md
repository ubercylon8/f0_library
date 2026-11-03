# Defense Guidance: The Gentlemen — GPO-Driven, Living-off-the-Land Intrusion

**Audience:** financial-sector CISOs, security architecture leads, SOC/threat-hunting managers, and incident-response commanders.

## Executive Summary

The Gentlemen ransomware operation (tracked as **GOLD SHERWOOD** by Sophos CTU; **G1058** and **S9051** in MITRE ATT&CK v20) runs a post-compromise playbook that is almost entirely **living-off-the-land**: legitimate, signed tools abused instead of custom malware. Across the Trend Micro, Sophos CTU (15-incident analysis), and Huntress reporting, one pattern repeats — the actor:

1. **Reconnoiters endpoint protection** in detail (WMI `SecurityCenter2` queries, `sc query` loops against EDR service names, `tasklist | findstr` EDR hunts) and *tailors its evasion to whatever it finds*;
2. **Repurposes Velociraptor — a legitimate DFIR tool — as its C2 implant**, staged under trusted-sounding paths (`C:\PerfLogs`), with AnyDesk, Datto RMM, and Cloudflared as alternate remote-access channels;
3. **Moves laterally with WMI, PsExec-style ADMIN$ drops, NetExec, and RDP**, never dropping an executable that an AV signature would catch;
4. **Pushes payloads domain-wide by abusing Group Policy** — including launching `gpme.msc` against LDAP-addressed policy objects and deploying `--password`-keyed payloads through NETLOGON; and
5. **Persists redundantly** with masqueraded scheduled tasks (`WindowsConnSvc`-style names, `/ru SYSTEM`, `/sc minute`), decoy services with legitimate-tool display names, and **newly created local accounts elevated straight into Administrators** (`itadmin`, `ldap` shapes).

Because nearly every step abuses sanctioned functionality, **signature-based and hash-based defenses add almost no coverage here**. The defenses that work are: allowlisting of remote-access/DFIR tooling, ASR rules that break WMI/PSExec child-process execution, SMB admin-share and signing restrictions, GPO change auditing, and high-signal alerting on scheduled-task/service/account-creation events (4698 / 7045 / 4720+4728). This guide maps each of the five emulated kill-chain stages to detection, hunting, and prevention guidance, ships an idempotent Windows hardening script, and includes an incident-response playbook tuned to this actor's artifacts.

**Priority recommendations (TL;DR):**
1. Enable the Defender ASR rule **"Block process creations originating from PSExec and WMI"** (audit first) — it degrades Stages 3 and 5 of the chain directly.
2. Allowlist remote-access and DFIR tooling (Velociraptor, AnyDesk, Cloudflared, Datto RMM, NetExec) via AppLocker/WDAC; **no legitimate end-user should ever run Velociraptor or an RMM agent** on a workstation.
3. Turn on GPO change auditing (Directory Service Changes + SYSVOL file SACLs) and alert on *any* `Registry.pol`/`gpt.ini` write, `New-GPO` invocation, or `gpme.msc /gpobject:` command line.
4. Alert on the persistence triad — 4698 (task created, especially `/ru SYSTEM` + minute-repeat), 7045 (service installed with a temp-path binPath), and 4720 followed by 4732/4728 (account created then group-added).
5. Deploy PowerShell Script Block logging — the actor's encoded `-enc` probes and DCOM fallbacks are otherwise invisible.

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | 7cc45d21-9a6e-4128-9f75-06e5167a4b80 |
| **Test Name** | The Gentlemen: GPO-Driven, Living-off-the-Land Intrusion |
| **MITRE ATT&CK** | [T1518.001](https://attack.mitre.org/techniques/T1518/001/), [T1087](https://attack.mitre.org/techniques/T1087/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1036](https://attack.mitre.org/techniques/T1036/), [T1219](https://attack.mitre.org/techniques/T1219/), [T1047](https://attack.mitre.org/techniques/T1047/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/), [T1021.001](https://attack.mitre.org/techniques/T1021/001/), [T1484.001](https://attack.mitre.org/techniques/T1484/001/), [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1136.001](https://attack.mitre.org/techniques/T1136/001/) |
| **Severity** | Critical |
| **Threat Actor** | The Gentlemen RaaS / GOLD SHERWOOD ([G1058](https://attack.mitre.org/groups/G1058), encryptor [S9051](https://attack.mitre.org/software/S9051)) |
| **Platform** | Windows endpoint (Domain Controller / AD-dependent stages from the actor's real tradecraft) |
| **Subcategory** | Ransomware (post-compromise LOLBin emulation; BYOVD and encryption owned by companion tests) |
| **Primary sources** | Trend Micro (2025-09), Sophos CTU (2026-09, 15 incidents), Huntress (2026-05); Microsoft, Check Point, ESET analyses of S9051/G1058 |

## MITRE ATT&CK Mapping

| Technique | Tactic (stage) | Applicable Mitigations (ATT&CK) |
|-----------|----------------|----------------------------------|
| T1518.001 — Security Software Discovery | Discovery (S1) | *No preventive mitigation* (abuse of system features) — **detection-first**: process/command-line telemetry (DET0016) |
| T1087 — Account Discovery | Discovery (S1) | M1028 Operating System Configuration (disable admin-account enumeration on elevation), M1018 User Account Management |
| T1082 — System Information Discovery | Discovery (S1) | *No preventive mitigation* — detection-first |
| T1036 — Masquerading | Defense Evasion (S2) | M1038 Execution Prevention (attribute-based app control), M1040 Behavior Prevention on Endpoint, M1045 Code Signing, M1022 Restrict File/Directory Permissions, M1049 Antivirus/Antimalware, M1047 Audit, M1018 User Account Management |
| T1219 — Remote Access Tools | Command and Control (S2) | M1042 Disable or Remove Feature or Program, M1038 Execution Prevention (allowlist), M1037 Filter Network Traffic, M1031 Network Intrusion Prevention, M1034 Limit Hardware Installation |
| T1047 — WMI | Execution / Lateral Movement (S3) | M1040 Behavior Prevention (ASR "Block process creations from PSExec/WMI"), M1038 Execution Prevention (WDAC can block `wmic.exe`), M1026 Privileged Account Management, M1018 User Account Management (restrict remote WMI/DCOM) |
| T1021.002 — SMB/Windows Admin Shares | Lateral Movement (S3) | M1035 Limit Access to Resource Over Network (disable admin shares where feasible), M1037 Filter Network Traffic (block lateral SMB), M1027 Password Policies, M1026 Privileged Account Management |
| T1021.001 — RDP | Lateral Movement (S3) | M1030 Network Segmentation, M1032 MFA, M1042 Disable RDP where unnecessary, M1035 RD Gateway, M1028 OS Configuration (session limits), M1026 Privileged Account Management, M1047 Audit |
| T1484.001 — Group Policy Modification | Defense Evasion / Priv. Esc. (S4) | M1047 Audit (BloodHound for GPO ACL abuse), M1018 User Account Management (WMI/security filtering, restrict GPO edit rights) |
| T1053.005 — Scheduled Task | Persistence (S5) | M1018 User Account Management, M1028 OS Configuration (force authenticated-context tasks), M1026 Privileged Account Management, M1047 Audit |
| T1543.003 — Windows Service | Persistence (S5) | M1018 User Account Management, M1028 OS Configuration (Driver Signature Enforcement), M1040 Behavior Prevention (vulnerable-driver blocklist), M1045 Code Signing, M1047 Audit |
| T1136.001 — Local Account | Persistence (S5) | M1026 Privileged Account Management (limit who can create accounts), M1032 Multi-factor Authentication |

## Stage-by-Stage Defense Guidance

### Stage 1 — Reconnaissance: security products, accounts, domain context (T1518.001 / T1087 / T1082)

**Actor behavior (emulated):** `wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState` (with a `Get-CimInstance -Namespace root/SecurityCenter2` fallback on WMIC-deprecated hosts), `sc query` loops against named EDR services (`WinDefend`, `Sense`, `CSFalconService`, `SepMasterService`, `SophosMMS`, `WdNisSvc`), `tasklist /v /fo csv | findstr /i "csagent sensedefend sophos sep"`, the `1.bat`-style mass enumeration (`net user /domain`, `net user <acct> /domain`, `net group "domain admins" /domain`, `net group "Enterprise admins" /domain`, `net localgroup administrators`, `net localgroup __vmware__*`), `whoami /all`, `hostname`, `systeminfo`, domain queries, and an encoded PowerShell PDC probe (`powershell -noni -nop -w 1 -enc` of `(Get-ADDomain).PDCEmulator`).

**Detection:**
- **Command-line telemetry is the whole game.** Require 4688 with `ProcessCreationIncludeCmdLine_Enabled` (or Sysmon EID 1). The strongest signals:
  - Any command line containing `SecurityCenter2` or `AntiVirusProduct` — near-zero benign workstation use.
  - `sc query` / `sc.exe query` repeated against *multiple distinct* AV/EDR service names from one host in a short window (burst correlation, not single-event).
  - `tasklist` piped to `findstr` with EDR process-name terms (`csagent`, `sense`, `sophos`, `csfalcon`).
  - `net.exe`/`net1.exe` argument sets: `user /domain`, `group "domain admins" /domain`, `localgroup administrators`, and especially `localgroup __vmware__` (actor fingerprint).
  - `powershell.exe` with `-w 1` (hidden window) plus `-enc`/`-encodedcommand` — correlate with 4104 script-block decode.
  - `systeminfo` + `whoami /all` + `net user /domain` clustering from a single process tree in < 2 minutes = scripted recon (Sigma-style frequency detection).
- **Hunting:** sweep 30 days of process telemetry for `SecurityCenter2` and `PDCEmulator` strings; hunt `findstr`/`findstr.exe` parents of `tasklist`; enumerate hosts where `net group "domain admins" /domain` executed outside Tier-0 admin workstations.
- Trend Micro's key observation: the actor *adapts to the EDR it finds* — so a SecurityCenter2 query is not noise, it is a leading indicator of tailored evasion to come.

**Prevention:**
- M1028: disable enumeration of administrator accounts on UAC elevation (`EnumerateAdministrators` = 0 via GPO).
- Restrict who can run `net.exe`/`wmic.exe` remoting from standard user contexts via AppLocker (attribute-based, not filename — M1038).
- Segment and delegate: only Tier-0 jump hosts should resolve PDC/AD management tooling; `Get-ADDomain` cmdlets should not exist on workstations (RSAT removal).

### Stage 2 — Masqueraded remote-access deployment: Velociraptor as C2 (T1036 / T1219)

**Actor behavior (emulated):** a "client" binary named `Velociraptor.exe` staged in a **PerfLogs-style directory** (Sophos CTU: tools staged in `C:\PerfLogs` because it is "not commonly scrutinized by security controls"), alongside the exact deployment artifacts a real Velociraptor client leaves behind: `client.config.yaml` (frontend `server_urls`, client nonce, CA certificate block, `pinned_server_name`) and `client.writeback`. The client then beacons the frontend with `POST /control?v=1&client_id=C.<hex>&nonce=<hex>` using a `Velociraptor <version> (windows amd64)` User-Agent, on the default frontend port (8000; fallback 8800). The actor's other observed remote-access tools: **AnyDesk, Datto RMM, Cloudflared** (as an installed Windows service), plus masqueraded names modeled on Windows components (`svchost32.exe`, service/task names like `WindowsConnSvc`). MITRE v20 adds: G1058 **fabricates version-info metadata of payload files** to pass casual inspection (ESET).

**Detection:**
- **File telemetry:** creation of `Velociraptor.exe`, `client.config.yaml`, or `client.writeback` anywhere on a non-sanctioned host is a P1 finding — these are DFIR-deployment artifacts, and DFIR tooling never self-deploys to production workstations. Watch `C:\PerfLogs` specifically: on a clean Windows build it should contain *nothing*; any file-create there is anomalous (M1022 permission restrictions also apply).
- **Network:** `User-Agent` matching `^Velociraptor \d`; POST URIs matching `/control\?v=1&client_id=C\.[0-9a-f]+` to any non-sanctioned destination (Velociraptor frontends are usually on port 8000/8889); AnyDesk/Cloudflared/Datto RMM traffic patterns (AnyDesk discovery on 6568/443 relay `*.net.anydesk.com`; Cloudflared outbound QUIC/7844 to `region1.v2.argotunnel.com`).
- **Masquerade analytics (T1036):** executables outside `%SystemRoot%`/`%ProgramFiles%` whose `OriginalFilename`/`FileDescription`/`Company` version-info claims Microsoft or a known vendor but whose signature does not match (covers G1058's fabricated version info); binaries in `C:\Windows\Temp` with `svchost`-adjacent names; service display names that name legitimate products ("Velociraptor Client") paired with binPaths in temp directories.
- **Hunting:** inventory your estate for *every* Velociraptor/RMM binary. Any endpoint where these appear without a change record is presumptively compromised — this is the single highest-confidence sweep in this guide.

**Prevention:**
- **Allowlist remote-access/DFIR tooling (M1042/M1038):** AppLocker/WDAC policy that denies `velociraptor*.exe`, `anydesk.exe`, `cloudflared.exe`, `DattoRMM*.exe`, `netexec*`/`nxc*` by publisher+product attribute (not just filename), with an explicit, documented exception process for your own IR team's tools (ideally deployed from a signed, version-pinned internal share only).
- Remove `wmic`/legacy tooling where unneeded; strip RSAT/GPMC from workstations (Stage 4 prerequisite).
- Egress filtering (M1037): workstations should reach the internet only via the corporate proxy; direct outbound 8000/8889/7844/6568 should be blocked at the firewall — this kills both Velociraptor frontends and Cloudflared tunnels.
- `C:\PerfLogs`, `C:\Windows\Temp`: ACL them to SYSTEM/Administrators-write only and alert on writes (M1022).

### Stage 3 — LOLBin lateral movement: WMI / SMB / NetExec / RDP (T1047 / T1021.002 / T1021.001)

**Actor behavior (emulated):** `wmic /node:<target> process call create "cmd.exe /c ..."` with a PowerShell DCOM fallback (`New-CimSessionOption -Protocol DCOM` + `Invoke-CimMethod Win32_Process.Create` — the required shape on WMIC-deprecated Win11 24H2+); a NetExec-shaped probe (`nxc smb <target> -u <user> -p --sam`); `net use \\<target>\ADMIN$` followed by a payload drop into `ADMIN$\Temp` (the PsExec prerequisite) and session teardown; and an RDP beat — the actor flips `fDenyTSConnections` and opens 3389 (the emulation only *reads* the value and probes the port). Real-actor corroboration from ATT&CK v20: S9051 uses WMI for execution and volume enumeration, SMB/admin shares for payload distribution, and enables RDP in victim environments.

**Detection:**
- **WMI (T1047):** `wmic.exe` with `/node:` on workstations; `WmiPrvSE.exe` spawning `cmd.exe`/`powershell.exe` (classic, still gold); `Microsoft-Windows-WMI-Activity/Operational` events (5857–5861) for unusual provider activity; PowerShell 4104 containing `Invoke-CimMethod` + `Win32_Process` + `-Protocol DCOM`.
- **SMB (T1021.002):** 5140 (share accessed) / 5145 (detailed share access) for `ADMIN$`/`C$`/`IPC$` initiated from workstation IPs — workstations should almost never mount admin shares of other hosts; `net.exe use` command lines referencing `\\*\ADMIN$`; PsExec-family event 7045 with binPath containing `\\*\ADMIN$` (PSEXESVC).
- **NetExec:** any process named `nxc.exe`/`netexec.exe` (it should never exist on your estate), or `--sam`/`--lsa`/`--shares` argument shapes in command-line telemetry; network-side, bursts of failed 4625 type 3 or SMB null-session patterns from a single source.
- **RDP (T1021.001):** registry-value change (Sysmon 13 / 4657) on `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` to 0, firewall-rule creation for port 3389 (4946/4947/4948 or `netsh advfirewall` command line), and 4624 type-10 logons between workstations.
- **Hunting:** chart workstation-to-workstation 445/135/3389 flows for 30 days — in a hardened financial-sector network, that matrix should be nearly empty; any persistent edges are your compromise candidates.

**Prevention:**
- **ASR rule "Block process creations originating from PSExec and WMI"** (`d1e49aac-8f56-4280-b9ba-993a6d77406a`, M1040) — deploy in audit, then block. It directly breaks the WMI-child and PsExec patterns. Document legitimate exceptions (SCCM, admin tooling) first.
- **M1035:** remove default admin shares where feasible (`AutoShareWks`/`AutoShareServer` = 0 on hosts that don't need them) and require SMB signing (M1037 at host level: `RequireSecuritySignature`), disable SMBv1.
- Restrict remote WMI/DCOM (M1018/M1026): default DCOM remote-launch rights should exclude non-admin principals; block inbound 135 + RPC dynamic range at the host firewall on workstations; never reuse local-admin credentials across systems (LAPS).
- RDP (M1030/M1032/M1042): disable RDP on workstations by policy, enforce NLA (`UserAuthentication=1`) where it must stay, force RD Gateway for servers, MFA on all remote logins.
- NetExec is an attack tool, not a business tool — its presence alone justifies allowlist enforcement.

### Stage 4 — Enterprise deployment via Group Policy abuse (T1484.001)

**Actor behavior (emulated + real):** Trend Micro observed `gpme.msc /s /gpobject:"LDAP://CN={GUID},CN=Policies,CN=System,DC=...,DC=local"` — the Group Policy Management Editor launched directly against an LDAP-addressed policy object — plus PowerShell GPO cmdlets (`New-GPO`) and deployment through the domain's NETLOGON share (`\\<domain>\NETLOGON\<payload>.exe --password <8-byte key>`, `cmd /c \\NETLOGON\avkill.bat`). The SYSVOL-side writes that betray the manipulation are `gpt.ini` (version bump) and `Machine\Registry.pol` (PReg binary). ATT&CK v20: S9051 modifies DC Group Policy via a PowerShell script that enables **simultaneous domain-wide ransomware detonation** — this stage is the trigger for the blast, which is why it must be caught in minutes.

**Detection:**
- **Command-line/process:** any `gpme.msc` with `/gpobject:` (attack-shaped; admins edit GPOs from the GPMC, not by LDAP-path command line); `New-GPO`, `New-GPLink`, `Set-GPRegistryValue`, `Set-GPOImmediateTask` (SharpGPOAbuse/Empire lineage) in PowerShell 4104/4688; `mmc.exe` launched on a DC from a non-console session.
- **Directory events (DC):** enable *Directory Service Changes* auditing → 5136/5137/5141 on `groupPolicyContainer` objects (watch `gPCFileSysPath`, `versionNumber`, `gPLink` changes), especially outside change windows.
- **File events (SYSVOL):** SACL-based auditing on `\<domain>\SYSVOL\<domain>\Policies` for writes to `gpt.ini`, `Registry.pol`, `ScheduledTasks.xml`, `GptTmpl.inf`, and any `Scripts` writes (5145 / file-audit 4663). Correlate writer process: `svchost.exe` (normal, during gpupdate-engineered edits) vs `powershell.exe`/`mmc.exe`/unknown (abuse).
- **NETLOGON:** alert on new `.exe`/`.bat` writes to NETLOGON/SYSVOL shares and on any execution with a `--password` argument from those paths.
- **Hunting:** regularly diff GPO inventory (GUID → displayName → version → owner → last-write); any GPO whose `versionNumber` changed without a corresponding change ticket is an incident. Run BloodHound (M1047) to find principals with `WriteGPO`/`GpLinkEdit`-equivalent rights that shouldn't have them — the Gentlemen's GPO abuse requires exactly those misdelegations.

**Prevention:**
- Tighten GPO ACLs (M1018): only a small Tier-0 group should have edit rights on any GPO (Default Domain Policy and Default Domain Controllers Policy above all); quarterly review of GPO delegation; remove GPO-edit from workstations entirely.
- Restrict NETLOGON/SYSVOL write access to Domain Admins + a change-managed service account; AV/EDR file rules on executable content in both shares (no legitimate `.exe` belongs in NETLOGON in most estates).
- Block `mmc.exe`/RSAT on workstations and non-admin hosts (M1038) so `gpme.msc` cannot run outside sanctioned admin workstations.
- Version-pin and monitor GPO backups; enable change-window alerting for 5136 on `groupPolicyContainer`.

### Stage 5 — Redundant persistence: task, service, privileged account (T1053.005 / T1543.003 / T1136.001)

**Actor behavior (emulated + real):** a scheduled task named **`WindowsConnSvc`** (a deliberately plausible name that is *not* a real Windows task) created with `/sc minute /mo 2 /ru SYSTEM`, action pointing at a temp-path binary (`C:\Windows\Temp\svchost32.exe client <C2>` — Huntress IO; both task and binary masquerade as Windows components); a decoy service whose **display name masquerades as a legitimate product ("Velociraptor Client")** with a binPath in a temp directory, never started until needed; and a **new local account created and immediately added to local Administrators** (Sophos: `net1 localgroup administrators itadmin /add`, `net group "domain admins" ldap /add /domain` — the 4720→4728/4732 sequence). ATT&CK v20 adds S9051 re-enabling discovery/network services (`fdrespub`, `fdPHost`, `SSDPSRV`, `upnphost`) to `start=auto` via `sc.exe` — watch that exact shape too.

**Detection (the persistence triad — alert on all three, in priority order):**
- **4698/4699/4700/4701** (requires *Other Object Access Events* auditing): task creation with `/ru SYSTEM` (or `S-1-5-18` in the task XML), minute-interval schedules (`PT2M`-style repetition), task actions in `%TEMP%`/`C:\Windows\Temp`, or task names that are *near* but not equal to real Windows task names (`WindowsConnSvc` vs the real `WpnTask`/`WininetCache`...). Maintain a baseline of the ~200 legitimate task names per OS build and alert on out-of-baseline creations.
- **7045** (Service Installation auditing): new service where `ImagePath`/binPath is in a temp/user directory, or `DisplayName` matches a known product name (Velociraptor, AnyDesk, Cloudflared) not deployed by IT; also 7040 for start-type flips on `fdrespub`/`fdPHost`/`SSDPSRV`/`upnphost`/`TermService`.
- **4720 (account created) + 4732/4728 (added to Administrators/domain group)** within a short window: on a financial-sector estate, local-account creation should be rare and always change-ticketed. Also watch 4722 (enabled), 4724 (password reset), and 4740 (lockout) on suspect accounts. The Gentlemen's `itadmin`/`ldap` shapes are generic on purpose — the *sequence* is the signature.
- **Hunting:** `Get-ScheduledTask` diff against a gold-image task list across the fleet; `Get-Service` where `BinaryPathName` resolves outside `%SystemRoot%`/`%ProgramFiles%`; local SAM dump comparison (`net user` census per host) against HR-joined identity sources; group membership drift for `Administrators` (local) and `Domain Admins`.

**Prevention:**
- M1018/M1026: only administrators can create tasks/services/accounts by default — verify with attack-path tooling that no helpdesk groups hold `SeCreateGlobalPrivilege`-adjacent service/task write rights; remove stale delegated "account operator" grants.
- AppLocker/WDAC blocks the temp-path binaries these tasks/services point at (execution never succeeds even if registration does).
- Consider Microsoft's "force tasks to run under the context of the authenticated account" hardening (M1028) and the Increase Scheduling Priority right restricted to Administrators.
- MFA (M1032) on all interactive logons degrades the utility of the actor's backdoor accounts.

## Hardening Recommendations

### Quick Wins (Immediate — Low Impact)
1. Run `7cc45d21-9a6e-4128-9f75-06e5167a4b80_hardening.ps1 -WhatIf`, review, then apply: PowerShell Script Block + Module logging, command-line auditing, the full audit-policy visibility pack (task/service/account/share events), WMI-Activity tracing, SMB signing, and the PSExec/WMI ASR rule.
2. Deploy the ASR rule in **audit** mode for one week, analyze 1124/1125-style events, then flip to block (exceptions first: SCCM, approved admin tooling).
3. Enable *Directory Service Changes* auditing and SYSVOL/NETLOGON SACLs on all DCs; alert on `groupPolicyContainer` 5136 and on executable writes to NETLOGON.
4. Egress: block direct outbound 8000/8889 (Velociraptor frontends), 7844 (Cloudflared), and AnyDesk relay paths at the perimeter proxy/firewall.
5. Fleet sweep (one-time hunt): Velociraptor/AnyDesk/Cloudflared/Datto/NetExec binaries anywhere; `C:\PerfLogs` contents; `WindowsConnSvc` task; `itadmin`/`ldap` and any non-ticketed local accounts.
6. Restrict `C:\PerfLogs` and `C:\Windows\Temp` write ACLs and add file-create alerts on both.

### Medium-Term (1–2 Weeks — Medium Impact)
1. Allowlisting program for RMM/DFIR tooling (AppLocker/WDAC, publisher+product rules) with a formal IR-tool exception process — coverage for Velociraptor, AnyDesk, Datto RMM, Cloudflared, NetExec.
2. LAPS everywhere; no shared/reused local-admin passwords (M1026/M1027); block workstation-to-workstation 445/135/3389 at the segment firewall (M1037/M1030).
3. Remove RSAT/GPMC and `mmc.exe` from workstations; strip unneeded WMI remoting paths (block inbound RPC 135 + dynamic range on workstations).
4. RDP hardening: disable on workstations by policy, NLA + RD Gateway + MFA on servers (M1032/M1035); alert on `fDenyTSConnections`→0 changes.
5. GPO ACL minimization: Tier-0-only edit rights, quarterly BloodHound pass for `WriteGPO` edges (M1047).
6. SOC content: the persistence-triad (4698-SYSTEM-minute, 7045-temp-binPath, 4720→4732) and the Stage-1 recon correlations (`SecurityCenter2`, EDR-name `sc query` bursts, `net localgroup __vmware__`) wired as high-priority alerts.

### Strategic (1–3 Months — Requires Planning)
1. **WDAC in enforce mode** (signed-and-allowed by default) across workstations — the structural answer to a LOLBin adversary; staged via audit-mode baselines and ISG.
2. **Tiered administration model** (Tier-0/1/2) with authentication-policy silos: no domain-admin credentials on workstations, no GPO/SYSVOL touch from Tier-1/2.
3. **EDR-telemetry assumption**: assume the actor profiles your EDR before acting (Stage 1); adopt EDR counter-measures — tamper protection, unsignable sensor components, decoy service names ("canary" EDR-named services that alert on `sc query`).
4. Change-managed IT: all task/service/account/GPO changes flow through workflow (ServiceNow/Intune) so that *any* out-of-band 4698/7045/4720/5136 is by definition anomalous — collapses detection from behavioral to deterministic.
5. Purple-Team validation: re-run this F0RT1KA bundle quarterly against a hardened build to measure control drift (per-stage exit codes show which layer caught what).

## Hardening Scripts

> **Note:** Only scripts for the test's target platform are included. This is a **Windows-endpoint** test — no Linux/macOS scripts ship with this bundle.

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `7cc45d21-9a6e-4128-9f75-06e5167a4b80_hardening.ps1` | Idempotent PowerShell: PowerShell logging, audit-policy visibility pack (4688/4698/7045/4720/5140/5136), ASR PSExec/WMI rule, SMB signing + admin-share restrictions, RDP NLA enforcement, WMI-Activity tracing, optional RMM/DFIR egress blocks. Supports `-WhatIf` and `-Undo`. |

**Caution:** the script disables default admin shares and enables ASR blocking — validate in a pilot ring first (both can affect management tooling such as SCCM/PsExec-based admin workflows).

## Incident Response Playbook — The Gentlemen

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| DFIR/RMM tool on endpoint | `velociraptor*.exe` / `client.config.yaml` / `anydesk.exe` / `cloudflared.exe` file-create or execution on non-sanctioned host | High | **P1** |
| PerfLogs staging | Any file created in `C:\PerfLogs` | High | **P1** |
| SecurityCenter2 recon | Process cmdline contains `SecurityCenter2` or `AntiVirusProduct` on workstation | High | P2 |
| EDR-hunt burst | ≥3 distinct EDR service names queried via `sc`/`tasklist+findstr` within 10 min from one host | High | P2 |
| GPO modification | 5136 on `groupPolicyContainer`, `New-GPO`/`gpme.msc /gpobject:` cmdline, or `Registry.pol`/`gpt.ini` write in SYSVOL | High | **P1** |
| NETLOGON payload | Executable/batch written to NETLOGON, or execution of `\\<domain>\NETLOGON\*.exe --password ...` | High | **P1** |
| WMI/DCOM remote exec | `wmic /node:`, `WmiPrvSE.exe` → `cmd.exe`/`powershell.exe`, `Invoke-CimMethod Win32_Process` | High | **P1** |
| ADMIN$ session from workstation | 5140/5145 on `ADMIN$` with source = workstation IP, or `net use \\\\*\\ADMIN$` | Medium-High | P2 |
| RDP enablement | `fDenyTSConnections` → 0 change; new firewall rule for 3389; 4624 type 10 workstation→workstation | Medium | P2 |
| Masqueraded task | 4698 with SYSTEM context + minute-repeat + temp-path action, or out-of-baseline task name | High | **P1** |
| Masqueraded service | 7045 with temp-dir binPath or legit-product DisplayName not in CMDB | High | **P1** |
| Backdoor account | 4720 followed by 4732/4728 (→ Administrators) within 1 h; 4724 on rarely-touched account | High | **P1** |
| Velociraptor network shape | UA `Velociraptor …` or `POST /control?...client_id=C.` to non-sanctioned destination | High | **P1** |

**Priority interpretation:** any **P1** trigger should open a Sev-1 incident immediately — this actor moves from foothold to domain-wide GPO deployment in hours (Sophos CTU observed rapid RDP pivots between internal systems).

### Containment (First 15 Minutes)
- [ ] Isolate affected host(s) via EDR network-containment — **do not power off** (volatile evidence: WMI traces, task XML, sessions).
- [ ] If GPO tampering is suspected: **freeze Group Policy processing** — block SMB/RPC from workstations to DCs at the segment firewall, and place DCs in enhanced monitoring; unlink the suspect GPO *after* evidence capture if detonation risk is imminent.
- [ ] Disable/quarantine accounts implicated in 4720→4732 sequences and any account seen executing WMI/ADMIN$ lateral movement; force password resets + session revocation (consider `krbtgt` if DC compromise confirmed).
- [ ] Kill and block Velociraptor/RMM processes at the EDR; add binary blocklist entries (filename + hash + publisher).
- [ ] Block egress ports 8000/8889/7844 and AnyDesk relays perimeter-wide until scope is known.
- [ ] Preserve volatile evidence **before** further mutation (next section).

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Security event log | System/Security/Sysmon | `wevtutil epl Security C:\IR\Security.evtx` (+ `System`, `Microsoft-Windows-WMI-Activity/Operational`) |
| PowerShell operational logs | `Microsoft-Windows-PowerShell/Operational`, `/4104 ScriptBlock` | `wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\IR\PS-Operational.evtx` |
| Task Scheduler defs | `C:\Windows\System32\Tasks\` | `robocopy C:\Windows\System32\Tasks C:\IR\Tasks /E /COPYALL` + `schtasks /query /xml > C:\IR\tasks.xml` (look for `WindowsConnSvc`) |
| Service database | `HKLM\SYSTEM\CurrentControlSet\Services` | `reg export HKLM\SYSTEM\CurrentControlSet\Services C:\IR\services.reg /y` (grep temp binPaths, "Velociraptor Client") |
| Local SAM accounts | `HKLM\SAM\SAM\Domains\Account\Users\Names` | `reg save HKLM\SAM C:\IR\SAM.hive` + `reg save HKLM\SYSTEM C:\IR\SYSTEM.hive` (offline parse for 4720-shape backdoors) |
| Masquerade staging | `C:\PerfLogs`, `C:\Windows\Temp` | `robocopy C:\PerfLogs C:\IR\PerfLogs /E /COPYALL`; `dir /a C:\Windows\Temp >> C:\IR\temp.txt` (grab `svchost32.exe`, `client.config.yaml`, `client.writeback`) |
| WMI repository traces | `Microsoft-Windows-WMI-Activity/Operational` | `wevtutil epl "Microsoft-Windows-WMI-Activity/Operational" C:\IR\wmi.evtx` |
| GPO objects (DC) | `\<domain>\SYSVOL\<domain>\Policies\{GUID}` | `robocopy \\<dc>\SYSVOL C:\IR\SYSVOL-Backup /MIR` (verify gpt.ini version + Registry.pol against backups) |
| NETLOGON contents (DC) | `\<domain>\NETLOGON` | `dir /s /t:w \\<dc>\NETLOGON >> C:\IR\netlogon.txt` + hash any `.exe`/`.bat` |
| RDP config state | `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` | `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections > C:\IR\rdp.txt` |
| EDR telemetry | Console | Export process tree, network connections (8000/8889/3389/445), and file-mods for the affected window |

### Eradication
- [ ] Delete masqueraded scheduled tasks (verify by GUID, e.g. `WindowsConnSvc`), then **hunt fleet-wide** for the same shapes.
- [ ] Remove decoy services (`sc delete <name>`); validate every 7045 in the incident window against the CMDB.
- [ ] Delete backdoor accounts *after* SAM/log capture; scrub `Administrators` and `Domain Admins` membership against HR-sourced identity data.
- [ ] Remove staged tooling: `C:\PerfLogs`, `C:\Windows\Temp\svchost32.exe`, Velociraptor client dirs, AnyDesk/Cloudflared installs (uninstall cleanly — check for their own services and scheduled tasks).
- [ ] Revert malicious GPO edits: restore `gpt.ini` version and `Registry.pol` from backup (or GPO versioning), unlink/delete the actor-created GPO, and force `gpupdate /force` *after* the fix is verified.
- [ ] Remove NETLOGON payloads; reset any credentials referenced in `--password` deployments.
- [ ] Patch/resolve the initial-access vector (out of this test's scope but mandatory) and confirm no residual WMI event-subscription persistence (`__EventFilter`/`__FilterToConsumerBinding` audit).

### Recovery
- [ ] Verify all artifacts removed: task diff vs gold image clean, service list CMDB-clean, account census matches identity source, SYSVOL diff vs backup clean.
- [ ] Restore modified configurations: `fDenyTSConnections`, firewall rules (remove actor's 3389 rules), service start types for `fdrespub`/`fdPHost`/`SSDPSRV`/`upnphost` back to standard.
- [ ] Re-enable security controls and re-deploy the hardening script baseline; rotate all credentials touched by the intrusion (local admin via LAPS rotation, service accounts, KRBTGT ×2 if DC compromise).
- [ ] Reconnect hosts to the network in staged rings; monitor for re-beaconing (UA/`client_id=C.` patterns) for ≥14 days.
- [ ] Validate backups unaffected before restoring any encrypted data (encryption itself is out of this bundle's scope but is the actor's end-state).

### Post-Incident
1. **How was the attack detected?** If the first trigger was Stage 5 persistence (or later), treat Stages 1–4 as control failures: recon, masqueraded C2, lateral movement, and GPO abuse all ran undetected. Add the missing Stage-1/2/3/4 detections from this guide.
2. **What was detection-to-response time?** The Gentlemen's blast chain (GPO → domain-wide detonation) compresses the useful window to hours — measure yours and rehearse.
3. **What would have prevented this?** In order of leverage: WDAC allowlisting (kills Velociraptor/RMM execution), ASR PSExec/WMI block (kills LOLBin lateral), GPO ACL tiering (kills Stage 4), the persistence-triad alerts (catches Stage 5 within minutes).
4. **Control drift check:** re-run the F0RT1KA Gentlemen bundle against a rebuilt host to confirm the hardening baseline changes per-stage outcomes from 101 (unprotected) to 126/105 (prevented/quarantined).
5. Feed IOCs (task name, staging paths, UA, `client_id=C.` pattern, account names) back into the SOC and threat-intel platform.

## References
- MITRE ATT&CK: [T1518.001](https://attack.mitre.org/techniques/T1518/001/), [T1087](https://attack.mitre.org/techniques/T1087/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1036](https://attack.mitre.org/techniques/T1036/), [T1219](https://attack.mitre.org/techniques/T1219/), [T1047](https://attack.mitre.org/techniques/T1047/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/), [T1021.001](https://attack.mitre.org/techniques/T1021/001/), [T1484.001](https://attack.mitre.org/techniques/T1484/001/), [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1136.001](https://attack.mitre.org/techniques/T1136/001/), group [G1058](https://attack.mitre.org/groups/G1058), software [S9051](https://attack.mitre.org/software/S9051)
- Mitigations: [M1018](https://attack.mitre.org/mitigations/M1018), [M1026](https://attack.mitre.org/mitigations/M1026), [M1027](https://attack.mitre.org/mitigations/M1027), [M1028](https://attack.mitre.org/mitigations/M1028), [M1030](https://attack.mitre.org/mitigations/M1030), [M1031](https://attack.mitre.org/mitigations/M1031), [M1032](https://attack.mitre.org/mitigations/M1032), [M1034](https://attack.mitre.org/mitigations/M1034), [M1035](https://attack.mitre.org/mitigations/M1035), [M1037](https://attack.mitre.org/mitigations/M1037), [M1038](https://attack.mitre.org/mitigations/M1038), [M1040](https://attack.mitre.org/mitigations/M1040), [M1042](https://attack.mitre.org/mitigations/M1042), [M1045](https://attack.mitre.org/mitigations/M1045), [M1047](https://attack.mitre.org/mitigations/M1047), [M1049](https://attack.mitre.org/mitigations/M1049), [M1022](https://attack.mitre.org/mitigations/M1022)
- Trend Micro — *Unmasking The Gentlemen Ransomware* (2025-09): https://www.trendmicro.com/en_us/research/25/i/unmasking-the-gentlemen-ransomware.html (includes "Defending against the Gentlemen attacks")
- Sophos CTU — *Ungentlemanly Behavior: Insights into a Ransomware Operation* (2026-09, 15 incidents): https://www.sophos.com/en-us/blog/ungentlemanly-behavior-insights-into-a-ransomware-operation
- Huntress — *The Gentlemen Ransomware Defense Evasion TTPs* (2026-05): https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps
- Microsoft Security Blog — *The Gentlemen ransomware: Dissecting a self-propagating Go encryptor* (2026-05): https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/
- Check Point Research — *DFIR Report – The Gentlemen & SystemBC* (2026-04): https://research.checkpoint.com/2026/dfir-report-the-gentlemen/
- ESET WeLiveSecurity — *Killing me gently: Inside Gentlemen's EDR killer framework* (2026-06): https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/
- Microsoft — Preventing SMB traffic from lateral connections: https://support.microsoft.com/en-us/help/3185535
- Microsoft — Attack Surface Reduction rules reference (PSExec/WMI rule `d1e49aac-8f56-4280-b9ba-993a6d77406a`)
- Microsoft — Advanced security audit policy settings (4698 Other Object Access Events; 7045 Service Installation; 5136 Directory Service Changes; 4720/4732 User Account Management / Security Group Management)
- Velociraptor documentation — client `client.config.yaml` / `client.writeback` deployment artifacts
- CIS Benchmarks: Microsoft Windows 10/11 (sections 9.x Scheduled Tasks, 18.x Audit Policy), Windows Server (SMB signing, admin shares), Active Directory (GPO management)

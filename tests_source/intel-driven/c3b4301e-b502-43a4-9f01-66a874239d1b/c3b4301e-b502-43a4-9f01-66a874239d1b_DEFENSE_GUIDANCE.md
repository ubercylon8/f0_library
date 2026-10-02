# Defense Guidance: Star Blizzard RedFlick CosmicPulse Espionage Chain

## Executive Summary

Star Blizzard (SEABORGIUM/Callisto, FSB-linked) delivers espionage malware to NGOs,
think-tanks, government and financial-sector organizations supporting Ukraine through a
heavily LOLBin-based chain: a spearphishing event invitation containing a
password-protected archive with an LNK masquerading as a PDF (hidden `conhost.exe
--headless` → `cmd.exe` → BAT), an `ssh.exe PermitLocalCommand` download cradle,
`curl.exe` payload fetches, base64 command extraction from a weaponized PDF executed by
PowerShell, a silent `msiexec /q` install, three scheduled tasks named to look like
network components, CPL execution via `rundll32 shell32.dll,Control_RunDLL` /
`control.exe`, an AES key staged in `HKCU\Software\Classes\.mollis`, and an HTTP
beacon (UTF-16LE + Base64 host data, spoofed Edge User-Agent) from a Python backdoor
(CosmicPulse/YESROBOT) staged inside a video-conference application folder.

Nearly every stage abuses signed, built-in Windows binaries, so **signature-based
controls alone will fail**. Defense must be layered:

1. **Prevent the first execution** — emailgateway controls on password-protected
   archives, Defender ASR rules (email-delivered executable content, obfuscated
   scripts, untrusted executables), SmartScreen.
2. **Reduce the LOLBin surface** — disable the WebClient (WebDAV) service (explicitly
   recommended in the Microsoft disclosure), remove/restrict the OpenSSH client,
   constrain PowerShell, keep `AlwaysInstallElevated` disabled.
3. **Detect what remains** — process-creation auditing with command lines (4688),
   scheduled-task auditing (4698/4699/4700/4701/4702), PowerShell script-block logging
   (4104), MSI logging, and Sysmon registry monitoring of `HKCU\Software\Classes`.

Priority recommendations: enable the four ASR rules listed below in Audit then Block
mode, disable WebClient, turn on scheduled-task and process-creation auditing (these
are quiet and high-signal), and deploy the hunting queries in the IR playbook for the
three fake task names and the `conhost --headless` / `ssh.exe LocalCommand` patterns.

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | c3b4301e-b502-43a4-9f01-66a874239d1b |
| **Test Name** | Star Blizzard RedFlick CosmicPulse Espionage Chain |
| **MITRE ATT&CK** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1218.007](https://attack.mitre.org/techniques/T1218/007/), [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1218.011](https://attack.mitre.org/techniques/T1218/011/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| **Tactics** | Execution, Command and Control, Defense Evasion, Persistence |
| **Severity** | High |
| **Threat Actor** | Star Blizzard (SEABORGIUM / Callisto, FSB-linked) |
| **Target Platform** | Windows endpoint (Windows-only hardening script included) |
| **Source** | [Microsoft Threat Intelligence — Star Blizzard refines phishing and malware delivery with the RedFlick technique (2026-09-29)](https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/) |

## MITRE ATT&CK Mapping

| Technique | Tactic | Applicable Mitigations |
|-----------|--------|----------------------|
| T1204.002 — User Execution: Malicious File (event-invite LNK, hidden conhost chain) | Execution | M1040 — Behavior Prevention on Endpoint; M1038 — Execution Prevention; M1017 — User Training |
| T1105 — Ingress Tool Transfer (ssh.exe PermitLocalCommand cradle, curl.exe fetches) | Command and Control | No dedicated mitigations are listed on the ATT&CK technique page; related mitigations applied here: M1038 — Execution Prevention (restrict/remove unused LOLBins), M1031 — Network Intrusion Prevention (egress filtering), M1054 — Software Configuration (disable unused Windows capabilities) |
| T1059.001 — PowerShell (cAB base64 extraction + Invoke-Expression) | Execution | M1049 — Antivirus/Antimalware; M1045 — Code Signing; M1042 — Disable or Remove Feature or Program; M1038 — Execution Prevention; M1026 — Privileged Account Management |
| T1218.007 — Msiexec (`msiexec /i /q /norestart`) | Defense Evasion | M1042 — Disable or Remove Feature or Program (keep `AlwaysInstallElevated` disabled); M1026 — Privileged Account Management |
| T1053.005 — Scheduled Task (fake network-component task trio) | Persistence / Privilege Escalation | M1047 — Audit; M1028 — Operating System Configuration; M1026 — Privileged Account Management; M1018 — User Account Management |
| T1218.011 — Rundll32 (`Control_RunDLL` / `control.exe` CPL from user-writable path) | Defense Evasion | M1050 — Exploit Protection (attack-surface reduction, ASR) |
| T1071.001 — Web Protocols (HTTP beacon, spoofed Edge UA, `/agent/poll?id=`) | Command and Control | No dedicated M-codes on the technique page; M1031 — Network Intrusion Prevention (IDS signatures / proxy egress control) applies |

> Note: M1042 is "Disable or Remove Feature or Program" (e.g., removing the OpenSSH
> client capability, disabling the WebClient service). M1054 is "Software
> Configuration". Where ATT&CK lists no dedicated mitigation for a technique, that is
> stated explicitly above rather than approximated.

## Hardening Recommendations

### Quick Wins (Immediate — Low Impact)

1. **Enable the four high-value Defender ASR rules** (Audit mode first, then Block):
   - `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` — Block executable content from email
     client and webmail (kills the LNK/BAT-from-archive delivery path when it arrives
     via mail; T1204.002).
   - `5beb7efe-fd9a-4556-801d-275e5ffc04cc` — Block execution of potentially obfuscated
     scripts (base64 + `Invoke-Expression` PowerShell; T1059.001). Explicitly
     recommended in the Microsoft disclosure.
   - `01443614-cd74-433a-b99e-2ecdc07bfc25` — Block executable files unless they meet
     a prevalence/age/trusted-list criterion (dropped stage binaries, CPL DLLs,
     Python backdoor; T1105/T1218.011). Also explicitly recommended in the disclosure.
     Requires cloud-delivered protection enabled.
   - `d1e49aac-8f56-4280-b9ba-993a6d77406c` — Block process creations originating from
     PSExec and WMI commands (standard hygiene; test compatibility if you use
     Configuration Manager).
2. **Disable the WebClient (WebDAV) service** — the real chain's "Network Configuration
   Manager" task exists solely to enable the WebClient redirector so task actions can
   fetch attacker DLLs over WebDAV UNC paths. Disabling it breaks that vector.
3. **Enable scheduled-task auditing**: `auditpol /set /subcategory:"Other Object Access
   Events" /success:enable /failure:enable` plus enable the
   `Microsoft-Windows-TaskScheduler/Operational` log (`wevtutil sl
   Microsoft-Windows-TaskScheduler/Operational /e:true`) — task history is disabled by
   default.
4. **Enable process-creation auditing with command lines**: `auditpol /set
   /subcategory:"Process Creation" /success:enable` and set
   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled
   = 1`. The single highest-value counter to LOLBin chains: every stage of this chain
   (`conhost --headless`, `ssh.exe -o PermitLocalCommand=yes -o LocalCommand=...`,
   `curl.exe -o ...`, `msiexec /i ... /q`, `rundll32 shell32.dll,Control_RunDLL`,
   `schtasks /Create`) is visible in EID 4688/Sysmon EID 1 command lines.
5. **Enable PowerShell logging**: ScriptBlock logging (EID 4104), module logging, and
   transcription via GPO/registry (see hardening script). ScriptBlock logging records
   the decoded base64 payload before `Invoke-Expression` runs it.
6. **Enable Windows Installer logging policy** (`Logging = voicewarmup` under
   `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`) — creates per-install
   `%TEMP%\MSI*.log` evidence for silent installs.
7. **Verify `AlwaysInstallElevated` is 0/absent** in both HKLM and HKCU Installer
   policies (M1042 for T1218.007).
8. **Enforce SmartScreen** (EnableSmartScreen = 1, "Block" level) for downloaded-file
   and LNK reputation checks.
9. **Enable Defender network protection, cloud-delivered protection (MAPS Advanced)
   and PUA protection** — required dependencies for the prevalence ASR rule and for
   blocking known C2 destinations from system processes.
10. **Show file extensions** (`HideFileExt = 0`) — undercuts "Invitation.pdf.lnk"
    masquerade. Low technical impact, requires user communication.
11. **Mail gateway policy**: quarantine or sandbox password-protected archives (RAR/ZIP)
    and archives containing LNK/VHDX files; Microsoft's report notes password-protected
    archives specifically evade gateway scanning.

### Medium-Term (1-2 Weeks — Medium Impact)

1. **Remove or restrict the Windows OpenSSH client** (`OpenSSH.Client~~~~0.0.1.0`)
   on hosts that do not need outbound SSH (M1042/M1054 for the T1105 ssh-cradle);
   where the client is required, add a Windows Firewall program rule blocking
   `C:\Windows\System32\OpenSSH\ssh.exe` outbound TCP/22 except to approved jump
   hosts, and alert on any `ssh.exe` command line containing `PermitLocalCommand` or
   `LocalCommand`.
2. **Deploy AppLocker or WDAC (App Control for Business)** allowing `ssh.exe`,
   `curl.exe`, `msiexec.exe`, `rundll32.exe`, `control.exe` and `conhost.exe` only in
   their system paths, denying user-writable execution (`%USERPROFILE%`,
   `%ProgramData%`, `%TEMP%`, removable media). This directly blocks: the CPL
   execution from user-writable paths, per-user MSI installs, and the staged Python
   backdoor under the video-conference app folder (`...\bin\update`).
3. **Deploy Sysmon** with a SwiftOnSecurity-style or OLDB config:
   - EID 1 (process creation with command line + parent) for all seven stage patterns;
   - EID 3 (network connection) for `curl.exe`/`ssh.exe`/`python.exe` egress;
   - EID 12/13 (registry create/set) on `HKCU\Software\Classes\*` — catches the
     `.mollis` key staging with no per-key SACL noise.
4. **PowerShell Constrained Language Mode** for interactive users via GPO
   (`__PSLockdownPolicy = 4`), with FullLanguage allowed only for signed admin
   tooling — breaks ad-hoc `Invoke-Expression` tradecraft. Pilot first; measure
   breakage of legitimate ops tooling.
5. **Registry auditing**: enable the "Registry" audit subcategory and apply a SACL to
   `HKU\<SID>\Software\Classes` for value-set events (or rely on Sysmon EID 13 for
   lower noise). Generates EID 4657 on `.mollis`-style staging.
6. **Outbound HTTP egress control**: this chain beacons over plain HTTP with a spoofed
   Edge User-Agent. Force egress through authenticating proxies (block direct
   TCP/80/443 from workstations where feasible), and write IDS/SIEM content for the
   exact C2 protocol: GET `/agent/poll?id=<base64>` where the decoded parameter is
   UTF-16LE `hostname|username`.
7. **Task Scheduler hygiene**: baseline all tasks (`schtasks /query /fo CSV /v` or
   `Export-ScheduledTask`) and alert on new-task creation by non-admin principals,
   ONLOGON-trigger tasks, and tasks whose action points into user profiles.
8. **User training with domain-specific lures** (M1017): Star Blizzard social-engineers
   with themed event invitations and prior-email rapport. Train staff to verify
   senders via previously established channels, and to treat password-protected
   archives as suspicious. Include the report's tell-tales: sender organization names
   in the email local-part rather than the domain, bulk sends, first contact without
   attachments followed by archive attachments, Proton addresses.

### Strategic (1-3 Months — Requires Planning)

1. **WDAC policy in enforced mode** with managed installer + intelligent security
   graph reputation — the strongest counter to LOLBin/staged-binary chains; blocks
   unsigned CPL applets, the MSI persistence package, and the embedded Python
   runtime regardless of packer or archive password.
2. **Zero Trust egress architecture**: firewall/proxy default-deny outbound for
   workstations, TLS inspection where legally permitted, DNS filtering, and IDS
   signatures for the RedFlick/CosmicPulse protocol patterns. Removes the T1071.001
   channel entirely.
3. **Phishing-resistant authentication** (FIDO2/WHfB), Conditional Access and
   Continuous Access Evaluation as recommended in the Microsoft report — limits
   credential harvesting that seeds Star Blizzard rapport-building.
4. **EDR in block mode** with automated investigation & response and the Defender
   detections named in the report: "Star Blizzard Activity Group", "Suspicious use of
   Control Panel item", suspicious LNK execution from containers, suspicious
   curl.exe downloads, suspicious msiexec.exe/script execution
   (signatures: Trojan:Script/RedFlick, Backdoor:Script/CosmicPulse,
   Backdoor:Python/CosmicPulse).
5. **Privileged access management** (M1026): standard users must not be local admins;
   combined with UAC and WDAC this converts every stage's persistence attempt from
   silent to denied/audited.
6. **Threat-intel-led purple team cadence**: re-run this chain (and the January
   ssh-cradle and July PDF-extraction variants) against hardened gold images each
   quarter; treat any stage reaching exit code 0 as a finding.
7. **Baseline control of conference/ collaboration apps**: inventory legitimate
   video-conference application directories and alert on new `bin\update` folders or
   embedded Python runtimes appearing inside them.

## Hardening Scripts

> **Note:** Only scripts for the test's target platform are included. This test
> targets `windows-endpoint` only, so a single PowerShell hardening script is
> provided.

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `c3b4301e-b502-43a4-9f01-66a874239d1b_hardening.ps1` | PowerShell with `-Undo` and `-WhatIf` support: ASR rules, Defender features, PowerShell logging, process/task/registry auditing, MSI hardening, WebClient disable, SmartScreen, file extensions, optional outbound-SSH firewall rule and optional OpenSSH client removal. Idempotent; backs up prior state to `%ProgramData%\EndpointHardening\Backups\`. |

Script techniques covered: T1204.002 (ASR email-content rule, SmartScreen, extension
visibility), T1105 (optional ssh.exe egress block / capability removal guidance),
T1059.001 (script-block/module/transcription logging, ASR obfuscated-script rule),
T1218.007 (AlwaysInstallElevated enforcement, MSI logging), T1053.005 (task auditing
+ TaskScheduler operational log), T1218.011 (WebDAV/WebClient disable, ASR
untrusted-executable rule, registry auditing), T1071.001 (Defender network
protection, cloud protection).

## Incident Response Playbook

### Detection Triggers

| # | Detection Name | Criteria | Confidence | Priority |
|---|----------------|----------|------------|----------|
| 1 | Hidden conhost LNK chain (T1204.002) | Sysmon EID 1 / EID 4688: `conhost.exe --headless cmd.exe /c ...` or `cmd.exe /c *.bat` with parent `explorer.exe`/`conhost.exe`; LNK with `WindowStyle=7` and PDF icon | High | P1 |
| 2 | ssh.exe local-command cradle (T1105) | Command line contains `ssh.exe` + `-o PermitLocalCommand=yes` or `-o LocalCommand=` | High | P1 |
| 3 | curl.exe fetch by script (T1105) | `curl.exe -s -S -o` executed by cmd/BAT/conhost parent (not a shell/terminal), or curl fetching `.msi`/`.zip`/`.pdf` to a user-writable path | High | P1 |
| 4 | Base64 PDF payload execution (T1059.001) | EID 4104 script block containing `cAB` regex match + `[Convert]::FromBase64String` + `Invoke-Expression`; or `[IO.File]::ReadAllText(...pdf...)` followed by IEX | High | P1 |
| 5 | Silent MSI install (T1218.007) | `msiexec.exe /i <user-writable path> /q /norestart`; MsiInstaller EID 1040/1042 (1040 without matching 1042 = started silently); AppLocker 8003/8004 | High | P1 |
| 6 | Fake network-component tasks (T1053.005) | EID 4698/4700/4701; TaskScheduler log EID 106/140/200; task named "Internet Quality Test Connection", "Network Configuration Manager", or "System Health Monitor"; any ONLOGON task created by a standard user | High (exact names: Critical) | P1 |
| 7 | CPL execution from user path (T1218.011) | `rundll32.exe shell32.dll,Control_RunDLL <user-writable>.cpl` or `control.exe <user-writable>.cpl`; Sysmon EID 1 | High | P1 |
| 8 | .mollis key staging (T1218.011) | Sysmon EID 12/13 or EID 4657 on `HKCU\Software\Classes\.mollis` | Critical (exact IOA) | P1 |
| 9 | CosmicPulse beacon (T1071.001) | Proxy/IDS: GET `/agent/poll?id=` where id decodes (base64→UTF-16LE) to `hostname\|username`; curl.exe UA spoofing Edge; `python.exe` under a video-conference app `\bin\update` folder | High | P1 |
| 10 | WebClient auto-enable (T1053.005 support) | Service control EID 7040 or Sysmon EID 1 `sc.exe config WebClient start= auto` following task creation | High | P2 |

**Mapping to this test's verdict codes** (how protection surfaces during detonation):
exit **0** on a stage = technique completed unimpeded (finding); **126** = stage blocked
by an OS-emitted access denial (e.g., AppLocker/WDAC policy on msiexec → msiexec error
1260 "rejected by policy", schtasks "Access is denied", registry ACL denial);
**105** = security-engine quarantine (Defender detects/quarantines artifact or task);
**999** = infrastructure/prerequisite failure — note that *network-egress* blocks
(firewall/proxy) surface here rather than as 126, because curl/ssh fail with
connection errors instead of access-denied; **102** = stage hung (CPL decoy dialog
does this legitimately in the sandbox — correlate with triggers 7/8 before treating
as benign).

### Containment (First 15 Minutes)

- [ ] Isolate host from network but keep it powered on (defender console network
      isolation, or disable the switch port / set firewall to block inbound+outbound):
      `New-NetFirewallRule -DisplayName "IR-Containment" -Direction Outbound -Action Block`
- [ ] Terminate active malicious processes:
      `Get-Process curl,ssh,msiexec,rundll32,control,python,conhost,cmd -ErrorAction SilentlyContinue | Where-Object {$_.Path -notlike "$env:windir\System32\*"} | Stop-Process -Force`
      (review before killing system binaries; snapshot process trees first)
- [ ] Disable the persistence tasks immediately (do not delete yet — preserve
      definition for evidence): `Disable-ScheduledTask -TaskName "Internet Quality Test Connection"`, `"Network Configuration Manager"`, `"System Health Monitor"`
- [ ] Block observed C2 domains/IPs at proxy/firewall; submit to threat intel.
- [ ] Capture volatile evidence (below) BEFORE any deletion or AV remediation.
- [ ] Reset credentials of the logged-on user (Star Blizzard chains follow credential
      harvesting with mailbox access).

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Security event log (task/audit events) | Security | `wevtutil epl Security C:\IR\Security.evtx` |
| Task Scheduler operational log | Microsoft-Windows-TaskScheduler/Operational | `wevtutil epl Microsoft-Windows-TaskScheduler/Operational C:\IR\TaskScheduler.evtx` |
| PowerShell operational log (4104) | Microsoft-Windows-PowerShell/Operational | `wevtutil epl Microsoft-Windows-PowerShell/Operational C:\IR\PowerShell.evtx` |
| MSI / Application log (1040/1042) | Application | `wevtutil epl Application C:\IR\Application.evtx` |
| Defender detections | Microsoft-Windows-Windows Defender/Operational | `wevtutil epl Microsoft-Windows-Windows Defender/Operational C:\IR\Defender.evtx` |
| All task definitions | Task folder | `schtasks /query /fo LIST /v > C:\IR\tasks.txt` and `Get-ScheduledTask \| Export-ScheduledTask` per task |
| .mollis registry payload | HKCU\Software\Classes\.mollis | `reg export "HKCU\Software\Classes\.mollis" C:\IR\mollis.reg /y` then `reg query "HKCU\Software\Classes\.mollis" /ve > C:\IR\mollis_value.txt` |
| LNK/archive lure | %USERPROFILE%\Desktop, Downloads | `Get-ChildItem $env:USERPROFILE -Recurse -Include *.lnk,*.rar,*.zip -ErrorAction SilentlyContinue \| Copy-Item -Destination C:\IR\Lure\` ; inspect LNK target: `$sh=New-Object -ComObject WScript.Shell; $sh.CreateShortcut('<path>').TargetPath` |
| MSI verbose logs | %TEMP%\MSI*.log | `Copy-Item $env:TEMP\MSI*.log C:\IR\ -ErrorAction SilentlyContinue` |
| SSH client config/cradle config | C:\Windows\System32\OpenSSH\ | `Get-ChildItem C:\Windows\System32\OpenSSH; Get-Content C:\Windows\System32\OpenSSH\ssh_config` |
| Defender state | AV | `Get-MpComputerStatus > C:\IR\mpstatus.txt; Get-MpThreatDetection \| Format-List * > C:\IR\mpthreats.txt; Get-MpPreference > C:\IR\mppref.txt` |
| Network connections | Live | `Get-NetTCPConnection -State Established \| Select LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess` + `netstat -anob > C:\IR\netstat.txt` |
| Beacon staging dir | Video-conference app | `Get-ChildItem "<app>\bin\update" -Recurse -ErrorAction SilentlyContinue > C:\IR\binupdate.txt` |

### Eradication

*Perform only after evidence collection.*

1. Delete the malicious scheduled tasks (all three names — the real chain installs
   them as a set; also sweep for any other task created in the same window):
   ```
   schtasks /Delete /TN "Internet Quality Test Connection" /F
   schtasks /Delete /TN "Network Configuration Manager" /F
   schtasks /Delete /TN "System Health Monitor" /F
   ```
   Sweep broader: `Get-ScheduledTask | Where-Object {$_.Actions.Execute -match 'rundll32|control\.exe|\\AppData\\|%USERPROFILE%|cmd\.exe|curl\.exe'}`
2. Remove the registry persistence: `reg delete "HKCU\Software\Classes\.mollis" /f`
   (retain the export made in evidence collection — it decrypts to the CosmicPulse
   config when combined with the bootstrapper's embedded key).
3. Remove staged payloads: the invite folder (decoy PDF + archive + LNK + BAT),
   `%TEMP%` MSI*.log are evidence — remove fetched `setup.msi`, `invite.pdf`,
   the CPL file, and the video-conference app's `bin\update` folder (python38 +
   bootstrapper). Reinstall the conference app from a trusted source if it was
   modified in place.
4. Run full Defender scans with latest signatures:
   `Update-MpSignature; Start-MpScan -ScanType FullScan` — verify detections for
   `Trojan:Script/RedFlick` and `Backdoor:Python/CosmicPulse` families.
5. Remove any unauthorized OpenSSH client or firewall changes; verify WebClient is
   disabled again: `Get-Service WebClient`.
6. Hunt neighboring hosts for the same task names, `.mollis` key, and `/agent/poll`
   proxy hits — Star Blizzard bulk-targets whole organizations.

### Recovery

- [ ] Verify all three task names absent: `schtasks /Query /TN "System Health Monitor"` returns error for each
- [ ] Verify `.mollis` absent and no new `HKCU\Software\Classes` oddities:
      `reg query "HKCU\Software\Classes\.mollis"` fails
- [ ] Full AV scan clean; Defender real-time protection and cloud protection enabled:
      `Get-MpComputerStatus \| fl AMServiceEnabled,RealTimeProtectionEnabled,AntivirusEnabled`
- [ ] Re-enable the hardened baseline (re-run the hardening script) and confirm
      ASR/audit settings survived (some malware reverts them)
- [ ] Rotate the user's password and any credentials used in the session; invalidate
      sessions (CA token revocation)
- [ ] Monitor the rebuilt host for 30 days for re-beaconing (`/agent/poll`, task
      re-creation)
- [ ] Reconnect to network after containment rule removal: `Remove-NetFirewallRule -DisplayName "IR-Containment"`

### Post-Incident

1. **How was the attack detected?** If via the user, invest in M1017 training; if via
   EID 4688/4104 telemetry, tune its correlation; if only via C2 proxy logs, your
   endpoint telemetry has a gap.
2. **Detection-to-response time?** Measure alert → isolation interval; target < 15
   minutes for P1 events.
3. **What would have prevented this?** Rank: mail-gateway archive policy (pre-stage
   1), ASR email-content/obfuscated-script rules (stages 1/3), WebClient disabled +
   WDAC (stages 5/6), default-deny egress (stage 7). Convert gaps found into Quick
   Win/Medium-Term items above.
4. **Re-test**: re-run this test chain against the recovered gold image; all stages
   must exit non-zero (126/105) with detections in EID 4688/4698/4104.

## References

- [MITRE ATT&CK T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1218.007 — Msiexec](https://attack.mitre.org/techniques/T1218/007/)
- [MITRE ATT&CK T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK T1218.011 — Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [MITRE ATT&CK T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [Microsoft Threat Intelligence — Star Blizzard refines phishing and malware delivery with the RedFlick technique (2026-09-29)](https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/)
- [Microsoft Learn — Attack surface reduction rules reference (GUIDs)](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft Learn — about_Logging_Windows (PowerShell script-block/module logging)](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [MITRE ATT&CK M1038 — Execution Prevention](https://attack.mitre.org/mitigations/M1038/), [M1017 — User Training](https://attack.mitre.org/mitigations/M1017/), [M1042 — Disable or Remove Feature or Program](https://attack.mitre.org/mitigations/M1042/), [M1047 — Audit](https://attack.mitre.org/mitigations/M1047/), [M1050 — Exploit Protection](https://attack.mitre.org/mitigations/M1050/), [M1031 — Network Intrusion Prevention](https://attack.mitre.org/mitigations/M1031/)
- CIS Microsoft Windows Desktop Benchmark — applicable areas: audit policy
  (advanced audit subcategories), PowerShell logging, Windows Installer,
  WebClient/WebDAV, Defender antivirus configuration, and Windows Firewall.

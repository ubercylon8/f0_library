# Defense Guidance: Webshell Post-Exploitation Simulation

## Executive Summary

Webshells represent one of the most persistent and impactful threats facing organizations with externally accessible web applications. After an attacker deploys a webshell via exploitation of a public-facing application (T1190), the webshell becomes a remote command execution interface. The immediate post-exploitation pattern is highly stereotyped: rapid-fire reconnaissance commands (whoami, systeminfo, ipconfig, netstat, tasklist) executed in tight sequence, followed by an outbound C2 beacon. This test validates whether endpoint and network controls detect and block these behaviors.

The highest-priority actions are: patching web application vulnerabilities, enabling IIS/web server process command-line auditing, and deploying network egress filtering that inspects outbound HTTP POST from server-tier systems. All three can be implemented within days and materially reduce attacker dwell time after a successful initial intrusion.

---

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09 |
| **Test Name** | Webshell Post-Exploitation Simulation |
| **MITRE ATT&CK** | [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) · [T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) |
| **Tactics** | Initial Access · Execution |
| **Severity** | High |
| **Threat Actor** | N/A (broadly observed across APT and financially-motivated groups) |
| **Subcategory** | initial-access |
| **Tags** | webshell, cmd-execution, exploit-public-facing, post-exploitation |

---

## MITRE ATT&CK Mapping

| Technique | Tactic | Description | Applicable Mitigations |
|-----------|--------|-------------|----------------------|
| T1190 — Exploit Public-Facing Application | Initial Access | Adversary exploits a weakness in an internet-facing system (web app, VPN, API gateway) to gain initial access; webshells are a common post-exploitation payload | M1048 — Application Isolation and Sandboxing; M1030 — Network Segmentation; M1016 — Vulnerability Scanning; M1026 — Privileged Account Management; M1050 — Exploit Protection |
| T1059.003 — Windows Command Shell | Execution | Adversary abuses cmd.exe to execute commands; webshells commonly spawn cmd.exe as a child of the web server worker process (w3wp.exe, httpd.exe) | M1038 — Execution Prevention; M1026 — Privileged Account Management; M1045 — Code Signing |

### Mitigation Detail

| M-Code | Name | Relevance to This Test |
|--------|------|----------------------|
| M1016 | Vulnerability Scanning | Discover exploitable web application vulnerabilities before attackers do |
| M1026 | Privileged Account Management | Restrict IIS app pool identities; run web services as low-privilege accounts to limit post-exploitation impact |
| M1030 | Network Segmentation | Isolate web server DMZ; prevent direct outbound internet access from server tier |
| M1038 | Execution Prevention | Block or restrict cmd.exe/powershell.exe spawned by web worker processes via AppLocker/WDAC |
| M1045 | Code Signing | Enforce WDAC policy to require code signing on all executables |
| M1048 | Application Isolation and Sandboxing | Run web applications in isolated containers or sandboxed environments |
| M1050 | Exploit Protection | Enable EMET/Windows Defender Exploit Guard mitigations on web server processes |
| M1051 | Update Software | Patch web application frameworks, CMS platforms, and underlying OS promptly |

---

## Hardening Recommendations

### Quick Wins (Immediate — Low Effort, High Impact)

1. **Enable Advanced Audit Policy — Process Creation** (`Audit Process Creation` → Success)
   - GPO: `Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Detailed Tracking > Audit Process Creation`
   - Enable command-line logging: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`

2. **Restrict IIS application pool identity privileges**
   - Change IIS app pool identity from `NetworkService` or `LocalSystem` to a dedicated minimal-rights service account
   - Deny interactive logon and network logon for the service account where possible

3. **Block cmd.exe and powershell.exe as child processes of web server workers via Windows Defender Attack Surface Reduction**
   - ASR Rule: `Block process creations originating from PSExec and WMI commands` (d1e49aac-8f56-4280-b9ba-993a6d77406c)
   - Custom parent-process restrictions via WDAC publisher rules for w3wp.exe, httpd.exe, tomcat.exe

4. **Enable Windows Defender Real-Time Protection and Behavioral Monitoring**
   - Verify `DisableRealtimeMonitoring = 0` in registry and via Group Policy

5. **Configure outbound firewall rules on web servers**
   - Default-deny egress on server-tier systems; whitelist only required destinations
   - Block HTTP/HTTPS to arbitrary external IPs from the IIS worker process identity

6. **Deploy Microsoft Defender for Endpoint (MDE) with behavioral detection enabled**
   - Enable `Cloud-delivered protection` and `Automatic sample submission`

### Medium-Term (1–2 Weeks — Moderate Effort)

1. **Deploy AppLocker or Windows Defender Application Control (WDAC) policy**
   - Enforce allowlist on web servers: only signed, trusted executables may run
   - Specifically deny cmd.exe and powershell.exe when spawned from web process paths

2. **Implement network proxy with TLS inspection for server-tier egress**
   - Route all outbound HTTP/HTTPS from web servers through an authenticated proxy
   - Alert on POST requests from server-tier hosts to external IPs not in approved list
   - Inspect User-Agent strings and payload patterns for reconnaissance data

3. **Enable Windows Defender Exploit Guard — Network Protection**
   - Blocks outbound connections from suspicious processes to untrusted hosts
   - `Set-MpPreference -EnableNetworkProtection Enabled`

4. **Enable Controlled Folder Access**
   - Prevents unauthorized processes from writing to protected directories

5. **Harden IIS configuration**
   - Disable directory browsing, WebDAV, HTTP TRACE
   - Remove unnecessary handler mappings (ASPX, ASHX, PHP if not needed)
   - Enable IIS request filtering to block `.asp`, `.aspx`, `.php` uploads to non-application directories

6. **Deploy web application firewall (WAF)**
   - OWASP ModSecurity Core Rule Set (CRS) blocks common webshell upload vectors
   - Alert on requests that execute system commands (parameter-level detection)

7. **Implement command-line activity alerting**
   - Alert when `whoami`, `systeminfo`, `ipconfig`, `netstat`, `tasklist` are executed in rapid succession (within 60 seconds) from the same process lineage

### Strategic (1–3 Months — Architecture-Level)

1. **Move web applications to containerized infrastructure**
   - Docker/Kubernetes with read-only container filesystems prevents webshell persistence
   - Container restart policies eliminate any runtime modifications

2. **Implement Zero Trust network architecture for server tier**
   - Micro-segmentation: web servers communicate only with explicitly approved back-end services
   - All inter-tier communication authenticated and logged

3. **Continuous vulnerability management program**
   - Integrate DAST (dynamic application security testing) into CI/CD pipeline
   - Schedule authenticated web application scans monthly minimum
   - Prioritize CVE remediation for web frameworks (Apache, IIS, Nginx, application libraries)

4. **Deception technology deployment**
   - Place honeypot webshell files in web directories; trigger alert on any access
   - Deploy canary tokens in web application files

5. **Privileged Access Workstation (PAW) program**
   - Administrators manage web servers only from dedicated hardened workstations
   - Eliminates lateral movement path if server is compromised

---

## Cross-Platform Hardening Scripts

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09_hardening.ps1` | PowerShell hardening with -Undo and -WhatIf support |

---

## Incident Response Playbook

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| Webshell Recon Command Chain | `whoami`, `systeminfo`, `ipconfig`, `netstat`, `tasklist` executed within 90 seconds sharing process lineage | High | P1 |
| Web Worker Spawning cmd.exe | w3wp.exe, httpd.exe, or tomcat.exe as parent of cmd.exe or powershell.exe | High | P1 |
| Outbound HTTP POST from Web Server Process | HTTP POST from w3wp.exe/web worker to external IP not in approved list | High | P1 |
| Reconnaissance Commands with Sensitive Flags | `whoami /all`, `ipconfig /all`, `netstat -an` executed on server | Medium | P2 |
| Unexpected Process Creation on Web Server | Any interactive shell (cmd.exe, powershell.exe) spawned on web server outside maintenance window | Medium | P2 |

### Containment (First 15 Minutes)

- [ ] **Isolate the affected web server from the network** — pull network cable or quarantine via EDR policy; preserve access via out-of-band management (IPMI/iLO)
- [ ] **Block the source IP at perimeter firewall** if the webshell access originated from an external IP visible in web server logs
- [ ] **Suspend or disable the IIS application pool identity** account to prevent further command execution: `net user <acct> /active:no`
- [ ] **Take a memory snapshot** of the web server process before restarting services: `procdump.exe -ma w3wp.exe c:\IR\w3wp_<timestamp>.dmp`
- [ ] **Do NOT restart the web server or IIS** until evidence is collected — volatile artifacts in memory and temp directories will be lost
- [ ] **Notify stakeholders** per your incident response communication plan

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| IIS access logs | `%SystemDrive%\inetpub\logs\LogFiles\W3SVC*\` | `robocopy "%SystemDrive%\inetpub\logs\LogFiles" C:\IR\iis_logs /E /COPYALL` |
| IIS application event log | Windows Event Log | `wevtutil epl Application C:\IR\Application.evtx` |
| Security event log | Windows Event Log | `wevtutil epl Security C:\IR\Security.evtx` |
| System event log | Windows Event Log | `wevtutil epl System C:\IR\System.evtx` |
| PowerShell operational log | Windows Event Log | `wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\IR\PowerShell_Operational.evtx` |
| Process creation log (Sysmon 4688) | Windows Event Log | `wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\IR\Sysmon.evtx` |
| Web server file system snapshot | `%SystemDrive%\inetpub\wwwroot\` | `robocopy "%SystemDrive%\inetpub\wwwroot" C:\IR\wwwroot /E /COPYALL /ZB` |
| Web application temp/upload dirs | Application-specific | Identify and copy all world-writable web directories |
| Running process list with handles | Memory | `tasklist /v /fo csv > C:\IR\tasklist.csv` |
| Active network connections | Memory | `netstat -anob > C:\IR\netstat.csv` |
| Scheduled tasks | Registry/filesystem | `schtasks /query /fo LIST /v > C:\IR\schtasks.txt` |
| Registry run keys | Registry | `reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run C:\IR\run_keys.reg` |
| w3wp.exe memory dump | Memory | `procdump.exe -ma w3wp.exe C:\IR\w3wp_<timestamp>.dmp` |
| Prefetch files | `C:\Windows\Prefetch\` | `robocopy C:\Windows\Prefetch C:\IR\Prefetch /E /COPYALL` |

### Webshell Identification

Search for webshell files in web root directories:

```powershell
# Search for recently modified script files in web directories
Get-ChildItem -Path "C:\inetpub\wwwroot" -Recurse -Include "*.asp","*.aspx","*.php","*.ashx","*.asmx","*.config" |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
    Select-Object FullName, LastWriteTime, Length |
    Sort-Object LastWriteTime -Descending |
    Export-Csv C:\IR\recent_web_files.csv -NoTypeInformation

# Search for files containing known webshell patterns
Select-String -Path "C:\inetpub\wwwroot\*.aspx","C:\inetpub\wwwroot\*.asp","C:\inetpub\wwwroot\*.php" `
    -Pattern "cmd\.exe|System\.Diagnostics\.Process|shell_exec|passthru|eval\s*\(" `
    -Recurse | Export-Csv C:\IR\webshell_candidates.csv -NoTypeInformation
```

### Eradication

Perform AFTER full evidence collection:

- [ ] **Identify and remove the webshell file(s)** — use evidence from IIS logs to map URL paths to filesystem locations
- [ ] **Audit all web-accessible directories** for unauthorized files — compare against last known-good backup manifest
- [ ] **Rotate all credentials accessible from the compromised web server**:
  - [ ] Service account passwords used by the web application
  - [ ] Database connection string credentials
  - [ ] API keys and secrets in web.config or environment variables
  - [ ] Any credentials found in IIS application configuration
- [ ] **Identify the initial exploit vector** — review IIS logs for the request that installed the webshell (typically a file upload, deserialization, or code injection endpoint)
- [ ] **Patch the exploited vulnerability** before restoring the system to production
- [ ] **Scan for additional persistence** — scheduled tasks, registry run keys, new local accounts, malicious IIS modules (native `.dll` handlers in applicationHost.config)
- [ ] **Check for lateral movement indicators** — review authentication logs on adjacent systems for logons from the compromised server's identity

### Recovery

- [ ] Verify all webshell files and related artifacts removed
- [ ] Rebuild or restore the web server from a known-good baseline if lateral movement or persistence beyond the webshell was found
- [ ] Apply the patch for the exploited vulnerability in a test environment first
- [ ] Restore patched web application from source control (do NOT restore from backup of the compromised state)
- [ ] Re-enable IIS application pool with a fresh, rotated identity
- [ ] Re-enable network connectivity with additional monitoring in place
- [ ] Verify hardening controls from this guidance are applied before returning to production
- [ ] Conduct a targeted threat hunt across web server fleet for similar indicators

### Post-Incident

1. **Detection gap analysis**: Was the initial webshell deployment detected? At which point in the kill chain was detection first triggered (or not)? What was detection-to-response time?
2. **Root cause**: Which specific vulnerability was exploited? Is this CVE present across other systems?
3. **Prevention**: Was patching delayed? Was WAF deployed and properly tuned? Were IIS handler restrictions in place?
4. **Logging completeness**: Were process creation events (Event ID 4688) with command-line logging enabled? Were IIS logs being centralized in real time?
5. **Response effectiveness**: Were containment actions completed within 15 minutes of alert? If not, what caused delays?
6. **Scope confirmation**: Is there evidence the attacker pivoted beyond the initial web server? Have all systems with trust relationships to this server been reviewed?

---

## References

| Resource | URL |
|----------|-----|
| MITRE ATT&CK T1190 | https://attack.mitre.org/techniques/T1190/ |
| MITRE ATT&CK T1059.003 | https://attack.mitre.org/techniques/T1059/003/ |
| MITRE M1016 — Vulnerability Scanning | https://attack.mitre.org/mitigations/M1016/ |
| MITRE M1026 — Privileged Account Management | https://attack.mitre.org/mitigations/M1026/ |
| MITRE M1030 — Network Segmentation | https://attack.mitre.org/mitigations/M1030/ |
| MITRE M1038 — Execution Prevention | https://attack.mitre.org/mitigations/M1038/ |
| MITRE M1048 — Application Isolation and Sandboxing | https://attack.mitre.org/mitigations/M1048/ |
| MITRE M1050 — Exploit Protection | https://attack.mitre.org/mitigations/M1050/ |
| MITRE M1051 — Update Software | https://attack.mitre.org/mitigations/M1051/ |
| NSA/ASD — Detect and Prevent Web Shell Malware | https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF |
| CISA Alert AA20-205A — Web Shells | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-205a |
| Microsoft Security Blog — Web Shell Attacks Continue to Rise | https://www.microsoft.com/en-us/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/ |
| CIS Benchmark for Microsoft IIS | https://www.cisecurity.org/benchmark/microsoft_iis |
| IIS Security Hardening Guidance (Microsoft Docs) | https://docs.microsoft.com/en-us/iis/get-started/whats-new-in-iis-10/new-features-introduced-in-iis-10 |

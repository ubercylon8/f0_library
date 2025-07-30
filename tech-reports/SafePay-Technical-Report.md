# SafePay Ransomware Group: Comprehensive Security Report (2024-2025)

## Executive Summary

SafePay ransomware emerged in September 2024 and rapidly ascended to become the most active ransomware group globally by May 2025, claiming over 248 victims across critical infrastructure sectors. Operating as a centralized, non-RaaS threat actor with suspected Conti heritage, SafePay demonstrates sophisticated capabilities including sub-24-hour breach-to-deployment timelines, strategic geographic targeting of Germany and the United States, and advanced social engineering tactics. This report provides both strategic threat intelligence for executives and deep technical analysis for security engineering teams to defend against this critical threat.

## Threat Intelligence Section

### SafePay Group Profile and History

SafePay represents a post-Conti ransomware operation that emerged in October 2024, distinguishing itself through a centralized operational model rather than the industry-standard Ransomware-as-a-Service (RaaS) approach. The group maintains an estimated 30+ core members and operates with sophisticated operational security practices.

**Key Organizational Characteristics:**
- **First Activity**: September 2024, with public emergence in October 2024
- **Operational Model**: Centralized command structure without affiliates
- **Geographic Base**: Strongly suspected Russian origins based on CIS avoidance
- **Group Composition**: Former Conti operators and potentially former BlackBasta members
- **Infrastructure**: Dual presence on Tor and TON (Telegram) networks

### Recent Campaigns and Notable Attacks (2024-2025)

**Growth Trajectory:**
- November 2024: 22 victims (5% of global ransomware activity)
- March 2025: 43 victims (4th most active group)
- May 2025: 58 victims (became #1 globally)
- July 2025: 248+ total claimed victims

**High-Profile Attacks:**

**Microlise (October 2024)**
- UK telematics company servicing critical logistics
- 1.2TB data exfiltration
- Sub-24-hour ransom deadline
- Collateral impact on DHL and Serco operations
- Disrupted prison transport tracking systems

**Ingram Micro (July 2025)**
- World's largest IT distributor ($48B revenue)
- Multi-day global service disruption
- Entry via GlobalProtect VPN exploitation
- Demonstrated supply chain targeting capability

### Victim Profiles and Targeting Patterns

**Geographic Distribution:**
- **Primary Focus**: Germany (24% of Q1 2025 ransomware victims)
- **Secondary Targets**: United States (105 victims), United Kingdom (13 victims)
- **Attack Patterns**: Coordinated waves of 10+ attacks per day
- **Strategic Intent**: Establishing dominant position in German market

**Industry Targeting Evolution:**
- **Initial Focus**: Financial, legal, and insurance sectors
- **Current Priorities**: Professional services, construction, manufacturing
- **Strategic Sectors**: Healthcare, critical infrastructure, supply chain entities
- **Risk Avoidance**: Below-average targeting of government and finance

### Ransom Demands and Negotiation Tactics

**Financial Structure:**
- **Calculation Method**: 1-3% of victim's annual revenue
- **Typical Range**: $500,000 - $1,000,000
- **Sanctions Sensitivity**: Reduces demands to $100,000-$300,000 when compliance issues raised
- **Payment Timeline**: Often demands payment within 24 hours

**Psychological Tactics:**
- Direct telephone calls to executives during attacks
- Microsoft Teams impersonation as "IT department"
- Offering "free decryptors" as manipulation technique
- Heavy emphasis on data theft over encryption ("care about data 100 more times than encryption")

### Attribution Indicators

**Russian Origin Evidence:**
- **CIS Killswitch**: Built-in language checks prevent execution in Russian-speaking countries
- **Avoided Languages**: Russian, Ukrainian, Belarusian, Armenian, Georgian, Kazakh
- **Operational Patterns**: Consistent with Eastern European cybercrime groups
- **Infrastructure**: Use of Vultr VPS and specific workstation naming conventions

### Relationships with Other Cybercrime Groups

**Confirmed Connections:**
- **Conti Heritage**: Employs standard Conti TTPs and likely includes former members
- **Triad Structure**: Suspected collaboration with INC Ransom and Lynx groups
- **Loose Affiliations**: Maintains connections to Akira, BlackSuit, Play, and Qilin
- **BlackBasta Impact**: SafePay's emergence cited as primary reason for BlackBasta dissolution

## Technical Analysis Section

### Detailed Malware Analysis

**Binary Characteristics:**
- **Base Code**: Derived from leaked LockBit 3.0 builder (late 2022)
- **File Type**: PE32 DLL requiring regsvr32.exe execution
- **Compilation**: Zeroed timestamp (0x00000000) for analysis evasion
- **Obfuscation**: Three-step XOR loop with dynamic key generation

### Initial Access Vectors

**Primary Methods:**
1. **VPN Exploitation**
   - GlobalProtect gateway compromise
   - Credential-based attacks (stolen/purchased)
   - Password spraying campaigns
   - Misconfigured firewall bypass

2. **Remote Desktop Protocol**
   - Direct RDP exploitation
   - Valid credential usage
   - No new account creation (stealth approach)

### Exploitation Techniques

**Configuration Weaknesses:**
- FortiGate firewall misconfigurations
- Local accounts bypassing MFA requirements
- Weak password policies
- Unpatched VPN appliances (VMware, Citrix)

**Attack Infrastructure:**
- Workstation names: `vultr-guest`, `WIN-SBOE3CPNALE`, `WIN-3IUUOFVTQAR`
- Average dwell time: 25 days before encryption

### Persistence Mechanisms

**Service-Based Persistence:**
```
Service Name: ScreenConnect Client
Service Path: C:\Program Files(x86)\ScreenConnect Client
Service Type: Auto start, LocalSystem context
```

**Registry Persistence:**
- Autorun value: `6F22-C16F-0C71-688A`
- Execution: `regsvr32.exe /n /i C:\locker.dll`

### Lateral Movement Methods

**Network Discovery:**
- **ShareFinder.ps1**: PowerView-based network enumeration
- **Command Pattern**: `Invoke-ShareFinder -CheckShareAccess`
- **Purpose**: Identify accessible network shares for propagation

**Propagation Methods:**
```bash
start C:\1.exe -pass=<string> -path=\\<location> -enc=1
```

### Encryption Implementation

**Algorithm Details:**
- **Cipher**: ChaCha20 with x25519 key exchange
- **File Extension**: `.safepay`
- **Block Size**: 10,485,760 bytes (0xa00000)
- **Partial Encryption**: Configurable via `-enc` parameter
  - `-enc=1`: 10% encryption
  - `-enc=3`: 30% encryption

**Metadata Structure (65 bytes):**
- Bytes 0-31: Public key (x25519 derived)
- Bytes 32-63: Validation hash (KDF integrity)
- Byte 64: Encryption percentage value

### Data Exfiltration Methods

**WinRAR Archiving Command:**
```bash
WinRAR.exe a -v5g -ed -r -tn1000d -m0 -mt5 
-x*.rar -x*.JPEG -x*.RAW -x*.PSD -x*.TIFF 
-x*.BMP -x*.GIF -x*.JPG -x*.MOV -x*.pst
```

**FileZilla Implementation:**
- Installer: `FileZilla_3.67.1_win64_sponsored-setup.exe`
- Pattern: Install → Execute → Uninstall (daily cycle)
- Volume: Up to 450GB exfiltration capacity

### Command and Control Infrastructure

**Primary C2:**
- IP: `88.119.167.239:443`
- Protocol: HTTPS with custom headers
- Traffic signature: `C4 C3 C2 C1`
- Component: `soc.dll` (QDoor backdoor)

**Communication Platforms:**
- **Tor Sites**: 
  - `iieavvi4wtiuijas3zw4w54a5n2srnccm2fcb3jcrvbb7ap5tfphw6ad.onion`
  - `qkzxzeabulbbaevqkoy2ew4nukakbi4etnnkcyo3avhwu7ih7cql4gyd.onion`
- **TON Network**: Telegram-based victim communication

## Tactics, Techniques, and Procedures (TTPs)

### MITRE ATT&CK Framework Mapping

**Initial Access**
- T1190 - Exploit Public-Facing Application
- T1078.002 - Valid Accounts: Domain Accounts
- T1133 - External Remote Services

**Execution**
- T1059.001 - PowerShell (ShareFinder.ps1)
- T1059.003 - Windows Command Shell
- T1218.010 - System Binary Proxy Execution: Regsvr32

**Persistence**
- T1543.003 - Create or Modify System Process: Windows Service
- T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys

**Privilege Escalation**
- T1548.002 - Abuse Elevation Control Mechanism: Bypass UAC
- T1134 - Access Token Manipulation

**Defense Evasion**
- T1027.002 - Obfuscated Files or Information
- T1070.004 - Indicator Removal: File Deletion
- T1562.001 - Impair Defenses: Disable Security Tools

**Discovery**
- T1082 - System Information Discovery
- T1135 - Network Share Discovery

**Lateral Movement**
- T1021.001 - Remote Services: Remote Desktop Protocol
- T1021.002 - Remote Services: SMB/Windows Admin Shares

**Collection**
- T1560.001 - Archive Collected Data: Archive via Utility

**Command and Control**
- T1071.001 - Application Layer Protocol: Web Protocols
- T1219 - Remote Access Software

**Exfiltration**
- T1048 - Exfiltration Over Alternative Protocol

**Impact**
- T1486 - Data Encrypted for Impact
- T1490 - Inhibit System Recovery

### Kill Chain Analysis

1. **Initial Compromise**: VPN/RDP credential abuse (Days 1-5)
2. **Establish Foothold**: ScreenConnect deployment (Days 5-10)
3. **Escalate Privileges**: UAC bypass, token manipulation (Days 10-15)
4. **Internal Reconnaissance**: ShareFinder.ps1 execution (Days 15-20)
5. **Move Laterally**: SMB propagation, admin share access (Days 20-23)
6. **Maintain Presence**: Registry persistence, service creation (Days 23-24)
7. **Complete Mission**: Data exfiltration, encryption deployment (Day 25)

### Behavioral Patterns

**Speed Characteristics:**
- Breach to encryption: <24 hours when activated
- Dwell time: Average 25 days for reconnaissance
- Data exfiltration: Concurrent with late-stage reconnaissance

**Operational Patterns:**
- No new user account creation (stealth priority)
- Manual Windows Defender disabling via GUI
- Install/uninstall cycles for tools (anti-forensics)
- Coordinated geographic waves (10+ victims/day)

## Detection and Prevention

### Indicators of Compromise (IOCs)

**File Indicators:**
```
readme_safepay.txt (ransom note)
1.exe (SHA256: 07353237350c35d6dc2c8f143b649cd07c71f62b)
locker.dll (SHA256: a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526)
soc.dll (SHA256: 921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae)
```

**Network Indicators:**
```
88.119.167.239:443 (Primary C2)
45.91.201.247 (Secondary C2)
77.37.49.40 (Secondary C2)
C4 C3 C2 C1 (Traffic header pattern)
```

### Detection Rules

**YARA Rule:**
```yara
rule SafePay_Ransomware {
    meta:
        description = "Detects SafePay ransomware"
        author = "Security Team"
        date = "2025-07-28"
        
    strings:
        $s1 = "readme_safepay.txt" ascii wide
        $s2 = ".safepay" ascii wide
        $s3 = "SafePay team" ascii wide
        $s4 = "-pass=" ascii
        $s5 = "-enc=" ascii
        $header = { C4 C3 C2 C1 }
        
    condition:
        uint16(0) == 0x5A4D and (3 of ($s*) or $header)
}
```

**Sigma Rule:**
```yaml
title: SafePay UAC Bypass Detection
id: safepay-uac-bypass-2025
status: production
description: Detects SafePay UAC bypass via CMSTPLUA COM object
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\DllHost.exe'
        ParentCommandLine|contains: 'CMSTPLUA'
    suspicious_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\regsvr32.exe'
    condition: selection and suspicious_child
falsepositives:
    - Unknown
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548.002
```

### Security Engineering Recommendations

**Immediate Actions:**
1. **VPN Hardening**
   - Enforce MFA on all VPN connections
   - Disable local account authentication
   - Implement certificate-based authentication
   - Monitor for password spray attacks

2. **Windows Security**
   - Enable Controlled Folder Access
   - Configure ASR rules for ransomware protection
   - Implement WDAC or AppLocker
   - Disable unnecessary services

3. **Network Segmentation**
   - Isolate critical systems
   - Implement east-west traffic inspection
   - Deploy internal firewalls
   - Restrict SMB access

### Testing Scenarios for Security Teams

**Scenario 1: Initial Access Testing**
```powershell
# Test VPN brute force detection
# Simulate multiple failed authentication attempts
# Expected: Alert on repeated failures from same source

# Test credential spray detection
# Attempt same password across multiple accounts
# Expected: Alert on distributed authentication failures
```

**Scenario 2: Lateral Movement Testing**
```powershell
# Test ShareFinder.ps1 detection
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/darkoperator/Veil-PowerView/master/PowerView/functions/Invoke-ShareFinder.ps1" -OutFile test.ps1
# Expected: PowerShell monitoring alerts on network enumeration

# Test SMB propagation detection
# Attempt to copy files to admin shares
# Expected: Alert on unusual admin share access
```

**Scenario 3: Defense Evasion Testing**
```powershell
# Test Windows Defender manipulation detection
# Simulate GUI-based security setting changes
# Expected: Alert on systemsettingsadminflows.exe execution

# Test UAC bypass detection
# Create test process mimicking CMSTPLUA abuse
# Expected: Alert on suspicious DllHost.exe child processes
```

### Mitigation Strategies

**Technical Controls:**
1. **Backup Protection**
   - Implement immutable backups
   - Test recovery procedures monthly
   - Maintain offline backup copies
   - Use 3-2-1-1 backup strategy

2. **Endpoint Protection**
   - Deploy EDR with behavioral detection
   - Enable ransomware-specific protections
   - Monitor for encryption behaviors
   - Implement application control

3. **Identity Security**
   - Enforce MFA universally
   - Implement privileged access management
   - Monitor for credential abuse
   - Deploy passwordless authentication

## Recommendations

### For Security Teams

**Immediate Priorities:**
1. **Detection Engineering**
   - Deploy provided detection rules
   - Tune for environment-specific false positives
   - Implement behavioral analytics
   - Create custom threat hunts

2. **Incident Preparation**
   - Update incident response playbooks
   - Conduct SafePay-specific tabletop exercises
   - Establish ransom negotiation protocols
   - Test backup recovery procedures

3. **Threat Intelligence**
   - Monitor SafePay leak sites
   - Track group evolution and TTPs
   - Share intelligence with industry peers
   - Maintain updated IOC feeds

### For Executives and Decision Makers

**Strategic Considerations:**
1. **Risk Management**
   - Assess organizational exposure to SafePay targeting criteria
   - Review cyber insurance coverage for ransomware
   - Evaluate business continuity capabilities
   - Consider engaging specialized incident response retainer

2. **Investment Priorities**
   - Privileged access management solutions
   - Immutable backup technologies
   - Advanced endpoint detection
   - Security awareness training

3. **Governance Actions**
   - Establish clear ransomware response policies
   - Define payment decision framework
   - Create executive communication protocols
   - Ensure regulatory compliance readiness

### Incident Response Guidance

**Initial Response (0-30 minutes):**
1. Isolate affected systems
2. Activate incident response team
3. Preserve evidence (memory, logs, ransom notes)
4. Assess scope of compromise
5. Notify leadership and legal counsel

**Containment Strategy:**
- Implement network segmentation
- Disable compromised accounts
- Block known C2 infrastructure
- Isolate backup systems
- Document all actions taken

**Recovery Approach:**
- Verify backup integrity before restoration
- Implement additional security controls
- Monitor for re-infection indicators
- Coordinate with law enforcement
- Consider professional negotiation services

## Conclusion

SafePay represents a sophisticated, rapidly evolving ransomware threat that demands immediate attention from security teams and executive leadership. Their combination of technical sophistication, operational efficiency, and strategic targeting makes them a critical threat to organizations globally, particularly in Germany and the United States. The group's sub-24-hour deployment capability and emphasis on data theft over encryption requires organizations to implement comprehensive preventive controls and maintain robust detection capabilities.

Security teams should prioritize implementation of the provided detection rules and testing scenarios, while executives must ensure adequate resources and governance structures are in place to address this evolving threat. The key to defense lies in layered security controls, proactive threat hunting, and maintaining resilient backup and recovery capabilities.
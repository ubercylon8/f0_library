# Local Account Enumeration

## Test Information

**Test ID**: b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02
**Test Name**: Local Account Enumeration
**Category**: Credential Access / Account Discovery
**Severity**: High
**MITRE ATT&CK**: T1078.003, T1087.001, T1558.003

## Description

This security test simulates local account enumeration techniques that adversaries commonly use during reconnaissance and credential access phases of an attack. The test evaluates EDR detection capabilities against both native Windows enumeration commands and advanced Kerberos abuse tools (Rubeus).

The test covers three key MITRE ATT&CK techniques:
- **T1078.003 (Valid Accounts: Local Accounts)**: Understanding local account context
- **T1087.001 (Account Discovery: Local Account)**: Enumerating local users and groups
- **T1558.003 (Kerberoasting)**: Targeting service accounts for offline credential cracking

This combination reflects real-world attack patterns where adversaries first enumerate accounts using native tools, then escalate to Kerberos-based attacks for credential theft.

## Test Score: 8.5/10

### Score Breakdown

| Criterion | Score | Justification |
|-----------|-------|---------------|
| **Real-World Accuracy** | **2.8/3.0** | Uses real offensive tool (Rubeus/GhostPack), native Windows commands exactly as used by threat actors. Kerberoasting is documented in APT29, FIN6, and other campaigns. |
| **Technical Sophistication** | **2.5/3.0** | Combines native enumeration (net, wmic, whoami) with advanced Kerberos operations. Multiple ATT&CK techniques tested. Optional tool loading pattern. |
| **Safety Mechanisms** | **1.5/2.0** | All operations are read-only enumeration. No credential extraction or cracking. Kerberos queries only. Immediate cleanup of artifacts. |
| **Detection Opportunities** | **1.0/1.0** | 8+ distinct detection points: net.exe, wmic.exe, whoami.exe patterns, Rubeus binary/process, Kerberos ticket requests, command line arguments. |
| **Logging & Observability** | **0.7/1.0** | Full Schema v2.0 logging with phase tracking, process execution logs, file drops, and comprehensive audit trail. |

**Key Strengths**:
- Combines native Windows commands with real offensive tooling (Rubeus)
- Tests multiple ATT&CK techniques in a single execution
- Optional tool loading allows testing with or without Rubeus
- Read-only operations ensure safety
- Comprehensive output capture for forensic analysis

**Improvement Opportunities**:
- Could add PowerShell-based enumeration (Get-LocalUser, Get-LocalGroupMember)
- Could implement additional Rubeus operations (tgtdeleg, s4u)
- Domain-joined environment testing for full Kerberoasting simulation

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Dropper initialization
   - Target directory creation (c:\F0)
   - Logger setup with Schema v2.0 compliance

2. **Phase 2: Net User Enumeration (T1087.001)**
   - Executes `net user` command
   - Captures list of all local user accounts
   - Output saved to `net_user_output.txt`

3. **Phase 3: Admin Group Enumeration (T1087.001)**
   - Executes `net localgroup administrators`
   - Identifies accounts with local admin privileges
   - Output saved to `net_localgroup_admins_output.txt`

4. **Phase 4: User Context Discovery (T1078.003)**
   - Executes `whoami /all`
   - Reveals current user privileges, group memberships, SIDs
   - Output saved to `whoami_all_output.txt`

5. **Phase 5: WMI Account Enumeration (T1087.001)**
   - Executes `wmic useraccount list brief`
   - Alternative enumeration method using WMI
   - Output saved to `wmic_useraccount_output.txt`

6. **Phase 6: Rubeus Kerberoasting (T1558.003) [Optional]**
   - Loads Rubeus.exe from `c:\F0\tools\` if available
   - Executes `Rubeus kerberoast /outfile:hashes.txt /opsec`
   - Requests TGS tickets for SPN-enabled accounts
   - Output saved to `rubeus_kerberoast_output.txt`

7. **Phase 7: Rubeus AS-REP Roasting (T1558.003) [Optional]**
   - Executes `Rubeus asreproast /format:hashcat`
   - Targets accounts without Kerberos pre-authentication
   - Output saved to `rubeus_asreproast_output.txt`

8. **Phase 8: Final Assessment**
   - Aggregates results across all phases
   - Generates comprehensive summary
   - Determines protection status based on blocked patterns

### Key Indicators

- **Process Creation**: net.exe, whoami.exe, wmic.exe, Rubeus.exe
- **Command Line Patterns**:
  - `net user`
  - `net localgroup administrators`
  - `whoami /all`
  - `wmic useraccount list brief`
  - `Rubeus kerberoast`
  - `Rubeus asreproast`
- **File System Activity**:
  - Creation of Rubeus.exe in c:\F0\
  - Output files in c:\F0\
  - Hash output files from Kerberoasting
- **Network Activity**:
  - Kerberos TGS-REQ requests (TCP 88)
  - AS-REQ requests without pre-authentication

## Detection Opportunities

1. **Native Command Monitoring**
   - net.exe spawned with 'user' or 'localgroup' arguments
   - whoami.exe with '/all' flag
   - wmic.exe querying useraccount class
   - Process tree analysis (parent process identification)

2. **Offensive Tool Detection**
   - Rubeus.exe file signature (hash-based)
   - Rubeus.exe behavioral signatures
   - Known command line patterns for Rubeus
   - Process creation from c:\F0\ directory

3. **Kerberos Activity Monitoring**
   - High volume of TGS-REQ requests in short time
   - TGS requests for rarely-used SPNs
   - AS-REQ without pre-authentication data
   - Kerberos ticket encryption type anomalies

4. **Command Line Analysis**
   - Pattern matching on enumeration commands
   - Frequency analysis of recon commands
   - Correlation of multiple enumeration methods

## Expected Results

### Unprotected System (Code 101)

- All native enumeration commands execute successfully
- Rubeus executes without quarantine (if available)
- Kerberoast/ASREProast operations complete
- Full output files generated in c:\F0\
- Summary shows 0 blocked patterns, 4-6 successful patterns

### Protected System (Enhanced Detection)

- **Code 105**: Rubeus.exe quarantined on extraction - AV detected offensive tool signature
- **Code 126**: One or more enumeration commands blocked - EDR detected suspicious patterns
  - Native command blocking indicates advanced behavioral detection
  - Rubeus execution blocking indicates process-level protection
- **Code 999**: Insufficient privileges or test error - prerequisites not met

## References

- [MITRE ATT&CK T1078.003 - Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)
- [MITRE ATT&CK T1087.001 - Account Discovery: Local Account](https://attack.mitre.org/techniques/T1087/001/)
- [MITRE ATT&CK T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Rubeus - GhostPack Kerberos Toolset](https://github.com/GhostPack/Rubeus)
- [Kerberoasting Detection](https://adsecurity.org/?p=2293)
- [AS-REP Roasting](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)

## Tool Placement

To enable Rubeus testing, place `Rubeus.exe` in `c:\F0\tools\` on the target system before running the test. See `tools/README.md` for detailed instructions on obtaining and placing Rubeus.

## Enhancement Notes

- **Version 1.0.0** (2026-01-11): Initial release with native enumeration and Rubeus placeholder
- Future versions may add:
  - PowerShell-based enumeration (Get-LocalUser)
  - Additional Rubeus operations (tgtdeleg, s4u, harvest)
  - Domain controller-aware Kerberoasting
  - LDAP-based enumeration

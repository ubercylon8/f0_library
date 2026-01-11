# RDP Lateral Movement Simulation

## Test Information

**Test ID**: c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03
**Test Name**: RDP Lateral Movement Simulation
**Category**: Lateral Movement / Credential Access
**Severity**: High
**MITRE ATT&CK**: T1021.001, T1555.004

## Description

This test evaluates EDR/AV detection capabilities against Remote Desktop Protocol (RDP) lateral movement techniques. RDP is consistently ranked among the most frequently abused remote access methods by threat actors, ransomware operators, and advanced persistent threats (APTs) for lateral movement within compromised networks.

The test simulates both reconnaissance activities (service status checks, session enumeration) and credential manipulation patterns (cmdkey operations) that attackers use to prepare for and execute RDP-based lateral movement. Additionally, the test includes a placeholder for SharpRDP, a headless RDP command execution tool used by red teams and threat actors.

## Test Score: 8.0/10

### Score Breakdown

| Criterion | Score |
|-----------|-------|
| **Real-World Accuracy** | **2.5/3.0** |
| **Technical Sophistication** | **2.0/3.0** |
| **Safety Mechanisms** | **2.0/2.0** |
| **Detection Opportunities** | **1.0/1.0** |
| **Logging & Observability** | **0.5/1.0** |

**Key Strengths**:
- Real tool potential with SharpRDP integration (attacker-grade tooling)
- Uses actual cmdkey credential manipulation (T1555.004)
- Multiple native Windows commands for realistic reconnaissance
- Comprehensive safety mechanisms (local-only, immediate cleanup)
- 5+ distinct detection opportunities across phases

**Improvement Opportunities**:
- Could add network-level RDP connection simulation (mock connections)
- Integration with additional RDP tools (xfreerdp, rdesktop patterns)
- More extensive credential enumeration patterns

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Create target directory at c:\F0
   - Initialize logging and dropper

2. **Phase 2: RDP Service Status Check**
   - Execute: `sc query TermService`
   - Determine if RDP service is running
   - This is a prerequisite check for meaningful test results

3. **Phase 3: RDP Registry Configuration**
   - Query: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
   - Check fDenyTSConnections (RDP enabled/disabled)
   - Check UserAuthentication (NLA requirement)
   - Check PortNumber configuration

4. **Phase 4: Session Enumeration**
   - Execute: `qwinsta` (Query Session)
   - Enumerate active RDP sessions
   - Save output for analysis
   - Detection point for session reconnaissance

5. **Phase 5: Cmdkey Credential Manager Manipulation**
   - Execute: `cmdkey /add:TESTSERVER /user:testuser /pass:testpass123!`
   - Immediately execute: `cmdkey /delete:TESTSERVER`
   - Tests T1555.004 (Credentials from Password Stores)
   - Safe operation - no persistent credentials

6. **Phase 6: SharpRDP Execution (if embedded)**
   - Extract SharpRDP.exe from embedded binary
   - Check for quarantine on extraction
   - Execute: `SharpRDP computername=localhost command=whoami`
   - Safe local-only execution

7. **Phase 7: Final Assessment**
   - Generate summary report
   - Determine protection status
   - Clean up artifacts

### Key Indicators

- `sc.exe` querying TermService
- `reg.exe` accessing Terminal Server registry keys
- `qwinsta.exe` session enumeration
- `cmdkey.exe` with /add and /delete arguments
- `SharpRDP.exe` binary presence and execution
- Credential Manager registry access
- RDP-related registry key enumeration

## Detection Opportunities

1. **Service Query Detection**
   - Process: sc.exe
   - Arguments: query TermService
   - Detection: Service enumeration for remote services

2. **Registry Access Detection**
   - Process: reg.exe
   - Keys: Terminal Server, RDP-Tcp
   - Detection: Configuration reconnaissance

3. **Session Enumeration Detection**
   - Process: qwinsta.exe
   - Detection: RDP session reconnaissance
   - High-fidelity indicator in non-admin contexts

4. **Credential Manager Manipulation**
   - Process: cmdkey.exe
   - Arguments: /add, /delete
   - Detection: Credential storage manipulation (T1555.004)
   - High-value behavioral indicator

5. **Malicious Tool Detection**
   - File: SharpRDP.exe
   - Detection: Known offensive tool signature
   - Behavioral: RDP API calls without GUI

6. **Process Chain Analysis**
   - Parent: Test binary
   - Children: sc.exe, reg.exe, qwinsta.exe, cmdkey.exe, SharpRDP.exe
   - Detection: Suspicious process lineage

## Expected Results

### Unprotected System (Code 101)

- sc query TermService executes successfully
- Registry queries return configuration data
- qwinsta enumeration completes without blocking
- cmdkey credential manipulation succeeds
- SharpRDP executes (if embedded) without detection
- All patterns indicate unmonitored RDP reconnaissance

### Protected System (Enhanced Detection)

- **Code 105**: SharpRDP.exe quarantined immediately on file extraction
  - Indicates strong file-based AV/EDR detection
  - SharpRDP signature detection active

- **Code 126**: Execution prevention occurred
  - cmdkey manipulation blocked by behavioral controls
  - SharpRDP execution prevented by EDR
  - qwinsta enumeration blocked (less common)
  - Indicates active monitoring of lateral movement indicators

- **Code 999**: RDP service not running
  - Test incomplete due to missing prerequisites
  - TermService not available for testing

## References

- [MITRE ATT&CK - T1021.001: Remote Services - Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [MITRE ATT&CK - T1555.004: Credentials from Password Stores - Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004/)
- [SharpRDP - Headless RDP Tool](https://github.com/0xthirteen/SharpRDP)
- [Microsoft Documentation - Remote Desktop Services](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/)

## Tool Integration

### SharpRDP Placeholder

This test includes a placeholder for SharpRDP, a C# tool that enables headless RDP command execution without spawning a full graphical RDP session. This technique is highly valued by threat actors for:

- Stealthy command execution over RDP
- Bypassing interactive session requirements
- Reduced network footprint compared to full RDP sessions

See `tools/README.md` for instructions on obtaining and embedding SharpRDP.

## Enhancement Notes

- v1.0.0 (2026-01-11): Initial release with native commands and SharpRDP placeholder

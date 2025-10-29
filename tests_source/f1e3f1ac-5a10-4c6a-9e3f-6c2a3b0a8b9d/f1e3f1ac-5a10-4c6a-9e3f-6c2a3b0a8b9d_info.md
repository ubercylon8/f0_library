# FIREFLAME Ransomware Emulation (DRAGONFORCE RaaS)

**Test ID**: f1e3f1ac-5a10-4c6a-9e3f-6c2a3b0a8b9d  
**Test binary SHA1**: [Generated during build]  
**Created**: 2025-10-17 15:00:00.000000  
**Test schedule**: Not scheduled

## Overview
This test evaluates Microsoft Defender protections against behaviors associated with FIREFLAME, a Windows ransomware family linked to the DRAGONFORCE RaaS and reported to share code overlaps with CONTI. The simulation emphasizes safe, high-signal ATT&CK techniques derived from the provided dataset to validate detection and prevention.

## Technique Details
- MITRE ATT&CK (simulated):
  - T1480.002 (Execution Guardrails: Mutual Exclusion)
  - T1027.001 (Obfuscated/Compressed: Binary Padding)
  - T1036.001 (Masquerading: Invalid Code Signature)
  - T1059.005 (Command and Scripting Interpreter: Visual Basic)
  - T1564.003 (Hide Artifacts: Hidden Window)
  - T1033 (System Owner/User Discovery)
  - T1057 (Process Discovery)
  - T1082 (System Information Discovery)
  - T1083 (File and Directory Discovery)
  - T1112 (Modify Registry)
  - T1070.004 (Indicator Removal: File Deletion)

- DRAGONFORCE dataset (context from `mitre-ttps-malware.csv`):
  - T1588.003 (Code Signing Certificates)
  - T1059.005 (Visual Basic)
  - T1027.001 (Binary Padding)
  - T1036.001 (Invalid Code Signature)
  - T1070.004 (File Deletion)
  - T1112 (Modify Registry)
  - T1480.002 (Mutual Exclusion)
  - T1497 (Virtualization/Sandbox Evasion)
  - T1564.003 (Hidden Window)
  - T1010, T1033, T1057, T1082, T1083, T1087, T1518, T1614 (Discovery)
  - T1113 (Screen Capture)
  - T1095 (Non-Application Layer Protocol)
  - T1105 (Ingress Tool Transfer)

## Attack Chain Description

### Stage 1: Execution Guardrails (Mutex)
Creates a named mutex (`Global\\FIREFLAME_MUTEX`) to emulate single-instance execution control used by ransomware families.

### Stage 2: Masquerading and Binary Padding
Drops a padded PE-like file `C:\\F0\\svchost.exe` to simulate obfuscation and masquerading behaviors. The probe checks if AV quarantines the drop shortly after creation.

### Stage 3: Hidden Visual Basic Execution
Writes and executes a benign VBScript (`C:\\F0\\ffl.vbs`) via `wscript.exe //B //nologo` to emulate script-based execution with a hidden window.

### Stage 4: Discovery
Executes basic discovery commands: `whoami`, `tasklist`, OS version, and directory listing of `C:\\F0`.

### Stage 5: Defense Evasion – Registry Tampering
Attempts to modify Windows Defender policy keys via PowerShell to set:
`HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware = 1`.
The script writes a status indicator to `C:\\F0\\status.txt` (DEFENDER_DISABLED or ACCESS_DENIED).

### Stage 6: Indicator Removal
Creates and deletes a temporary file in `C:\\F0` to emulate file deletion behavior.

## Expected Behaviors

### Detection Points
- File drops into `C:\\F0` with PE headers and padding
- `wscript.exe` execution of `.vbs` with `//B //nologo`
- Registry attempts targeting Defender policy keys
- Discovery command executions indicative of pre-encryption reconnaissance
- Mutex creation patterns

### Prevention Stages
- File quarantine on creation (105)
- Script execution block (126)
- Registry tamper protection block or access denial (126)

### Alerting Expectations
- Malware/PE drop and quarantine events
- Script interpreter execution in hidden mode
- Policy tampering attempts for Windows Defender
- Discovery sequences preceding ransomware activity

## Success Metrics

- 101 (Unprotected): Defender policy modified successfully (DisableAntiSpyware = 1)
- 105 (FileQuarantinedOnExtraction): Decoy PE quarantined on write
- 126 (ExecutionPrevented): VBS blocked, or registry modification denied/tamper-protected
- NotRelevant: Administrator privileges unavailable

## Technical Implementation

### File Artifacts
- `C:\\F0\\svchost.exe` (padded PE-like decoy)
- `C:\\F0\\ffl.vbs` (benign VBScript)
- `C:\\F0\\defender_evasion.ps1` (policy tamper attempt)
- `C:\\F0\\status.txt` (status indicator)

### Registry Targets
- `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware`

### Cleanup Operations
- Removal of dropped files (`svchost.exe`, `ffl.vbs`, `defender_evasion.ps1`, `status.txt`)

## Threat Intelligence Context
FIREFLAME, associated with DRAGONFORCE RaaS and exhibiting overlaps with CONTI, leverages common ransomware practices such as discovery, execution guardrails (mutex), script-based staging, and attempts to impair defenses. This test focuses on safe emulation of those behaviors rather than any destructive encryption.

## Defensive Recommendations

1. Enable Defender Tamper Protection and verify policy integrity
2. Monitor for PE drops in user-writable directories (e.g., `C:\\F0` during testing)
3. Alert on `wscript.exe` hidden execution and VBScript abuse
4. Detect mutex patterns typical of ransomware families
5. Harden script execution policies and enable PowerShell Script Block Logging

## References
- mitre-ttps-malware.csv (repository dataset)
- MITRE ATT&CK Techniques: T1112, T1480.002, T1059.005, T1070.004, T1033, T1057, T1082, T1083


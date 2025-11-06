# Qilin Cross-Platform Evasion Simulation

This F0RT1KA test simulates the Qilin ransomware's innovative cross-platform evasion technique, which uses Linux binaries executed through WSL (Windows Subsystem for Linux) to bypass Windows-centric EDR solutions.

## Overview
The test simulates Qilin's multi-phase attack that leverages cross-platform execution:
- WSL verification and installation if needed
- Linux binary execution via WSL to evade Windows-based detection
- Credential harvesting targeting Veeam and SQL databases
- BYOVD (Bring Your Own Vulnerable Driver) attacks
- Cross-platform lateral movement techniques

## MITRE ATT&CK Mapping
- T1202 - Indirect Command Execution (WSL abuse)
- T1055 - Process Injection
- T1574.002 - DLL Side-Loading
- T1003 - OS Credential Dumping
- T1046 - Network Service Scanning
- T1082 - System Information Discovery

## Attack Phases

### Phase 1: WSL Verification & Installation
- Checks if WSL is installed and functional
- Automatically installs WSL if not present
- **Special Requirement**: As requested, includes WSL verification and installation

### Phase 2: Linux Binary Execution
- Executes Linux payload via WSL
- Performs system reconnaissance using Linux commands
- Bypasses Windows-based EDR monitoring

### Phase 3: Credential Harvesting
- Simulates Veeam Backup credential theft
- SQL database credential extraction
- Domain admin credential search
- Browser and network credential enumeration

### Phase 4: BYOVD Attack
- Loads vulnerable driver (rwdrv.sys)
- Demonstrates kernel-level evasion
- Simulates driver-based privilege escalation

### Phase 5: Cross-Platform Lateral Movement
- Network reconnaissance using Linux tools
- SSH connection attempts
- Simulates movement between Linux and Windows systems

## Expected Behavior
A properly protected endpoint should:
- Block WSL installation or usage for malicious purposes
- Prevent Linux binary execution in Windows context
- Detect and stop credential harvesting attempts
- Block vulnerable driver loading
- Alert on cross-platform attack patterns

## Technical Innovation
This test specifically addresses the emerging threat of cross-platform attacks where:
- Traditional Windows EDR may not monitor WSL activities
- Linux binaries can execute under the radar
- Attack surface expands across both Windows and Linux environments
- Detection requires cross-platform visibility

## Risk Assessment
Systems vulnerable to this attack lack:
- WSL usage monitoring and control
- Cross-platform attack detection
- Linux binary execution policies
- Comprehensive credential protection
- Driver loading restrictions

This simulation helps validate security controls against sophisticated, cross-platform evasion techniques used by modern ransomware groups like Qilin.
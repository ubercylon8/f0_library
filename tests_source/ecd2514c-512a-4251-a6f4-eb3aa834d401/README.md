# CyberEye RAT - Windows Defender Disabling via PowerShell

## Test Overview
This test simulates the CyberEye RAT's technique of disabling Windows Defender using PowerShell commands and registry modifications. The test evaluates whether security solutions can detect and prevent malicious PowerShell scripts that attempt to disable endpoint protection.

## Test Steps
1. Drop PowerShell script (CyberEye-TTPs.ps1) to c:\F0
2. Execute script with execution policy bypass
3. Script attempts to:
   - Disable Tamper Protection via registry
   - Disable Anti-Spyware features
   - Disable Real-Time Protection components
   - Modify registry keys in Windows Defender paths
4. Check for detection/prevention of registry modifications

## How It Works
The test embeds a PowerShell script that replicates the exact registry modifications used by the CyberEye RAT:

- **Registry Modifications**:
  - `HKLM:\SOFTWARE\Microsoft\Windows Defender\Features` - TamperProtection = 0
  - `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender` - DisableAntiSpyware = 1
  - `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection` - Multiple disable flags

- **PowerShell Execution**:
  - Uses `-ExecutionPolicy Bypass` to circumvent restrictions
  - Requires administrative privileges
  - Logs all modifications for verification

## Expected Results
- **Protected**: Security solution should detect and block the PowerShell script execution or registry modifications
- **Unprotected**: Script executes successfully and disables Windows Defender components

## MITRE ATT&CK Mapping
- **Technique**: T1562.001 - Impair Defenses: Disable or Modify Tools
- **Sub-technique**: Disable or Modify System Firewall
- **Tactic**: Defense Evasion
- **Platform**: Windows
- **Permissions Required**: Administrator

## Detection Opportunities
- PowerShell script execution with suspicious parameters
- Registry modifications in Windows Defender paths
- Attempts to disable security services
- Execution policy bypass attempts
- Administrative privilege escalation

## Test Requirements
- Windows operating system
- Administrative privileges
- PowerShell execution capability
- Access to registry modification
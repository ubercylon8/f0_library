# Akira Ransomware BYOVD Attack Chain

This VST simulates the Bring Your Own Vulnerable Driver (BYOVD) attack chain used by Akira ransomware to achieve privilege escalation and disable Windows Defender. The test replicates the dual-driver technique where legitimate vulnerable drivers are abused alongside malicious drivers to evade detection and disable security controls.

## How

> Safety: This test only simulates driver operations and registry modifications without performing actual kernel-level exploitation.

Steps:

1. Check for administrator privileges. If not running as admin, exit `NOTRELEVANT`
2. Drop simulated driver files (`rwdrv.sys` and `hlpdrv.sys`) to the `C:\F0` directory
3. Create Windows services (`mgdsrv` and `KMHLPSVC`) that would load these drivers
4. Execute a PowerShell script to attempt Windows Defender registry manipulation
5. Monitor defensive responses at each phase and determine protection status
6. Clean up created services, files, and registry modifications

## Attack Phases

**Phase 1: Driver Deployment**
- Drops `rwdrv.sys` (15,360 bytes) - simulates legitimate ThrottleStop driver
- Drops `hlpdrv.sys` (24,576 bytes) - simulates malicious helper driver
- Monitors for file quarantine by AV/EDR solutions

**Phase 2: Service Creation** 
- Creates `mgdsrv` service pointing to rwdrv.sys
- Creates `KMHLPSVC` service pointing to hlpdrv.sys
- Tests ability to register kernel-mode services

**Phase 3: Defense Evasion**
- Executes PowerShell script with execution policy bypass
- Attempts to modify Windows Defender registry keys
- Targets `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`
- Attempts tamper protection bypass

Example Output:
```bash
[2024-12-30T10:15:30][c3634a9c-e8c9-44a8-992b-0faeca14f612] Starting Akira Ransomware BYOVD Attack Chain simulation
[2024-12-30T10:15:30][c3634a9c-e8c9-44a8-992b-0faeca14f612] Phase 1: Dropping vulnerable and malicious drivers
[2024-12-30T10:15:30][c3634a9c-e8c9-44a8-992b-0faeca14f612] Created simulated driver: rwdrv.sys (15360 bytes)
[2024-12-30T10:15:30][c3634a9c-e8c9-44a8-992b-0faeca14f612] Created simulated driver: hlpdrv.sys (24576 bytes)
[2024-12-30T10:15:33][c3634a9c-e8c9-44a8-992b-0faeca14f612] Phase 2: Creating malicious services
[2024-12-30T10:15:33][c3634a9c-e8c9-44a8-992b-0faeca14f612] Successfully created service: mgdsrv
[2024-12-30T10:15:33][c3634a9c-e8c9-44a8-992b-0faeca14f612] Successfully created service: KMHLPSVC
[2024-12-30T10:15:33][c3634a9c-e8c9-44a8-992b-0faeca14f612] Phase 3: Attempting Windows Defender registry manipulation
[2024-12-30T10:15:38][c3634a9c-e8c9-44a8-992b-0faeca14f612] PowerShell status: DEFENDER_DISABLED
[2024-12-30T10:15:38][c3634a9c-e8c9-44a8-992b-0faeca14f612] Windows Defender registry manipulation succeeded
[2024-12-30T10:15:38][c3634a9c-e8c9-44a8-992b-0faeca14f612] Completed with code: 101
```

## MITRE ATT&CK Mapping

- **T1068 - Exploitation for Privilege Escalation**: Simulates abuse of vulnerable drivers for privilege escalation
- **T1562.001 - Impair Defenses: Disable or Modify Tools**: Registry manipulation to disable Windows Defender

## Detection Opportunities

**File System**
- Driver files dropped to C:\F0 directory
- PowerShell script creation and execution
- Suspicious file sizes matching known malicious drivers

**Service Operations**
- Creation of services with suspicious names (`mgdsrv`, `KMHLPSVC`)
- Kernel-mode service registration attempts
- Service pointing to non-standard driver locations

**Registry Activity** 
- Modifications to Windows Defender policy keys
- Tamper protection bypass attempts
- DisableAntiSpyware registry value changes

**Process Activity**
- PowerShell execution with ExecutionPolicy bypass
- sc.exe commands for service creation
- Administrator privilege escalation attempts

## Resolution

If this test fails (returns code 101 - Unprotected):

**Immediate Actions:**
- Verify Windows Defender is enabled and properly configured
- Check that Tamper Protection is enabled in Windows Security
- Ensure real-time protection is active

**Advanced Protections:**
- Deploy EDR solution with behavioral detection capabilities
- Implement application control policies to block unsigned drivers
- Enable Windows Defender Application Control (WDAC)
- Configure registry monitoring and alerting

**Network Controls:**
- Monitor for suspicious service creation events (Event ID 7045)
- Alert on registry modifications to security software keys
- Detect PowerShell execution with execution policy bypass

**Verification Steps:**
1. Run Windows Security scan to ensure it's functioning
2. Check Event Viewer for service creation and registry modification events
3. Verify that Windows Defender policies cannot be modified by non-admin users
4. Test that driver loading requires proper signing and authorization
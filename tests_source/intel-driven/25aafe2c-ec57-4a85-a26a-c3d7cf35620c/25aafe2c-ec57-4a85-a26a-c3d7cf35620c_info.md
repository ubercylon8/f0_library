# ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira)

## Test Information

**Test ID**: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c
**Test Name**: ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira)
**Category**: Ransomware / Hypervisor Attack / Multi-Stage Kill Chain
**Severity**: Critical
**MITRE ATT&CK**: T1046, T1018, T1021.004, T1068, T1489, T1529, T1048, T1567.002, T1486

## Description

This test simulates the complete 5-stage kill chain used by ESXi-targeting ransomware operations, synthesized from multiple threat actor TTPs including RansomHub (Go/C++, ChaCha20+Curve25519, intermittent encryption), Akira (dual-variant, SonicWall VPN initial access), Black Basta (-killesxi flag, CVE-2024-37085), and LockBit Linux (vmdumper enumeration, 9x kill retry). The test models the full attack flow from initial reconnaissance through data exfiltration and encryption, providing technique-level detection precision through 5 independently executable stage binaries.

ESXi-targeting IR engagements more than doubled according to Microsoft, and virtually every major RaaS operation now ships an ESXi encryptor. This test evaluates whether an organization's security controls can detect and interrupt the hypervisor ransomware kill chain at any stage.

## Test Score: 9.6/10

**Overall Rating**: Exceptional -- comprehensive multi-stage ESXi ransomware simulation with realistic attack patterns from multiple active threat actors

**Scoring Breakdown**:
| Criterion | Score | Justification |
|-----------|-------|---------------|
| Real-World Accuracy | **2.8/3.0** | Directly models TTPs from RansomHub, Akira, Black Basta, and LockBit ESXi operations. Uses actual vim-cmd/esxcli command patterns, SSH-Snake behavior, CVE-2024-37085/1086 exploitation chains, Rclone with binary rename evasion, and intermittent encryption (1MB/11MB skip pattern). All techniques sourced from active IR engagements. |
| Technical Sophistication | **3.0/3.0** | 5-stage killchain with 9 distinct ATT&CK techniques across 5 tactics. Implements CVE simulation, SSH key harvesting, intermittent encryption algorithms, Rclone cloud exfiltration with renamed binary evasion, LockBit 9x kill retry pattern, and free-space wiping. Multi-stage architecture with per-technique detection isolation. |
| Safety Mechanisms | **2.0/2.0** | All operations are simulated -- no actual encryption, no real VM killing, no real data exfiltration. Simulation files created in c:\Users\fortika-test (non-whitelisted for EDR detection). Dedicated cleanup utility removes all artifacts. Ransom notes clearly marked as simulated. |
| Detection Opportunities | **1.0/1.0** | 10+ distinct detection opportunities across all 5 stages: network scanning, ESXi management commands, SSH key harvesting, AD group creation (CVE-2024-37085), mass VM termination, snapshot deletion, Rclone activity, binary rename evasion, file encryption patterns, and ransom note deployment. |
| Logging & Observability | **0.8/1.0** | Full Schema v2.0 test_logger with per-stage structured logging, WriteStageBundleResults for per-technique ES fan-out, comprehensive artifact generation at each stage, and detailed summary files. Stage-level stdout for real-time monitoring. |

**Key Strengths**:
- Synthesizes TTPs from 4 active ESXi ransomware operations (RansomHub, Akira, Black Basta, LockBit)
- 5-stage multi-stage architecture provides technique-level detection precision
- Simulates 2 real CVEs (CVE-2024-37085 ESXi auth bypass, CVE-2024-1086 kernel privesc)
- Implements realistic Rclone exfiltration with binary rename evasion pattern
- Models RansomHub's intermittent encryption algorithm (1MB encrypt / 11MB skip)
- LockBit's 9x VM kill retry pattern and free-space wiping
- SSH-Snake lateral movement based on Sysdig TRT analysis
- 10+ detection opportunities for comprehensive EDR evaluation

**Improvement Opportunities**:
- Could implement actual ChaCha20 cipher operations on simulation files for deeper crypto detection
- Network-level simulation (actual DNS/HTTP requests to safe endpoints) could test network monitoring

## Technical Details

### Attack Flow

1. **Stage 1: Network Reconnaissance & VM Enumeration (T1046, T1018)**
   - Simulates nmap/fscan network scanning for ESXi hosts on ports 443, 902, 22, 5480
   - Executes simulated `vim-cmd vmsvc/getallvms` to enumerate all VMs (10 VMs across 4 hosts)
   - Executes `esxcli --formatter=csv vm process list` for running VM inventory
   - Performs `vmdumper -l` for VM state enumeration (LockBit pattern)
   - Discovers `/vmfs/volumes/` datastores (3 datastores, 28.7 TB total)
   - Writes reconnaissance summary for subsequent stages

2. **Stage 2: SSH Lateral Movement & Privilege Escalation (T1021.004, T1068)**
   - Simulates SSH-Snake self-modifying worm: discovers 4 ESXi hosts via SSH key chain
   - Harvests 6 SSH private keys from known_hosts, authorized_keys, and config files
   - Exploits CVE-2024-37085: Creates "ESX Admins" AD group for automatic admin rights
   - Exploits CVE-2024-1086: nf_tables use-after-free for root privilege escalation
   - Enables SSH on all ESXi hosts: `vim-cmd hostsvc/enable_ssh` (LockBit pattern)

3. **Stage 3: VM Kill & Snapshot Deletion (T1489, T1529)**
   - Force-kills 9 running VMs: `esxcli vm process kill --type=force --world-id=$wid`
   - Implements LockBit's 9x retry pattern for stubborn VMs (SQL, ERP)
   - Deletes all snapshots: `vim-cmd vmsvc/snapshot.removeall` (32 snapshots across 10 VMs)
   - Powers off all VMs: `vim-cmd vmsvc/power.off $vmid`
   - Stops 8 critical ESXi services (hostd, vpxd, fdm, sps, vsan-health, etc.)

4. **Stage 4: Data Exfiltration via Rclone (T1048, T1567.002)**
   - Creates Rclone configuration with 3 targets: Mega, AWS S3, SFTP staging server
   - Renames Rclone binary to svchost.exe (EDR evasion technique)
   - Stages 847 files (12.3 GB) from /vmfs/volumes/ including SQL backups, Exchange DBs, AD data
   - Syncs to Mega cloud storage with 8 parallel transfers
   - Backup exfiltration to S3 with 64MB chunk size

5. **Stage 5: VMDK Encryption (T1486)**
   - Enumerates 28 target files (.vmdk, .vmx, .vmsn) across 3 datastores
   - Creates simulation files in c:\Users\fortika-test\vmfs_simulation (EDR-visible)
   - Simulates ChaCha20+Curve25519 intermittent encryption (1MB encrypt / 11MB skip)
   - Renames files to .ransomhub extension
   - Deploys ransom notes (README.txt) to all datastores and VM directories
   - Simulates free-space wiping (LockBit 5.0 pattern) on 3 datastores

### Key Indicators

- **vim-cmd** and **esxcli** command execution
- **vmdumper** binary execution
- SSH key file access (id_rsa, id_ed25519, authorized_keys)
- "ESX Admins" Active Directory group creation
- Mass VM process termination events
- Snapshot deletion across multiple VMs
- Rclone binary execution (or renamed variants)
- rclone.conf file creation with cloud storage targets
- Mass file rename to .ransomhub extension
- README.txt ransom note creation in /vmfs/volumes/
- Free-space wipe file creation and deletion

## Detection Opportunities

1. **Network Scanning Detection**
   - Port scanning on ESXi-specific ports (443, 902, 5480, 8697)
   - Multiple SSH connection attempts to management network
   - nmap/fscan process creation

2. **ESXi Management Command Detection**
   - vim-cmd process creation with vmsvc/getallvms arguments
   - esxcli process creation with vm process list arguments
   - vmdumper process execution

3. **SSH Lateral Movement Detection**
   - SSH key file reads (known_hosts, authorized_keys, private keys)
   - SSH connections from unexpected sources
   - bash_history reads for SSH command harvesting

4. **Privilege Escalation Detection**
   - AD group creation matching "ESX Admins" pattern (CVE-2024-37085)
   - nftables rule manipulation (CVE-2024-1086)
   - Service enable commands (vim-cmd hostsvc/enable_ssh)

5. **VM Kill Pattern Detection**
   - Multiple esxcli vm process kill commands in rapid succession
   - VM snapshot removal across many VMs
   - Bulk VM power-off operations
   - Critical service stop commands

6. **Rclone Exfiltration Detection**
   - Rclone binary execution (any name)
   - rclone.conf file creation
   - Renamed binary executing Rclone-like behavior (svchost.exe with cloud API calls)
   - Large outbound data transfers to cloud storage (Mega, S3)

7. **Encryption Activity Detection**
   - Mass file rename with .ransomhub extension
   - Ransom note file creation (README.txt with characteristic content)
   - High-rate file I/O on VMDK files
   - Temporary large file creation/deletion (free-space wipe)

## Expected Results

### Unprotected System (Code 101)
- All 5 stages complete without interruption
- Reconnaissance data collected across 4 simulated ESXi hosts
- Lateral movement artifacts created (SSH-Snake, CVE exploits)
- VM kill and snapshot deletion logs generated
- Rclone exfiltration simulation artifacts in c:\F0\esxi_exfil
- Simulated VMDK files renamed to .ransomhub in c:\Users\fortika-test
- Ransom notes deployed to simulation directories
- Full attack chain demonstrates critical security gap

### Protected System (Enhanced Detection)
- **Code 105**: Stage binary quarantined before execution (file-level detection)
- **Code 126**: Stage blocked during execution (behavioral detection)
  - Stage 1 blocked: Reconnaissance tool detection
  - Stage 2 blocked: SSH key harvesting or exploit simulation detected
  - Stage 3 blocked: Mass VM termination pattern detected
  - Stage 4 blocked: Rclone or data exfiltration pattern detected
  - Stage 5 blocked: Encryption behavior or ransom note detected
- Log output shows which specific technique triggered EDR for remediation focus

## References

- [MITRE ATT&CK T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1489 - Service Stop](https://attack.mitre.org/techniques/T1489/)
- [MITRE ATT&CK T1021.004 - Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/)
- [MITRE ATT&CK T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK T1567.002 - Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
- [CVE-2024-37085 - VMware ESXi Authentication Bypass](https://www.cve.org/CVERecord?id=CVE-2024-37085)
- [CVE-2024-1086 - Linux Kernel nf_tables Use-After-Free](https://www.cve.org/CVERecord?id=CVE-2024-1086)
- [Sysdig TRT - SSH-Snake Analysis (January 2024)](https://sysdig.com/blog/ssh-snake/)
- [ReliaQuest - Rclone in 57% of Ransomware Incidents](https://www.reliaquest.com/)
- [Microsoft Threat Intelligence - ESXi Targeting Trends](https://www.microsoft.com/en-us/security/blog/)

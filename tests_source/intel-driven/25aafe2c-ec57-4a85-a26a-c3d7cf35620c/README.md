# ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira)

**Test Score**: **9.6/10**

## Overview

Simulates the complete 5-stage kill chain used by ESXi-targeting ransomware operations including RansomHub, Akira, Black Basta, and LockBit Linux. "Virtually every major RaaS operation now ships an ESXi encryptor" -- ESXi-targeting IR engagements more than doubled according to Microsoft. This test evaluates endpoint detection capabilities against the full hypervisor ransomware attack flow: from network reconnaissance and VM enumeration, through SSH lateral movement and privilege escalation (CVE-2024-37085, CVE-2024-1086), to VM killing, data exfiltration via Rclone, and intermittent VMDK encryption using ChaCha20+Curve25519.

## MITRE ATT&CK Mapping

| Stage | Tactic | Technique | Description |
|-------|--------|-----------|-------------|
| 1 | Discovery | T1046, T1018 | Network scanning, VM enumeration via vim-cmd/esxcli |
| 2 | Lateral Movement / Privilege Escalation | T1021.004, T1068 | SSH-Snake, CVE-2024-37085, CVE-2024-1086 |
| 3 | Impact | T1489, T1529 | VM force-kill (9x retry), snapshot deletion, service stop |
| 4 | Exfiltration | T1048, T1567.002 | Rclone to Mega/S3, renamed binary evasion |
| 5 | Impact | T1486 | ChaCha20+Curve25519 intermittent encryption, ransom note |

## Architecture

Multi-stage test with 5 embedded signed stage binaries plus cleanup utility. Each stage maps to a distinct phase of the ESXi ransomware kill chain and executes as a separate process for technique-level detection precision.

```
Main Orchestrator (single .exe)
  |-- Stage 1: T1046  (Network Recon & VM Enumeration)
  |-- Stage 2: T1021.004 (SSH Lateral Movement & Privesc)
  |-- Stage 3: T1489  (VM Kill & Snapshot Deletion)
  |-- Stage 4: T1048  (Data Exfiltration via Rclone)
  |-- Stage 5: T1486  (VMDK Encryption)
  |-- Cleanup Utility
```

## Test Execution

```powershell
# Deploy single binary to target
C:\25aafe2c-ec57-4a85-a26a-c3d7cf35620c.exe

# Cleanup after test
C:\F0\esxi_cleanup.exe
```

## Expected Outcomes

- **Protected (Exit 126)**: EDR detects and blocks one of the 5 stages -- the specific blocked technique is logged
- **Unprotected (Exit 101)**: All 5 stages complete without detection -- full ransomware chain succeeded
- **Error (Exit 999)**: Test prerequisites not met or execution error

## Build Instructions

```bash
# Build with dual signing (recommended)
./tests_source/intel-driven/25aafe2c-ec57-4a85-a26a-c3d7cf35620c/build_all.sh --org sb

# Build with F0RT1KA-only signing
./tests_source/intel-driven/25aafe2c-ec57-4a85-a26a-c3d7cf35620c/build_all.sh
```

## Threat Intelligence Sources

- RansomHub ESXi operations (600+ attacks, $244M+ proceeds, ChaCha20+Curve25519)
- Akira dual-variant deployment via SonicWall VPN (CVE-2024-40766)
- Black Basta `-killesxi` bash VM kill sequence (CVE-2024-37085)
- LockBit Linux `vmdumper -l` enumeration, 9x kill retry
- SSH-Snake self-modifying worm (Sysdig TRT, January 2024)
- Rclone in 57% of ransomware incidents (ReliaQuest)
- CVE-2024-37085 ESXi Authentication Bypass (Storm-0506)
- CVE-2024-1086 "Flipping Pages" kernel nf_tables exploit

## Detection Opportunities

1. **Network Scanning** -- Nmap/fscan probes targeting ESXi ports (443, 902, 22, 5480)
2. **ESXi Management Commands** -- vim-cmd, esxcli, vmdumper execution
3. **SSH Key Harvesting** -- Access to known_hosts, authorized_keys, private keys
4. **AD Group Creation** -- "ESX Admins" group creation (CVE-2024-37085)
5. **Mass VM Termination** -- Multiple esxcli vm process kill commands in rapid succession
6. **Snapshot Deletion** -- vim-cmd vmsvc/snapshot.removeall across multiple VMs
7. **Rclone Activity** -- Rclone binary execution, config file creation, cloud sync
8. **Binary Rename** -- Rclone renamed to svchost.exe/csrss.exe
9. **File Encryption** -- Mass file rename to .ransomhub extension
10. **Ransom Note Drop** -- README.txt files in datastore directories

## References

- [MITRE ATT&CK T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1489 - Service Stop](https://attack.mitre.org/techniques/T1489/)
- [MITRE ATT&CK T1021.004 - Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/)
- [MITRE ATT&CK T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [CVE-2024-37085 - VMware ESXi Authentication Bypass](https://www.cve.org/CVERecord?id=CVE-2024-37085)
- [CVE-2024-1086 - Linux Kernel nf_tables Use-After-Free](https://www.cve.org/CVERecord?id=CVE-2024-1086)

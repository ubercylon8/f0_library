# Defense Guidance: ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira)

## Executive Summary

This document provides comprehensive defensive guidance against the ESXi hypervisor ransomware kill chain, synthesized from RansomHub, Akira, Black Basta, and LockBit Linux operations. The attack chain targets VMware ESXi hosts through a 5-stage kill chain: network reconnaissance, SSH lateral movement with CVE exploitation, VM kill and snapshot deletion, Rclone-based data exfiltration, and VMDK encryption with ransom note deployment.

ESXi-targeting IR engagements more than doubled according to Microsoft, and virtually every major RaaS operation now ships an ESXi encryptor. This guidance covers detection engineering, platform hardening, and incident response for all 5 attack stages.

| Field | Value |
|-------|-------|
| **Test ID** | 25aafe2c-ec57-4a85-a26a-c3d7cf35620c |
| **Test Name** | ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira) |
| **MITRE ATT&CK** | T1046, T1018, T1021.004, T1068, T1489, T1529, T1048, T1567.002, T1486 |
| **Severity** | Critical |
| **Platform** | Linux / ESXi |
| **Score** | 9.6/10 |
| **Threat Actors** | RansomHub, Akira, Black Basta, LockBit Linux |

---

## Threat Overview

ESXi-targeting ransomware operations have more than doubled according to Microsoft, and virtually every major RaaS operation now ships an ESXi encryptor. This attack chain combines:

1. **Network Reconnaissance**: nmap/fscan scanning for ESXi hosts, vim-cmd/esxcli/vmdumper VM enumeration
2. **SSH Lateral Movement**: SSH-Snake self-modifying worm, SSH key chain harvesting
3. **Privilege Escalation**: CVE-2024-37085 (ESXi AD auth bypass), CVE-2024-1086 (kernel nf_tables UAF)
4. **Service Disruption**: Force-killing VMs with LockBit 9x retry, snapshot deletion, critical service stops
5. **Data Exfiltration**: Rclone with binary rename to svchost.exe, multi-target cloud sync (Mega, S3, SFTP)
6. **Encryption**: ChaCha20+Curve25519 intermittent encryption (1MB encrypt/11MB skip), ransom note deployment, free-space wipe

### Attack Flow

```
[Network Scan] --> [vim-cmd/esxcli VM Enumeration]
                          |
                          v
              [SSH-Snake Key Harvesting + Lateral Movement]
                          |
                          v
              [CVE-2024-37085: ESX Admins AD Group]
              [CVE-2024-1086: Kernel Root Escalation]
                          |
                          v
              [Force-Kill VMs + Delete Snapshots + Stop Services]
                          |
                          v
              [Rclone Exfiltration: Mega/S3/SFTP (renamed to svchost)]
                          |
                          v
              [Intermittent VMDK Encryption + Ransom Notes + Free-Space Wipe]
```

### Key Threat Intelligence

| Threat Actor | ESXi Variant | Initial Access | Key TTPs |
|-------------|-------------|---------------|----------|
| **RansomHub** | Go/C++ | VPN compromise, RDP | ChaCha20+Curve25519, intermittent encryption, Rclone exfil |
| **Akira** | Dual-variant | SonicWall VPN (CVE-2024-40766) | Cross-platform, vSphere targeting |
| **Black Basta** | Bash script | CVE-2024-37085 | `-killesxi` flag, ESX Admins AD group |
| **LockBit Linux** | ELF | SSH key chains | vmdumper enumeration, 9x kill retry, free-space wipe |

---

## MITRE ATT&CK Mapping with Mitigations

### T1046 - Network Service Discovery

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **[M1030](https://attack.mitre.org/mitigations/M1030/)** | Network Segmentation | Isolate ESXi management network (ports 443, 902, 5480) from general production |
| **[M1031](https://attack.mitre.org/mitigations/M1031/)** | Network Intrusion Prevention | Deploy IDS/IPS on management VLAN boundaries to detect port scanning |
| **[M1035](https://attack.mitre.org/mitigations/M1035/)** | Limit Access to Resource Over Network | Restrict ESXi management ports to authorized jump hosts only |

### T1021.004 - Remote Services: SSH

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **[M1042](https://attack.mitre.org/mitigations/M1042/)** | Disable or Remove Feature | Disable SSH on ESXi hosts when not in active use |
| **[M1032](https://attack.mitre.org/mitigations/M1032/)** | Multi-factor Authentication | Require MFA for SSH access to hypervisors |
| **[M1018](https://attack.mitre.org/mitigations/M1018/)** | User Account Management | Use individual named accounts, never shared root |
| **[M1036](https://attack.mitre.org/mitigations/M1036/)** | Account Use Policies | Implement SSH session timeouts and idle limits |

### T1068 - Exploitation for Privilege Escalation

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **[M1051](https://attack.mitre.org/mitigations/M1051/)** | Update Software | Patch CVE-2024-37085 (vCenter) and CVE-2024-1086 (kernel 6.7+) immediately |
| **[M1048](https://attack.mitre.org/mitigations/M1048/)** | Application Isolation | Use vSphere Trust Authority for ESXi attestation |
| **[M1050](https://attack.mitre.org/mitigations/M1050/)** | Exploit Protection | Apply kernel hardening (KASLR, stack canaries, SMEP/SMAP) |

### T1489 / T1529 - Service Stop / System Shutdown

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **[M1030](https://attack.mitre.org/mitigations/M1030/)** | Network Segmentation | Isolate hypervisor management from workload networks |
| **[M1024](https://attack.mitre.org/mitigations/M1024/)** | Restrict Registry Permissions | Protect ESXi service configurations |
| **[M1022](https://attack.mitre.org/mitigations/M1022/)** | Restrict File/Directory Permissions | Set restrictive permissions on /etc/init.d/ scripts |

### T1048 / T1567.002 - Exfiltration Over Alternative Protocol / Cloud Storage

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **[M1031](https://attack.mitre.org/mitigations/M1031/)** | Network Intrusion Prevention | Block Rclone traffic patterns at network edge |
| **[M1037](https://attack.mitre.org/mitigations/M1037/)** | Filter Network Traffic | Block outbound to Mega, unauthorized S3 endpoints |
| **[M1057](https://attack.mitre.org/mitigations/M1057/)** | Data Loss Prevention | Monitor and alert on large outbound transfers from ESXi hosts |

### T1486 - Data Encrypted for Impact

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **[M1053](https://attack.mitre.org/mitigations/M1053/)** | Data Backup | Maintain offline/immutable VM backups separate from ESXi infrastructure |
| **[M1030](https://attack.mitre.org/mitigations/M1030/)** | Network Segmentation | Air-gap backup infrastructure from production |

---

## Detection Rules

Detection rules are provided in the following files, all targeting technique-level behaviors rather than test framework artifacts:

| File | Format | Rule Count | Purpose |
|------|--------|------------|---------|
| `25aafe2c-ec57-4a85-a26a-c3d7cf35620c_detections.kql` | KQL (Microsoft Sentinel/Defender) | 16 queries | Advanced hunting and analytics |
| `25aafe2c-ec57-4a85-a26a-c3d7cf35620c_sigma_rules.yml` | Sigma 2.0 | 14 rules | SIEM-agnostic detection |
| `25aafe2c-ec57-4a85-a26a-c3d7cf35620c_elastic_rules.ndjson` | Elastic Security (SIEM) | 14 rules | Elastic SIEM import |
| `25aafe2c-ec57-4a85-a26a-c3d7cf35620c_dr_rules.yaml` | LimaCharlie D&R | 12 rules | LimaCharlie EDR |
| `25aafe2c-ec57-4a85-a26a-c3d7cf35620c_rules.yar` | YARA | 8 rules | File/memory scanning |

### Detection Priority Matrix

| Priority | Detection | Confidence | MITRE Technique | Stage |
|----------|-----------|------------|-----------------|-------|
| **P1** | Mass VM Process Kill (esxcli) | Critical | T1489 | 3 |
| **P1** | ESX Admins AD Group Creation (CVE-2024-37085) | Critical | T1068 | 2 |
| **P1** | Ransomware File Extension Rename (.ransomhub) | Critical | T1486 | 5 |
| **P1** | Multi-stage correlation (recon + kill + encrypt) | Critical | Multiple | All |
| **P1** | Binary Rename Evasion (svchost.exe on Linux) | Critical | T1036.005 | 4 |
| **P2** | SSH Key Bulk Access | High | T1021.004 | 2 |
| **P2** | Rclone Execution with Cloud Targets | High | T1048 | 4 |
| **P2** | ESXi SSH Service Enable | High | T1021.004 | 2 |
| **P2** | VM Snapshot Deletion (snapshot.removeall) | High | T1489 | 3 |
| **P3** | vim-cmd/esxcli Management Commands | High | T1046 | 1 |
| **P3** | VMDK/VMX File Modification | Critical | T1486 | 5 |
| **P3** | Free-Space Wiping (dd on datastore) | Critical | T1485 | 5 |
| **P3** | ESXi Critical Service Stop | Critical | T1489 | 3 |
| **P3** | nftables Manipulation (CVE-2024-1086) | Medium | T1068 | 2 |

### Detection Coverage by Attack Stage

| Stage | Technique | KQL | Sigma | Elastic | LimaCharlie | YARA |
|-------|-----------|-----|-------|---------|-------------|------|
| 1 - Recon | T1046, T1018 | Q1 | R1 | E1 | DR1 | Y7 |
| 2 - Lateral/PrivEsc | T1021.004, T1068 | Q3-6, Q13 | R3-4, R11, R14 | E3-4, E14 | DR4-5 | Y3, Y5-6 |
| 3 - VM Kill | T1489, T1529 | Q2, Q12 | R2, R13 | E2, E10-11 | DR2-3, DR11 | Y1 |
| 4 - Exfiltration | T1048, T1567.002 | Q7-8, Q14 | R5-7 | E5, E9, E12 | DR6-8 | Y4 |
| 5 - Encryption | T1486 | Q9-11, Q15 | R8-10, R12 | E6-7, E13 | DR9-10, DR12 | Y2, Y5 |
| All - Correlation | Multiple | Q16 | -- | E8 | -- | -- |

---

## Hardening Guidance

### Quick Wins (Immediate Actions)

1. **Disable SSH on ESXi hosts** when not actively in use
   ```bash
   vim-cmd hostsvc/disable_ssh
   vim-cmd hostsvc/disable_esx_shell
   ```

2. **Patch CVE-2024-37085** -- update vCenter to latest version
   - Remove or rename default "ESX Admins" AD group
   - Monitor for group recreation

3. **Patch CVE-2024-1086** -- update Linux kernel to 6.7+ or apply backported fix
   ```bash
   # Check current kernel version
   uname -r
   # Ubuntu/Debian
   apt update && apt upgrade linux-image-generic
   # RHEL/Rocky
   dnf update kernel
   ```

4. **Block Rclone** -- add Rclone binary hashes to application block policies
   - Block outbound connections to mega.nz, g.api.mega.co.nz
   - Monitor for unauthorized S3 API calls from ESXi management network

5. **Network segmentation** -- isolate ESXi management VLAN from workload networks
   - Restrict management ports (443, 902, 22, 5480) to jump hosts only

6. **Monitor ESX Admins group** -- alert on any creation or modification of this AD group in Windows Security Event Log (Event IDs 4727, 4731, 4754)

### ESXi-Specific Hardening

| Setting | Current Risk | Recommended Action |
|---------|-------------|-------------------|
| SSH Service | Enabled by default on some builds | Disable via `vim-cmd hostsvc/disable_ssh` |
| ESXi Shell | May be enabled | Disable via `vim-cmd hostsvc/disable_esx_shell` |
| Lockdown Mode | Often disabled | Enable Normal or Strict Lockdown Mode |
| AD Integration | ESX Admins group auto-admin | Remove or rename default ESX Admins group |
| vMotion Network | May share management VLAN | Isolate on dedicated VLAN |
| Datastore Access | NFS/iSCSI may be open | Restrict to authorized hosts only |
| SSH Keys | Shared root keys | Use individual keys with passphrase protection |
| Firewall Rules | May allow all outbound | Block unnecessary outbound from ESXi |

### Hardening Scripts

Platform-specific hardening scripts are provided to implement the above recommendations:

| File | Platform | Purpose |
|------|----------|---------|
| `25aafe2c-ec57-4a85-a26a-c3d7cf35620c_hardening.ps1` | Windows / AD | Protect AD against ESX Admins group abuse, network egress controls, backup infrastructure hardening |
| `25aafe2c-ec57-4a85-a26a-c3d7cf35620c_hardening_linux.sh` | Linux / ESXi | SSH hardening, kernel patching verification, firewall rules, Rclone blocking, file integrity monitoring |
| `25aafe2c-ec57-4a85-a26a-c3d7cf35620c_hardening_macos.sh` | macOS | SSH key protection, outbound filtering, exfiltration prevention |

Each script supports three modes:
- **apply** (default) -- applies all hardening settings
- **undo** -- reverts all changes to defaults
- **check** -- verifies current hardening posture without making changes

### Complex Hardening: vSphere Lockdown Mode

**MITRE Mitigation:** [M1042](https://attack.mitre.org/mitigations/M1042/) - Disable or Remove Feature

**Applicable Techniques:** T1021.004, T1489

| Setting | Value |
|---------|-------|
| **Location** | vSphere Client > Host > Configure > System > Security Profile |
| **Recommended Value** | Normal Lockdown Mode (minimum) or Strict Lockdown Mode |
| **Default Value** | Disabled |
| **Impact Level** | Medium -- restricts direct ESXi access to vCenter-managed operations |

**Verification Command:**
```bash
# Check lockdown mode via ESXi CLI
vim-cmd -U dcui hostsvc/hostsummary | grep lockdownMode
# Expected: lockdownNormal or lockdownStrict
```

**Considerations:**
- **Potential Impacts:** Direct SSH and DCUI access will be blocked; all management must go through vCenter
- **Compatibility:** Requires functional vCenter; if vCenter is down, DCUI still accessible in Normal mode
- **Testing:** Test in a non-production environment first; ensure vCenter connectivity is reliable

### Complex Hardening: ESXi Firewall for Outbound Restriction

**MITRE Mitigation:** [M1037](https://attack.mitre.org/mitigations/M1037/) - Filter Network Traffic

**Applicable Techniques:** T1048, T1567.002

```bash
# Block all outbound SSH from ESXi (prevent lateral movement)
esxcli network firewall ruleset set -e false -r sshClient

# Verify firewall rules
esxcli network firewall ruleset list

# Restrict allowed outbound IPs for NTP, DNS, syslog
esxcli network firewall ruleset allowedip add -r ntpClient -i 10.0.0.1
esxcli network firewall ruleset set -e true -r ntpClient -a false
```

**Rollback:**
```bash
esxcli network firewall ruleset set -e true -r sshClient
```

---

## Incident Response Playbook

### Quick Reference

| Field | Value |
|-------|-------|
| **Test ID** | 25aafe2c-ec57-4a85-a26a-c3d7cf35620c |
| **Test Name** | ESXi Hypervisor Ransomware Kill Chain (RansomHub/Akira) |
| **MITRE ATT&CK** | [T1046](https://attack.mitre.org/techniques/T1046/), [T1021.004](https://attack.mitre.org/techniques/T1021/004/), [T1068](https://attack.mitre.org/techniques/T1068/), [T1489](https://attack.mitre.org/techniques/T1489/), [T1048](https://attack.mitre.org/techniques/T1048/), [T1486](https://attack.mitre.org/techniques/T1486/) |
| **Severity** | Critical |
| **Estimated Response Time** | 2-4 hours |
| **Escalation** | Immediate -- hypervisor compromise affects all hosted VMs |

---

### 1. Detection Triggers

| Detection Name | Trigger Criteria | Confidence | Priority |
|----------------|------------------|------------|----------|
| Mass VM Kill | >3 esxcli vm process kill commands in 5 min | Critical | P1 |
| ESX Admins Group | AD group creation matching "ESX Admins" pattern | Critical | P1 |
| Ransomware Extension | .ransomhub/.akira/.lockbit file renames | Critical | P1 |
| SSH Key Harvesting | >3 SSH key file reads by single process | High | P2 |
| Rclone Activity | Cloud sync command with Mega/S3 targets | High | P2 |
| Binary Rename | Windows process name executing on Linux | Critical | P1 |
| Free-Space Wipe | dd if=/dev/zero targeting /vmfs/volumes/ | Critical | P1 |

### Initial Triage Questions

1. Is this a known F0RT1KA security test execution or unexpected activity?
2. What is the scope -- single ESXi host or multiple hosts in the cluster?
3. What user account is associated with the activity?
4. Has SSH been recently enabled on any ESXi hosts?
5. Are any VM snapshot deletion or power-off operations in progress?
6. Is there unusual outbound network traffic to cloud storage providers?

---

### 2. Containment (First 15 Minutes)

- [ ] **Isolate affected ESXi host(s)** from management and production networks
  ```bash
  # Disable all VMkernel adapters except console
  esxcli network ip interface remove -i vmk1
  # Or disconnect from vDS at the physical switch level
  ```

- [ ] **Disable SSH** on all ESXi hosts immediately
  ```bash
  vim-cmd hostsvc/disable_ssh
  ```

- [ ] **Block Rclone cloud destinations** at firewall/proxy
  ```bash
  # Block Mega, unauthorized S3 at Linux firewall
  iptables -A OUTPUT -d mega.nz -j DROP
  iptables -A OUTPUT -d g.api.mega.co.nz -j DROP
  # Block at ESXi level
  esxcli network firewall ruleset set -e false -r httpClient
  ```

- [ ] **Terminate malicious processes**
  ```bash
  # Kill any running rclone or renamed variant
  pkill -9 -f rclone
  pkill -9 -f svchost.exe
  pkill -9 -f csrss.exe
  ```

- [ ] **Preserve volatile evidence** before any remediation
  ```bash
  # Capture running VM state
  esxcli vm process list > /tmp/ir_vm_list_$(date +%s).txt
  # Capture network connections
  esxcli network ip connection list > /tmp/ir_connections_$(date +%s).txt
  # Capture running processes
  ps auxf > /tmp/ir_processes_$(date +%s).txt
  # Capture shell history
  cp /var/log/shell.log /tmp/ir_shell_log_$(date +%s).txt
  ```

---

### 3. Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|--------------------|
| ESXi shell history | `/var/log/shell.log` | `cp /var/log/shell.log /vmfs/volumes/IR/` |
| Authentication logs | `/var/log/auth.log` | `cp /var/log/auth.log /vmfs/volumes/IR/` |
| VMkernel logs | `/var/log/vmkernel.log` | `cp /var/log/vmkernel.log /vmfs/volumes/IR/` |
| Host agent logs | `/var/log/hostd.log` | `cp /var/log/hostd.log /vmfs/volumes/IR/` |
| SSH authorized_keys | `/etc/ssh/keys-root/authorized_keys` | Compare to known baseline |
| Rclone config | `~/.config/rclone/rclone.conf` | Evidence of exfiltration targets |
| Ransom notes | `/vmfs/volumes/*/README.txt` | Capture for attribution analysis |
| Encrypted files | `/vmfs/volumes/*/*.ransomhub` | Sample for decryptor research |
| Process memory | Active processes | `gcore <pid>` or `/proc/<pid>/maps` |
| Network captures | Active connections | `tcpdump -i vmk0 -w /tmp/ir_pcap.pcap -c 10000` |

### Memory Acquisition

```bash
# Capture ESXi diagnostic information
vm-support --output /vmfs/volumes/IR/vm-support-$(date +%s).tgz

# For individual VM memory (if still running)
vim-cmd vmsvc/snapshot.create <vmid> "IR-Snapshot" "Memory capture for IR" true
```

### Timeline Generation

```bash
# Export relevant logs with timestamps
for log in shell auth vmkernel hostd vobd; do
    cp /var/log/${log}.log /vmfs/volumes/IR/${log}_$(date +%s).log 2>/dev/null
done

# Check for attacker persistence
find / -name "*.sh" -newer /var/log/shell.log -type f 2>/dev/null > /vmfs/volumes/IR/new_scripts.txt
find / -name "authorized_keys" -type f 2>/dev/null > /vmfs/volumes/IR/all_authkeys.txt
```

---

### 4. Eradication

```bash
# Remove attacker SSH keys
cat /etc/ssh/keys-root/authorized_keys  # Review each key
# Remove unauthorized entries and save clean copy

# Remove any ESX Admins group from AD
# (On domain controller)
# net group "ESX Admins" /domain /delete

# Remove Rclone configuration and binary
rm -f ~/.config/rclone/rclone.conf
find / -name "rclone" -o -name "rclone.conf" -o -name "svchost.exe" 2>/dev/null | xargs rm -f

# Remove any malicious cron entries
crontab -l 2>/dev/null  # Review
ls -la /etc/cron.d/ /var/spool/cron/

# Re-enable ESXi lockdown mode
vim-cmd hostsvc/advancedoption set UserVars.ESXiShellInteractiveTimeOut 300
```

---

### 5. Recovery

- [ ] Restore VMs from offline/immutable backups (do NOT trust any backup accessible from compromised ESXi)
- [ ] Rebuild ESXi hosts from clean installation media if root compromise is suspected
- [ ] Rotate ALL SSH keys on ALL ESXi hosts and connected systems
- [ ] Rotate AD service accounts used for vCenter integration
- [ ] Re-enable Lockdown Mode on all ESXi hosts
- [ ] Verify no "ESX Admins" group exists in Active Directory
- [ ] Re-baseline all ESXi host configurations against CIS VMware ESXi Benchmark
- [ ] Apply all outstanding patches (CVE-2024-37085, CVE-2024-1086)

### Validation Commands

```bash
# Verify SSH is disabled
vim-cmd hostsvc/runtime_info | grep -i ssh

# Verify lockdown mode
vim-cmd -U dcui hostsvc/hostsummary | grep lockdownMode

# Verify no unauthorized keys
cat /etc/ssh/keys-root/authorized_keys | wc -l

# Verify no Rclone artifacts
find / -name "rclone*" -o -name "svchost.exe" 2>/dev/null

# Verify ESXi services are running normally
esxcli system process list | grep -E "hostd|vpxd|fdm"

# Check AD for ESX Admins group (from domain controller)
# Get-ADGroup -Filter "Name -like 'ESX*Admin*'"
```

---

### 6. Post-Incident

### Lessons Learned Questions

1. How was the attack detected? Which detection rule fired first?
2. What was the detection-to-containment time?
3. Were all ESXi hosts patched against CVE-2024-37085 and CVE-2024-1086?
4. Was SSH disabled on ESXi hosts as per security baseline?
5. Were VM backups stored on a separate, air-gapped infrastructure?
6. Was there network segmentation between ESXi management and workload networks?
7. Were outbound connections from ESXi management network restricted?

### Recommended Improvements

| Area | Recommendation | Priority |
|------|----------------|----------|
| Detection | Deploy ESXi-specific SIEM detections for vim-cmd/esxcli abuse | Critical |
| Detection | Implement Rclone binary and traffic detection at network edge | High |
| Detection | Monitor AD for ESX Admins group creation (Event ID 4727/4731) | Critical |
| Prevention | Implement vSphere Trust Authority for ESXi host attestation | High |
| Prevention | Air-gap VM backup infrastructure from production ESXi | Critical |
| Prevention | Patch CVE-2024-37085 and CVE-2024-1086 across all hosts | Critical |
| Prevention | Enable ESXi Lockdown Mode (Normal or Strict) | High |
| Prevention | Block outbound cloud storage (Mega, unauthorized S3) from management VLAN | High |
| Architecture | Isolate ESXi management network with ACLs and firewall rules | High |
| Architecture | Deploy jump hosts for ESXi administration with MFA | High |
| Response | Pre-stage ESXi rebuild media and golden images at all sites | Medium |
| Response | Document and rehearse ESXi ransomware recovery runbook quarterly | Medium |

---

## References

- [MITRE ATT&CK T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1489 - Service Stop](https://attack.mitre.org/techniques/T1489/)
- [MITRE ATT&CK T1529 - System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529/)
- [MITRE ATT&CK T1021.004 - Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/)
- [MITRE ATT&CK T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
- [MITRE ATT&CK T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK T1567.002 - Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
- [MITRE ATT&CK T1036.005 - Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [MITRE ATT&CK T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [CVE-2024-37085 - VMware ESXi Authentication Bypass](https://www.cve.org/CVERecord?id=CVE-2024-37085)
- [CVE-2024-1086 - Linux Kernel nf_tables Use-After-Free](https://www.cve.org/CVERecord?id=CVE-2024-1086)
- [Sysdig TRT - SSH-Snake Analysis (January 2024)](https://sysdig.com/blog/ssh-snake/)
- [ReliaQuest - Rclone in 57% of Ransomware Incidents](https://www.reliaquest.com/)
- [Microsoft Threat Intelligence - Ransomware operators exploit ESXi hypervisor vulnerability (July 2024)](https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/)
- [CIS VMware ESXi 8.0 Benchmark](https://www.cisecurity.org/benchmark/vmware)

# Defense Guidance: Perfctl/Symbiote LD_PRELOAD Hijacking with PAM Credential Harvesting

## Executive Summary

This document provides comprehensive defensive guidance against LD_PRELOAD-based rootkit attacks, synthesized from four real-world malware families: **Perfctl** (cryptomining, 3+ years targeting millions of Linux servers), **Symbiote** (financial sector, Latin America, 2025 variants), **Auto-Color** (university/government targets), and **WolfsBane** (Gelsemium APT, state-sponsored). The attack chain spans 5 phases: LD_PRELOAD shared library hijacking, PAM credential hooking, network artifact hiding via userland rootkit, XOR-encrypted C2 configuration, and SUID binary abuse for privilege escalation.

| Field | Value |
|-------|-------|
| **Test ID** | 54a0bd24-d75a-4d89-8dce-c381d932ca97 |
| **Test Name** | Perfctl/Symbiote LD_PRELOAD Hijacking with PAM Credential Harvesting |
| **MITRE ATT&CK** | T1574.006, T1003.008, T1548.001, T1014, T1059.004 |
| **Severity** | Critical |
| **Platform** | Linux (primary), with Windows/macOS equivalents |
| **Score** | 9.4/10 |

---

## Threat Overview

LD_PRELOAD hijacking is the dominant persistence and evasion technique for sophisticated Linux malware. By writing a malicious shared library path to `/etc/ld.preload` or `/etc/ld.so.preload`, attackers force the dynamic linker to load their code into every user-mode process on the system. This enables:

- **Credential harvesting**: Hooking `pam_authenticate` to capture all SSH, sudo, and login credentials
- **Network hiding**: Hooking `open()`, `read()`, and `pcap_loop()` to scrub C2 connections from `/proc/net/tcp`
- **File/process hiding**: Hooking `readdir()` and `stat()` to hide malicious files from listing tools
- **Persistence**: Surviving reboots via systemd services, crontab trojanization, and shell profile injection

### Attack Flow

```
[Phase 1: LD_PRELOAD Injection]
    |-- libgcwrap.so dropped to /lib/x86_64-linux-gnu/ (Perfctl)
    |-- /etc/ld.preload written (Auto-Color)
    |-- /etc/ld.so.preload written (WolfsBane/BEURK)
    |-- Systemd service with LD_PRELOAD env var (Perfctl)
    |-- ~/.profile injection: export LD_PRELOAD=... (Perfctl)
    v
[Phase 2: PAM Credential Hooking]
    |-- pam_authenticate hooked via libgcwrap.so
    |-- Credentials captured from sshd, sudo, login
    |-- /etc/shadow dumped (SHA-512, yescrypt hashes)
    |-- Credential log staged for XOR-encrypted exfiltration
    v
[Phase 3: Network Artifact Hiding]
    |-- open() hooked to scrub /proc/net/tcp (Auto-Color)
    |-- read() hooked for file content filtering (Symbiote)
    |-- pcap_loop() hooked to hide C2 traffic from tcpdump (Perfctl)
    |-- 3 C2 connections hidden from userland tools
    v
[Phase 4: XOR-Encrypted C2 Configuration]
    |-- Plaintext config: pool, wallet, beacon settings
    |-- XOR encryption with Perfctl key 0xAC
    |-- Trojanized crontab binary hides malicious entries
    v
[Phase 5: SUID Abuse for Privilege Escalation]
    |-- find / -type f -perm -u=s enumeration
    |-- 6 exploitable SUID binaries (GTFOBins)
    |-- find -exec /bin/sh, vim -c ':!/bin/sh', bash -p
    |-- chmod u+s /bin/bash for persistent root
```

### Threat Actor Profiles

| Actor | Type | Targets | Key Technique |
|-------|------|---------|---------------|
| **Perfctl** | eCrime (cryptomining) | Millions of Linux servers (3+ years) | libgcwrap.so + XOR 0xAC + pam_authenticate hook |
| **Symbiote** | eCrime (financial) | Latin American banks | libc + libpcap dual hooking, 8-port IPv6 support |
| **Auto-Color** | Targeted | Universities, government | /etc/ld.preload + open() hook for /proc/net/tcp scrubbing |
| **WolfsBane** | APT (Gelsemium) | State-sponsored targets | Modified BEURK rootkit via /etc/ld.so.preload |

---

## MITRE ATT&CK Mapping with Mitigations

### T1574.006 - Hijack Execution Flow: Dynamic Linker Hijacking

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **M1038** | Execution Prevention | Use immutable attributes on /etc/ld.preload and /etc/ld.so.preload |
| **M1022** | Restrict File and Directory Permissions | Set strict permissions on /lib/, /usr/lib/, and ld.preload files |
| **M1047** | Audit | Deploy auditd rules to monitor writes to ld.preload files |
| **M1028** | Operating System Configuration | Mount /dev/shm with noexec,nosuid,nodev options |

### T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **M1027** | Password Policies | Enforce strong passwords that resist offline cracking |
| **M1026** | Privileged Account Management | Minimize accounts with /etc/shadow read access |
| **M1022** | Restrict File and Directory Permissions | Ensure /etc/shadow is mode 640 owned by root:shadow |
| **M1032** | Multi-factor Authentication | Deploy MFA for SSH and sudo to reduce credential value |

### T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **M1038** | Execution Prevention | Remove SUID from non-essential binaries (vim, nmap, python) |
| **M1028** | Operating System Configuration | Enable nosuid on /tmp and /home mount points |
| **M1047** | Audit | Monitor chmod commands that set SUID bits |

### T1014 - Rootkit

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **M1040** | Behavior Prevention on Endpoint | Deploy eBPF-based monitoring that bypasses userland hooks |
| **M1047** | Audit | Compare /proc/net/tcp with conntrack for discrepancies |
| **M1028** | Operating System Configuration | Enable Secure Boot, kernel module signing |

### T1059.004 - Command and Scripting Interpreter: Unix Shell

| Mitigation ID | Mitigation Name | Implementation |
|---------------|-----------------|----------------|
| **M1038** | Execution Prevention | Restrict crontab access via /etc/cron.allow |
| **M1022** | Restrict File and Directory Permissions | Protect crontab binary integrity |
| **M1031** | Network Intrusion Prevention | Block outbound connections to known mining pools |

---

## Detection Rules Summary

### Available Detection Formats

| Format | File | Rules Count | Purpose |
|--------|------|-------------|---------|
| **KQL** | `54a0bd24_detections.kql` | 16 queries | Microsoft Sentinel / Defender for Endpoint |
| **Sigma** | `54a0bd24_sigma_rules.yml` | 16 rules | Platform-agnostic, converts to any SIEM |
| **Elastic** | `54a0bd24_elastic_rules.ndjson` | 12 rules | Elastic Security SIEM (import via API) |
| **YARA** | `54a0bd24_rules.yar` | 8 rules | File/memory scanning |
| **LimaCharlie** | `54a0bd24_dr_rules.yaml` | 10 rules | LimaCharlie EDR D&R rules |

### Detection Coverage Matrix

| Attack Phase | KQL | Sigma | Elastic | YARA | LimaCharlie |
|-------------|-----|-------|---------|------|-------------|
| LD_PRELOAD file write | Q1, Q16 | S1, S4 | E1, E3 | R7 | DR1, DR3 |
| Suspicious .so drop | Q2 | S2 | E2 | R1, R2, R3, R4 | DR2 |
| Systemd LD_PRELOAD service | Q3 | S3 | E3 | - | DR3 |
| Shell profile injection | Q4 | S4 | - | - | DR9 |
| PAM module tampering | Q5 | S5 | E4 | R5 | DR4 |
| /etc/shadow access | Q6 | S6 | E5 | R8 | DR5 |
| PAM auth anomalies | Q7 | S14 | - | - | - |
| SUID enumeration | Q8 | S7 | E6 | - | DR6 |
| SUID bit on interpreter | Q9 | S8 | E7 | - | DR7 |
| GTFOBins exploitation | Q10 | S9 | E8 | - | DR8 |
| Rootkit network comparison | Q11 | S11 | - | - | - |
| XOR encrypted configs | Q12 | - | - | R6 | - |
| Crontab modification | Q13 | S10 | E9 | - | DR10 |
| Mining pool connections | Q14 | S12 | E10 | - | - |
| Perfctl process names | - | S15 | E11 | R2 | - |
| Correlated attack chain | Q15 | S16 | E12 | - | - |

---

## Key Detection Queries (Highlights)

### Critical: LD_PRELOAD Persistence File Write (KQL)

```kql
Syslog
| where SyslogMessage has_any ("/etc/ld.preload", "/etc/ld.so.preload")
| where SyslogMessage has_any ("open", "write", "create", "modify")
```

**Why this matters**: Any write to these files should trigger an immediate investigation. Legitimate use is virtually nonexistent.

### Critical: Combined Behavioral Detection (KQL)

```kql
// Correlates: .so creation + shadow access + SUID enumeration = attack chain
let SuspiciousSO = DeviceFileEvents | where FileName endswith ".so" ...;
let ShadowAccess = DeviceFileEvents | where FileName == "shadow" ...;
let SUIDEnum = DeviceProcessEvents | where FileName == "find" and ProcessCommandLine has "-perm" ...;
SuspiciousSO | join ShadowAccess on DeviceName | join SUIDEnum on DeviceName
```

**Why this matters**: The combination of all three indicators on the same host is an extremely high-confidence indicator of an active LD_PRELOAD rootkit campaign.

### Critical: LD_PRELOAD Attack Chain Sequence (Elastic EQL)

```eql
sequence by host.id with maxspan=1h
  [file where event.type == "creation" and file.extension == "so"
   and file.path : ("/lib/*", "/usr/lib/*", "/tmp/*", "/dev/shm/*")]
  [process where event.type == "start" and process.name == "find"
   and process.args : ("-perm", "-u=s", "/4000", "-4000")]
```

**Why this matters**: Elastic's EQL sequence detection catches the temporal correlation between .so drops and SUID enumeration within a 1-hour window.

---

## Hardening Guidance

### Quick Reference

| Script | Platform | Purpose |
|--------|----------|---------|
| `54a0bd24_hardening_linux.sh` | Linux | Primary target hardening (10 controls) |
| `54a0bd24_hardening_macos.sh` | macOS | DYLD equivalent hardening (8 controls) |
| `54a0bd24_hardening.ps1` | Windows | DLL hijacking equivalent hardening (7 controls) |

### Linux Hardening Controls (Primary)

| # | Control | MITRE | Impact |
|---|---------|-------|--------|
| 1 | Lock /etc/ld.preload with immutable flag | T1574.006 | **Critical** - Prevents primary persistence |
| 2 | Restrict ptrace to admin-only (YAMA scope=2) | T1574.006, T1014 | **High** - Blocks runtime hooking |
| 3 | Harden /etc/shadow permissions (640) | T1003.008 | **High** - Prevents credential harvesting |
| 4 | Remove SUID from dangerous binaries | T1548.001 | **Critical** - Eliminates privilege escalation |
| 5 | Deploy auditd rules (15+ rules) | All | **High** - Enables real-time detection |
| 6 | Harden shared library directories | T1574.006 | **Medium** - Prevents .so drops |
| 7 | Deploy AIDE file integrity monitoring | T1014, T1574.006 | **High** - Detects rootkit modifications |
| 8 | Restrict crontab access | T1059.004 | **High** - Prevents cron persistence |
| 9 | Deploy rootkit network detection | T1014 | **Medium** - Detects connection hiding |
| 10 | Block mining pool connections | T1059.004 | **Medium** - Stops cryptojacking revenue |

### Deployment Instructions

```bash
# Linux - Apply all hardening
sudo ./54a0bd24-d75a-4d89-8dce-c381d932ca97_hardening_linux.sh apply

# Linux - Check current posture
sudo ./54a0bd24-d75a-4d89-8dce-c381d932ca97_hardening_linux.sh check

# Linux - Revert all changes
sudo ./54a0bd24-d75a-4d89-8dce-c381d932ca97_hardening_linux.sh undo

# macOS - Apply hardening
sudo ./54a0bd24-d75a-4d89-8dce-c381d932ca97_hardening_macos.sh apply

# Windows - Apply hardening (PowerShell as Administrator)
.\54a0bd24-d75a-4d89-8dce-c381d932ca97_hardening.ps1

# Windows - Revert
.\54a0bd24-d75a-4d89-8dce-c381d932ca97_hardening.ps1 -Undo
```

### Critical AuditD Rules (Manual Deployment)

If the hardening script cannot be run, deploy these auditd rules manually:

```bash
# /etc/audit/rules.d/90-ldpreload.rules
-w /etc/ld.so.preload -p wa -k ld_preload_persistence
-w /etc/ld.preload -p wa -k ld_preload_persistence
-w /etc/pam.d/ -p wa -k pam_module_change
-w /etc/shadow -p r -k shadow_access
-w /usr/bin/crontab -p wa -k crontab_integrity
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F a2&04000 -k suid_change
```

### Complex Hardening: /dev/shm noexec Mount

**MITRE Mitigation:** [M1028](https://attack.mitre.org/mitigations/M1028/) - Operating System Configuration

**Applicable Techniques:** T1574.006, T1014

**Implementation:**

| Setting | Value |
|---------|-------|
| **Location** | /etc/fstab |
| **Recommended Value** | `tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0` |
| **Default Value** | `tmpfs /dev/shm tmpfs defaults 0 0` |
| **Impact Level** | Low |

**Verification Command:**
```bash
mount | grep shm | grep noexec
```

**Rollback Command:**
```bash
mount -o remount,exec /dev/shm
# Then remove noexec from /etc/fstab
```

**Considerations:**
- **Potential Impacts:** Some applications (Oracle DB, certain build tools) use /dev/shm for executable shared memory. Test thoroughly.
- **Compatibility:** Works on all modern Linux distributions.
- **Testing:** Run application test suite after applying to ensure no functionality is broken.

---

## Incident Response Playbook

### Quick Reference

| Field | Value |
|-------|-------|
| **Test ID** | 54a0bd24-d75a-4d89-8dce-c381d932ca97 |
| **Test Name** | Perfctl/Symbiote LD_PRELOAD Hijacking |
| **MITRE ATT&CK** | T1574.006, T1003.008, T1548.001, T1014, T1059.004 |
| **Severity** | Critical |
| **Estimated Response Time** | 4-8 hours |

### 1. Detection Triggers

| Detection Name | Trigger Criteria | Confidence | Priority |
|----------------|------------------|------------|----------|
| LD_PRELOAD file write | Write to /etc/ld.preload or /etc/ld.so.preload | Critical | P1 |
| Suspicious .so creation | New .so in /lib/ by non-package-manager | High | P1 |
| PAM module tampering | File change in /etc/pam.d/ or /lib/security/ | High | P1 |
| Shadow file access | Non-standard process reads /etc/shadow | High | P2 |
| SUID bit on interpreter | chmod u+s on bash, python, vim, etc. | Critical | P1 |
| SUID enumeration | find -perm -u=s command execution | High | P2 |
| Mining pool connection | DNS query to supportxmr.com etc. | High | P2 |
| Attack chain correlation | SO drop + shadow access + SUID enum | Critical | P1 |

### Initial Triage Questions

1. Is this a known F0RT1KA test execution or unexpected activity?
2. What is the scope -- single host or multiple hosts?
3. What user account is associated with the activity?
4. What is the timeline -- when did the first indicator appear?
5. Are there active C2 connections visible in conntrack but not in ss/netstat?

### 2. Containment (First 15 Minutes)

- [ ] **Isolate affected host(s)**
  ```bash
  # Network isolation via iptables
  iptables -P INPUT DROP
  iptables -P OUTPUT DROP
  iptables -P FORWARD DROP
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT
  # Allow management SSH from known IP
  iptables -A INPUT -s <MGMT_IP> -p tcp --dport 22 -j ACCEPT
  iptables -A OUTPUT -d <MGMT_IP> -p tcp --sport 22 -j ACCEPT
  ```

- [ ] **Check for active rootkit**
  ```bash
  # Compare connection counts from different sources
  echo "=== /proc/net/tcp ===" && wc -l /proc/net/tcp
  echo "=== ss ===" && ss -tun | wc -l
  echo "=== conntrack ===" && conntrack -C 2>/dev/null
  # If counts differ significantly, rootkit is active
  ```

- [ ] **Preserve volatile evidence**
  ```bash
  mkdir -p /tmp/IR-$(date +%Y%m%d)
  # Process listing (from kernel, bypasses rootkit)
  ls -la /proc/*/exe 2>/dev/null > /tmp/IR-$(date +%Y%m%d)/processes.txt
  # Network connections (kernel view)
  cat /proc/net/tcp > /tmp/IR-$(date +%Y%m%d)/proc_net_tcp.txt
  cat /proc/net/tcp6 > /tmp/IR-$(date +%Y%m%d)/proc_net_tcp6.txt
  # Active LD_PRELOAD state
  cat /etc/ld.so.preload 2>/dev/null > /tmp/IR-$(date +%Y%m%d)/ld_so_preload.txt
  cat /etc/ld.preload 2>/dev/null > /tmp/IR-$(date +%Y%m%d)/ld_preload.txt
  # PAM configuration
  cp -r /etc/pam.d/ /tmp/IR-$(date +%Y%m%d)/pam.d/
  ```

### 3. Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| LD_PRELOAD config | `/etc/ld.preload`, `/etc/ld.so.preload` | `cp /etc/ld*.preload* /tmp/IR/` |
| Malicious .so files | `/lib/`, `/usr/lib/`, `/dev/shm/`, `/tmp/` | `find / -name "*.so" -newer /etc/passwd` |
| PAM modules | `/etc/pam.d/`, `/lib/security/` | `cp -r /etc/pam.d/ /lib/security/ /tmp/IR/` |
| Shadow file | `/etc/shadow` | `cp /etc/shadow /tmp/IR/shadow.bak` |
| Credential logs | `/tmp/`, `/var/tmp/`, home dirs | `find / -name "*credential*" -o -name "*pam_capture*"` |
| Systemd services | `/etc/systemd/system/` | `ls -la /etc/systemd/system/*.service` |
| Crontab binary | `/usr/bin/crontab` | `sha256sum /usr/bin/crontab` and `dpkg -V cron` |
| Shell profiles | `~/.profile`, `~/.bashrc` | `grep LD_PRELOAD /home/*/.profile /root/.profile` |
| Audit logs | `/var/log/audit/` | `cp /var/log/audit/audit.log /tmp/IR/` |
| Auth logs | `/var/log/auth.log` | `cp /var/log/auth.log /tmp/IR/` |

### Memory Acquisition

```bash
# Using LiME (Linux Memory Extractor)
insmod lime.ko "path=/tmp/IR/memory.lime format=lime"

# Or using /proc/kcore (if available)
cp /proc/kcore /tmp/IR/kcore.raw
```

### 4. Eradication

```bash
# Step 1: Remove LD_PRELOAD persistence (AFTER evidence collection)
chattr -i /etc/ld.so.preload /etc/ld.preload 2>/dev/null
> /etc/ld.so.preload  # Empty the file
> /etc/ld.preload      # Empty the file

# Step 2: Remove malicious shared libraries
rm -f /lib/x86_64-linux-gnu/libgcwrap.so
rm -f /usr/lib/libmodule.so
# Remove any other identified malicious .so files

# Step 3: Restore PAM configuration
dpkg --force-confmiss -i $(dpkg -S /etc/pam.d/ | cut -d: -f1 | head -1) 2>/dev/null
# Or restore from backup

# Step 4: Remove malicious systemd services
systemctl disable <malicious-service> 2>/dev/null
rm -f /etc/systemd/system/<malicious-service>.service
systemctl daemon-reload

# Step 5: Restore crontab binary
apt-get install --reinstall cron 2>/dev/null   # Debian/Ubuntu
yum reinstall cronie 2>/dev/null                # RHEL/CentOS

# Step 6: Clean shell profiles
for profile in /home/*/.profile /root/.profile /home/*/.bashrc /root/.bashrc; do
    if grep -q "LD_PRELOAD" "$profile" 2>/dev/null; then
        sed -i '/LD_PRELOAD/d' "$profile"
        sed -i '/wizlmsh/d' "$profile"
        sed -i '/perfctl/d' "$profile"
    fi
done

# Step 7: Remove SUID from dangerous binaries
chmod u-s /usr/bin/vim* /usr/bin/nano /usr/bin/nmap /usr/bin/find 2>/dev/null

# Step 8: Kill malicious processes
pkill -9 wizlmsh 2>/dev/null
pkill -9 perfctl 2>/dev/null
pkill -9 perfcc 2>/dev/null

# Step 9: Remove hidden directories
rm -rf /tmp/.hidden/ 2>/dev/null
rm -rf /dev/shm/.* 2>/dev/null
```

### 5. Recovery

**System Restoration Checklist**

- [ ] Verify /etc/ld.preload and /etc/ld.so.preload are empty or removed
- [ ] Verify no malicious .so files remain in /lib/ and /usr/lib/
- [ ] Verify PAM configuration integrity via package manager
- [ ] Verify crontab binary integrity via package manager
- [ ] Verify shell profiles are clean of LD_PRELOAD exports
- [ ] Verify no SUID on dangerous binaries (vim, nmap, python, etc.)
- [ ] Verify no malicious systemd services
- [ ] Remove network isolation and reconnect
- [ ] Rotate all credentials (passwords compromised via PAM hook)
- [ ] Apply hardening script to prevent reinfection

**Validation Commands**
```bash
# Verify LD_PRELOAD files are clean
cat /etc/ld.so.preload /etc/ld.preload 2>/dev/null | grep -v "^#"
# Should be empty

# Verify no suspicious .so files
find /lib /usr/lib /dev/shm /tmp -name "*.so" -newer /etc/hostname 2>/dev/null

# Verify PAM integrity
dpkg -V libpam-modules 2>/dev/null || rpm -V pam 2>/dev/null

# Verify crontab integrity
dpkg -V cron 2>/dev/null || rpm -V cronie 2>/dev/null

# Verify no malicious processes
ps aux | grep -E "wizlmsh|perfctl|perfcc|xmrig" | grep -v grep

# Verify no SUID on interpreters
find /usr/bin -name "vim*" -o -name "python*" -o -name "perl" -o -name "nmap" | \
    xargs ls -la 2>/dev/null | grep "^-..s"
```

### 6. Post-Incident

**Credential Rotation (MANDATORY)**

Because PAM credential hooking captures all authentication attempts, assume ALL credentials used during the compromise period are compromised:

1. Reset all local user passwords
2. Rotate SSH keys for all users
3. Revoke and regenerate service account credentials
4. Reset database passwords if captured
5. Rotate API keys and tokens used via sudo

**Lessons Learned Questions**

1. How was the attack detected? (Which rule/alert?)
2. What was the detection-to-response time?
3. What would have prevented this attack? (immutable ld.preload, SUID removal)
4. What detection gaps were identified?
5. Were eBPF or kernel-level monitoring tools in place to bypass rootkit hiding?

**Recommended Improvements**

| Area | Recommendation | Priority |
|------|----------------|----------|
| Prevention | Set immutable flag on /etc/ld.preload files | Critical |
| Prevention | Remove SUID from non-essential binaries | Critical |
| Prevention | Mount /dev/shm and /tmp with noexec,nosuid | High |
| Detection | Deploy auditd rules from hardening script | High |
| Detection | Deploy eBPF-based network monitoring | High |
| Detection | Implement file integrity monitoring (AIDE/OSSEC) | High |
| Response | Pre-stage rootkit detection scripts on systems | Medium |
| Response | Document baseline SUID binaries per OS image | Medium |
| Recovery | Maintain package manager hash database for integrity checks | Medium |

---

## References

- [Aqua Security - Perfctl Malware Analysis (October 2024)](https://www.aquasec.com/blog/perfctl-malware/)
- [FortiGuard Labs - Symbiote 2025 Variants (December 2025)](https://www.fortiguard.com/threat-signal-report/)
- [Unit 42 - Auto-Color Malware (February 2025)](https://unit42.paloaltonetworks.com/)
- [ESET - WolfsBane Backdoor (November 2024)](https://www.welivesecurity.com/)
- [MITRE ATT&CK T1574.006 - Hijack Execution Flow: Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006/)
- [MITRE ATT&CK T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008/)
- [MITRE ATT&CK T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001/)
- [MITRE ATT&CK T1014 - Rootkit](https://attack.mitre.org/techniques/T1014/)
- [MITRE ATT&CK T1059.004 - Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [GTFOBins - Unix Binaries SUID Abuse](https://gtfobins.github.io/)

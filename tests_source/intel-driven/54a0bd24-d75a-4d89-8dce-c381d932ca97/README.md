# Perfctl/Symbiote LD_PRELOAD Hijacking with PAM Credential Harvesting

**Test Score**: **9.4/10**

## Overview

Simulates the dominant Linux persistence and evasion technique used by sophisticated malware families: LD_PRELOAD shared library hijacking combined with PAM credential hooking, network artifact hiding, XOR-encrypted C2 configuration, and SUID abuse for privilege escalation. This test models real-world TTPs from Perfctl (3+ years targeting millions of Linux servers), Symbiote (financial sector, Latin America), Auto-Color (university/government targets), and WolfsBane/Gelsemium APT.

The test creates simulated artifacts that mirror the file patterns, encryption schemes, and persistence mechanisms used by these threat actors, enabling evaluation of EDR/AV detection capabilities against Linux-targeting attack chains deployed on Windows-based F0RT1KA infrastructure.

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Persistence | T1574.006 | Hijack Execution Flow: LD_PRELOAD |
| Credential Access | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow |
| Privilege Escalation | T1548.001 | Abuse Elevation Control Mechanism: SUID/SGID |
| Defense Evasion | T1014 | Rootkit (Userland) |
| Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell |

## Threat Intelligence Sources

- **Perfctl** (Aqua Security, Oct 2024): libgcwrap.so hooks pam_authenticate + pcap_loop; XOR key 0xAC; targeted millions of Linux servers for 3+ years
- **Symbiote** (FortiGuard Labs, Dec 2025): Hooks libc + libpcap; 3 new 2025 variants with IPv6 and 8-port support; financial sector targeting
- **Auto-Color** (Unit 42, Feb 2025): Writes malicious library to /etc/ld.preload; hooks open() to scrub /proc/net/tcp
- **WolfsBane** (ESET, Nov 2024): Gelsemium APT; modified BEURK rootkit; hooks open, stat, readdir via /etc/ld.so.preload

## Test Execution

The test executes 5 sequential phases simulating a complete LD_PRELOAD-based attack chain:

1. **LD_PRELOAD Injection** - Creates simulated malicious .so, /etc/ld.preload, systemd service, and ~/.profile modification
2. **PAM Credential Hooking** - Simulates pam_authenticate hooking and /etc/shadow credential dumping
3. **Network Artifact Hiding** - Creates original vs. scrubbed /proc/net/tcp showing hidden C2 connections
4. **XOR-Encrypted C2 Config** - Generates Perfctl-style XOR-encrypted configuration with key 0xAC
5. **SUID Abuse** - Simulates SUID binary enumeration and GTFOBins-based privilege escalation

## Expected Outcomes

- **Protected (Code 105)**: Simulated .so file quarantined by EDR before execution
- **Protected (Code 126)**: One or more simulation phases blocked by security controls
- **Unprotected (Code 101)**: All 5 phases completed without prevention - system vulnerable to LD_PRELOAD-based attacks

## Artifacts Created

All artifacts are dropped to `c:\F0` as per F0RT1KA requirements:

| Artifact | Description |
|----------|-------------|
| `libgcwrap.so` | Simulated malicious shared library (ELF header + stub code) |
| `etc_ld.preload` | Simulated /etc/ld.preload persistence file |
| `etc_ld.so.preload` | Simulated /etc/ld.so.preload (WolfsBane pattern) |
| `perfctl_systemd_service.txt` | Simulated systemd persistence service |
| `profile_modification.txt` | Simulated ~/.profile injection |
| `pam_credential_capture.log` | Simulated PAM credential capture log |
| `shadow_dump.txt` | Simulated /etc/shadow dump |
| `passwd_enum.txt` | Simulated /etc/passwd enumeration |
| `proc_net_tcp_original.txt` | Original /proc/net/tcp with all connections |
| `proc_net_tcp_scrubbed.txt` | Rootkit-scrubbed version hiding C2 connections |
| `hidden_connections_report.txt` | Report of hidden network connections |
| `pcap_filter_rules.txt` | Simulated Symbiote pcap filtering rules |
| `c2_config_plaintext.json` | Plaintext C2 configuration |
| `c2_config_encrypted.bin` | XOR-encrypted C2 config (key 0xAC) |
| `trojanized_crontab.txt` | Simulated trojanized crontab output |
| `suid_enumeration.txt` | SUID binary discovery results |
| `suid_exploit_log.txt` | SUID exploitation log |
| `cleanup.bat` | Cleanup utility to remove all artifacts |

## Build Instructions

```bash
# Standard build
./utils/gobuild build tests_source/intel-driven/54a0bd24-d75a-4d89-8dce-c381d932ca97/
./utils/codesign sign build/54a0bd24-d75a-4d89-8dce-c381d932ca97/54a0bd24-d75a-4d89-8dce-c381d932ca97.exe
```

## Cleanup

Run `c:\F0\cleanup.bat` on the target system after test execution to remove all simulation artifacts.

# CIS Linux Endpoint Level 1 Hardening Bundle

**Test Score**: **9.2/10**

## Overview

Multi-binary cyber-hygiene bundle that validates 35 CIS Linux Benchmark Level 1 controls across 7 security categories. Each category runs as an independent embedded validator binary, providing quarantine resilience -- if an EDR/AV agent quarantines one validator, the remaining validators still execute and report results.

## MITRE ATT&CK Mapping

| Technique | Name | Tactic |
|-----------|------|--------|
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion |
| T1021.004 | Remote Services: SSH | Lateral Movement |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid/Setgid | Privilege Escalation |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution |
| T1070.002 | Indicator Removal: Clear Linux/Mac System Logs | Defense Evasion |
| T1543.002 | Create or Modify System Process: Systemd Service | Persistence |

## Validators

| # | Validator | Controls | Category |
|---|-----------|----------|----------|
| 1 | Filesystem Security | CH-CL1-001 to CH-CL1-004 (4) | cramfs, USB storage, /tmp noexec, /var/tmp |
| 2 | Service Hardening | CH-CL1-005 to CH-CL1-008 (4) | xinetd, avahi, cups, time sync |
| 3 | Network Security | CH-CL1-009 to CH-CL1-013 (5) | IP forwarding, ICMP, source routing, firewall |
| 4 | Audit & Logging | CH-CL1-014 to CH-CL1-018 (5) | auditd, retention, identity files, permissions |
| 5 | SSH Configuration | CH-CL1-019 to CH-CL1-024 (6) | protocol, root login, auth tries, keys |
| 6 | Access Control | CH-CL1-025 to CH-CL1-030 (6) | sudo, password hashing, PAM, root lock |
| 7 | System Maintenance | CH-CL1-031 to CH-CL1-035 (5) | file permissions, world-writable, SUID audit |

**Total: 35 controls across 7 validators**

## Requirements

- **Platform**: Linux (Debian/Ubuntu, RHEL/CentOS/Rocky/Alma)
- **Privileges**: Root (sudo)
- **Dependencies**: Standard Linux utilities (sysctl, systemctl, auditctl, iptables)

## Build Instructions

```bash
# Build the bundle
./tests_source/cyber-hygiene/7f0d43e7-8a7b-48f3-9aff-cfa9703a51e8/build_all.sh

# Deploy to target
scp build/7f0d43e7-8a7b-48f3-9aff-cfa9703a51e8/7f0d43e7-8a7b-48f3-9aff-cfa9703a51e8 debian:/opt/f0/

# Execute (requires root)
ssh debian 'sudo /opt/f0/7f0d43e7-8a7b-48f3-9aff-cfa9703a51e8'
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 126 | COMPLIANT -- all 35 controls passed |
| 101 | NON-COMPLIANT -- one or more controls failed |
| 999 | ERROR -- prerequisites not met (not root, missing tools) |

## Output Files

| File | Location | Description |
|------|----------|-------------|
| `test_execution_log.json` | `/tmp/F0/` | Schema v2.0 structured execution log |
| `test_execution_log.txt` | `/tmp/F0/` | Human-readable execution log |
| `bundle_results.json` | `/tmp/F0/` | Per-control results for ES fan-out |

## Architecture

Multi-binary bundle pattern (same as Windows baseline `a3c923ae`):

1. Orchestrator extracts each embedded validator to `/tmp/F0/`
2. Waits 1.5s for EDR/AV quarantine reaction
3. Checks if file still exists (quarantine detection via `os.Stat`)
4. Executes as subprocess, reads `/tmp/F0/vr_<name>.json`
5. Merges all results into `/tmp/F0/bundle_results.json`
6. Cleans up validator binaries and output files

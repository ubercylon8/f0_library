# CrowdStrike Falcon Configuration Validator

**Test Score**: **8.0/10**

## Overview

This cyber hygiene test validates that CrowdStrike Falcon endpoint protection is properly configured with all critical protection features enabled. Proper Falcon configuration is essential for preventing ransomware and other advanced threats. This is the CrowdStrike equivalent of the Microsoft Defender Configuration Validator test.

## MITRE ATT&CK Mapping

- **Tactic**: Defense Evasion
- **Techniques**:
  - T1562.001 - Impair Defenses: Disable or Modify Tools
  - T1562.004 - Impair Defenses: Disable or Modify System Firewall
  - T1070 - Indicator Removal

## Configuration Checks

All 6 checks must pass for COMPLIANT status (exit code 126):

| # | Check | Method | Compliant Value |
|---|-------|--------|-----------------|
| 1 | Falcon Sensor Service | Service query | CSFalconService = Running |
| 2 | Sensor Operational Status | Registry | ProvisioningState = 1 (Provisioned) |
| 3 | Prevention Mode | Service/Registry | Enabled (not detect-only) |
| 4 | Sensor Version | Registry/File | >= 7.0 |
| 5 | Cloud Connectivity | Registry | Connected |
| 6 | Tamper Protection | Service/Registry | Enabled |

### Registry Locations Checked

| Check | Registry Path | Value |
|-------|---------------|-------|
| Agent ID | `HKLM\SYSTEM\CrowdStrike\{9b03c1d9...}\{16e0423f...}\Default\AG` | CID string |
| Provisioning | `HKLM\SYSTEM\CrowdStrike\{9b03c1d9...}\{16e0423f...}\Default\ProvisioningState` | 1 |
| Version | `HKLM\SOFTWARE\CrowdStrike\Falcon\Version` | Version string |
| Service | `HKLM\SYSTEM\CurrentControlSet\Services\CSAgent` | Service config |

## Test Characteristics

- **Type**: Configuration Validation (READ-ONLY)
- **Category**: Cyber Hygiene
- **Priority**: CRITICAL
- **Admin Required**: Recommended (some checks work without)
- **Destructive**: No
- **Network Required**: No

## Expected Outcomes

- **Code 126 (COMPLIANT)**: All 6 protection checks pass
- **Code 101 (NON-COMPLIANT)**: One or more checks fail
- **Code 999 (ERROR)**: Test error (e.g., Falcon not installed, insufficient privileges)

## CIS Benchmark Reference

- **CIS Controls v8: 10.1** - Deploy and Maintain Anti-Malware Software
- **CIS Controls v8: 10.2** - Configure Automatic Updates for Anti-Malware Signature Files

## Build Instructions

```bash
# Build the test
./utils/gobuild build tests_source/cyber-hygiene/bac53a6e-dd97-4764-bb10-2ee605f24808/

# Sign the binary
./utils/codesign sign build/bac53a6e-dd97-4764-bb10-2ee605f24808/bac53a6e-dd97-4764-bb10-2ee605f24808.exe
```

## Remediation Guidance

If the test returns NON-COMPLIANT (exit code 101), apply the following remediations:

### Start Falcon Sensor Service

```cmd
sc start CSFalconService
```

Or:

```cmd
net start CSFalconService
```

### Verify Sensor Provisioning

1. Verify the correct CID was used during installation
2. Check network connectivity to CrowdStrike cloud (*.crowdstrike.com)
3. Review sensor health status in Falcon console

### Enable Prevention Policies

1. Log into Falcon console (falcon.crowdstrike.com)
2. Navigate to Configuration > Prevention Policies
3. Ensure prevention policies are applied to the host's sensor group

### Update Sensor Version

1. Enable automatic sensor updates in Falcon console
2. Or manually deploy the latest sensor version
3. Minimum recommended version: 7.0+

### Verify Cloud Connectivity

1. Ensure firewall allows outbound HTTPS to *.crowdstrike.com
2. Verify proxy settings if applicable
3. Check sensor logs for connectivity errors

### Enable Tamper Protection

Tamper protection is enabled by default when the sensor is running. Ensure:
1. Kernel driver (CSAgent) is loaded
2. No errors in Falcon console sensor health alerts

## Output Files

After execution, the test produces:
- `c:\F0\test_execution_log.json` - Structured JSON log (Schema v2.0)
- `c:\F0\test_execution_log.txt` - Human-readable text log
- `c:\F0\falcon_status_output.txt` - Sensor status details

## Why CrowdStrike Falcon Validation Matters

CrowdStrike Falcon provides next-generation endpoint protection that goes beyond traditional antivirus. A properly configured Falcon sensor provides:

- **Real-time threat prevention** - Blocks known and unknown malware
- **Behavioral analysis** - Detects fileless attacks and suspicious behavior
- **Threat intelligence** - Leverages CrowdStrike's global threat data
- **Tamper protection** - Prevents attackers from disabling the sensor

Without proper configuration, sophisticated attackers may be able to:
- Disable the sensor before executing ransomware
- Operate in a "detect-only" blind spot
- Evade detection due to outdated sensor versions

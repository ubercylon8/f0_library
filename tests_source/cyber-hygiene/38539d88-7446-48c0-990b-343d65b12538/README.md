# Network Protocol Hardening Validator

**Test Score**: **7.5/10**

## Overview

This cyber hygiene test validates that dangerous legacy network protocols are disabled to prevent credential harvesting attacks. Tools like Responder exploit LLMNR, NetBIOS, and WPAD broadcast protocols to intercept authentication requests and harvest credentials on local networks.

## MITRE ATT&CK Mapping

- **Tactics**: Credential Access, Collection
- **Techniques**:
  - T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning
  - T1557 - Adversary-in-the-Middle
  - T1040 - Network Sniffing

## Configuration Checks

| Check | Registry/Method | Compliant Value |
|-------|-----------------|-----------------|
| LLMNR Disabled | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast` | 0 |
| NetBIOS Disabled | Per-adapter: `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*\NetbiosOptions` | 2 (Disabled on all adapters) |
| WPAD Mitigated | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WpadOverride` or service disabled | 1 or disabled |

### NetBIOS Options Values

- **0** = Default (use DHCP setting - potentially enabled)
- **1** = Enabled
- **2** = Disabled

## Test Characteristics

- **Type**: Configuration Validation (READ-ONLY)
- **Category**: Cyber Hygiene
- **Priority**: HIGH
- **Admin Required**: Yes
- **Destructive**: No
- **Network Required**: No

## Expected Outcomes

- **Code 126 (COMPLIANT)**: All 3 protocol hardening checks pass
- **Code 101 (NON-COMPLIANT)**: One or more checks fail
- **Code 999 (ERROR)**: Test error (e.g., insufficient privileges)

## CIS Benchmark Reference

- **CIS Controls v8: 4.8** - Uninstall or Disable Unnecessary Services on Enterprise Assets and Software
- **CIS Controls v8: 3.10** - Encrypt Sensitive Data in Transit

## GPO Paths

- **LLMNR**: `Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution`
- **NetBIOS**: Per-adapter configuration in Network Adapter Properties > TCP/IPv4 > Advanced > WINS tab
- **WPAD**: Disable via Internet Options or GPO for IE/Edge settings

## Build Instructions

```bash
# Build the test
./utils/gobuild build tests_source/cyber-hygiene/38539d88-7446-48c0-990b-343d65b12538/

# Sign the binary
./utils/codesign sign build/38539d88-7446-48c0-990b-343d65b12538/38539d88-7446-48c0-990b-343d65b12538.exe
```

## Remediation Guidance

If the test returns NON-COMPLIANT (exit code 101), apply the following remediations:

### Disable LLMNR

```powershell
# Via GPO (preferred):
# Computer Configuration > Administrative Templates > Network > DNS Client
# > Turn off multicast name resolution = Enabled

# Via Registry:
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
```

### Disable NetBIOS on All Adapters

```powershell
# Disable NetBIOS on all adapters via WMI
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -ne $null }
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable
}

# Or via registry for each Tcpip_* interface:
# Set NetbiosOptions = 2 under:
# HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}
```

### Mitigate WPAD

```powershell
# Method 1: Set WpadOverride registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "WpadOverride" -Value 1 -Type DWord

# Method 2: Disable WinHTTP Auto-Proxy Service
Set-Service -Name WinHttpAutoProxySvc -StartupType Disabled
Stop-Service -Name WinHttpAutoProxySvc -Force

# Method 3: Disable auto-detect in Internet Options (per-user)
# Internet Options > Connections > LAN Settings > Uncheck "Automatically detect settings"
```

## Output Files

After execution, the test produces:
- `c:\F0\test_execution_log.json` - Structured JSON log (Schema v2.0)
- `c:\F0\test_execution_log.txt` - Human-readable text log
- `c:\F0\wpad_diagnostics.txt` - WPAD mitigation diagnostic output

## Security Context

### Why These Protocols Are Dangerous

1. **LLMNR/NetBIOS Poisoning**: When a Windows host fails to resolve a hostname via DNS, it falls back to LLMNR (UDP 5355) and NetBIOS (UDP 137) broadcasts. An attacker on the local network can respond to these broadcasts, redirecting traffic to their machine and capturing NTLMv2 hashes.

2. **WPAD Exploitation**: WPAD allows automatic proxy configuration discovery. Attackers can respond to WPAD queries to inject malicious proxy configurations, enabling man-in-the-middle attacks on web traffic.

3. **Responder Tool**: The popular Responder tool automates these attacks, making credential harvesting trivial on networks where these protocols are enabled.

### Attack Scenario

1. Attacker runs Responder on the local network
2. User types an invalid hostname (e.g., `\\fileserverr` with typo)
3. DNS fails, host broadcasts LLMNR/NetBIOS query
4. Responder responds, claiming to be the requested host
5. User's machine sends NTLM authentication to attacker
6. Attacker captures NTLMv2 hash for offline cracking

# Identity Endpoint Posture Bundle

**Test UUID**: `7659eeba-f315-440e-9882-4aa015d68b27`

## Overview

This bundled security test validates the identity posture of Windows endpoints by checking 5 critical identity and cloud-integration configurations. It complements the Entra ID Tenant Security Hygiene Bundle (`4f484076`) by focusing on the **endpoint side** of identity hardening -- device join status, Windows Hello for Business, MDM enrollment, cloud credential protection, and BitLocker cloud escrow.

**Test Score**: **8.7/10**

## Included Validators

| # | Validator | Checks | Key Configurations |
|---|-----------|--------|-------------------|
| 1 | Device Join Status | 5 | AAD Join, Domain Join, Join Type, Tenant Info, Device Auth |
| 2 | Windows Hello for Business | 5 | WHfB Policy, NGC Provider, PIN Complexity, NGC Keys, Biometrics |
| 3 | Intune/MDM Enrollment | 4 | MDM Enrollment, MDM Authority, Compliance Policies, Config Profiles |
| 4 | Cloud Credential Protection | 5 | PRT Status, PRT Update, Cloud Kerberos Trust, Device-Bound PRT, SSO State |
| 5 | BitLocker Cloud Escrow | 3 | BitLocker Enabled, Recovery Key AAD Backup, Encryption Method |

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 126 | COMPLIANT | All 5 validators passed - identity posture is properly hardened |
| 101 | NON-COMPLIANT | One or more validators failed - identity gaps detected |
| 999 | ERROR | Test error (administrator privileges required) |

## MITRE ATT&CK Coverage

- **T1078.004** - Valid Accounts: Cloud Accounts
- **T1556.007** - Modify Authentication Process: Hybrid Identity
- **T1556.006** - Modify Authentication Process: MFA Interception
- **T1528** - Steal Application Access Token
- **T1550.001** - Use Alternate Authentication Material: Application Access Token
- **T1588.004** - Obtain Capabilities: Digital Certificates
- **T1005** - Data from Local System
- **T1111** - Multi-Factor Authentication Request Generation

## Requirements

- Windows 10/11 or Windows Server 2019+
- Administrator privileges
- Azure AD joined or hybrid-joined device (for full validation)

## Build

```bash
cd tests_source/cyber-hygiene/7659eeba-f315-440e-9882-4aa015d68b27/
go mod tidy
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ../../../build/7659eeba-f315-440e-9882-4aa015d68b27/7659eeba-f315-440e-9882-4aa015d68b27.exe *.go
```

## Usage

```powershell
# Run as Administrator
.\7659eeba-f315-440e-9882-4aa015d68b27.exe
```

## Output

The test produces:
1. Console output with formatted results for each validator
2. JSON log file at `C:\F0\7659eeba-f315-440e-9882-4aa015d68b27_execution_log.json`

## References

- [Azure AD Device Identity](https://learn.microsoft.com/en-us/entra/identity/devices/)
- [Windows Hello for Business Deployment](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/)
- [Intune Device Enrollment](https://learn.microsoft.com/en-us/mem/intune/enrollment/)
- [Primary Refresh Token (PRT)](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
- [BitLocker Recovery Key Storage](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
- [MITRE ATT&CK](https://attack.mitre.org/)

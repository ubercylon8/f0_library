# Entra ID Tenant Security Hygiene Bundle

**Test UUID**: `4f484076-9816-4813-947e-b76bce3d3f83`

## Overview

This bundled security test validates the identity security posture of a Microsoft Entra ID tenant against the CISA SCuBA (Secure Cloud Business Applications) baseline. It authenticates via service principal to the Microsoft Graph API and checks 8 security domains encompassing ~26 controls.

**Test Score**: **9.2/10**

## Included Validators

| # | Validator | SCuBA Section | Checks | Key Configurations |
|---|-----------|---------------|--------|--------------------|
| 1 | Legacy Authentication | MS.AAD.1.x | 1 | CA policy blocking legacy auth protocols |
| 2 | Risk-Based Policies | MS.AAD.2.x | 3 | High-risk user/sign-in blocking, notifications |
| 3 | Strong Authentication (MFA) | MS.AAD.3.x | 7 | Phishing-resistant MFA, weak methods, Authenticator context |
| 4 | Centralized Log Collection | MS.AAD.4.x | 1 | Diagnostic settings for AuditLogs/SignInLogs |
| 5 | Application Governance | MS.AAD.5.x | 3 | App registration, user consent, admin workflow |
| 6 | Password Policies | MS.AAD.6.x | 1 | NIST 800-63B non-expiring passwords |
| 7 | Privileged Access Management | MS.AAD.7.x | 7 | GA count, PIM, cloud-only admins, approval |
| 8 | Guest Access Controls | MS.AAD.8.x | 3 | Guest restrictions, invitation limits, domain filtering |

## Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+ with Microsoft Graph PowerShell SDK installed
- Service principal with read-only Graph API permissions
- Environment variables: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`

### Required Graph API Permissions

| Permission | Type | Purpose |
|-----------|------|---------|
| Policy.Read.All | Application | Conditional Access, auth methods |
| Directory.Read.All | Application | Roles, users, groups |
| RoleManagement.Read.All | Application | PIM assignments |
| AuditLog.Read.All | Application | Diagnostic settings |
| Application.Read.All | Application | App registration/consent |

### PowerShell Module Installation

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 126 | COMPLIANT | All 8 validators passed -- tenant is properly configured |
| 101 | NON-COMPLIANT | One or more validators failed -- identity security gaps detected |
| 999 | ERROR | Prerequisites not met (missing env vars, modules, or auth failure) |

## MITRE ATT&CK Coverage

- **T1078.004** - Valid Accounts: Cloud Accounts
- **T1556.007** - Modify Authentication Process: Hybrid Identity
- **T1110.001** - Brute Force: Password Guessing
- **T1098.003** - Account Manipulation: Additional Cloud Roles
- **T1098.001** - Account Manipulation: Additional Cloud Credentials
- **T1566** - Phishing
- **T1528** - Steal Application Access Token
- **T1562.008** - Impair Defenses: Disable Cloud Logs

## Build

```bash
./utils/gobuild build tests_source/cyber-hygiene/4f484076-9816-4813-947e-b76bce3d3f83/
```

## Usage

```powershell
# Set environment variables
$env:AZURE_TENANT_ID = "<your-tenant-id>"
$env:AZURE_CLIENT_ID = "<your-client-id>"
$env:AZURE_CLIENT_SECRET = "<your-client-secret>"

# Run the test
.\4f484076-9816-4813-947e-b76bce3d3f83.exe
```

## Output

The test produces:
1. Console output with formatted results for each validator
2. JSON log file at `C:\F0\4f484076-9816-4813-947e-b76bce3d3f83_execution_log.json`

## References

- [CISA SCuBA Baseline for Entra ID](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project)
- [CIS Microsoft 365 Foundations Benchmark](https://www.cisecurity.org/benchmark/microsoft_365)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)

# CIS Identity & Active Directory Level 1 Bundle

**Test UUID**: `602a5333-e9cf-4ddf-a132-a22aa7126447`

## Overview

This bundled security test validates the identity and Active Directory security posture of a domain-joined Windows environment against CIS Benchmark Level 1 controls. It queries on-premises Active Directory via PowerShell AD cmdlets and optionally validates Entra ID (Azure AD) tenant controls via Microsoft Graph API. The bundle covers 6 security domains with 28 controls total.

**Test Score**: **9.3/10**

## Included Validators

| # | Validator | Controls | Checks | Key Configurations |
|---|-----------|----------|--------|--------------------|
| 1 | Privileged Account Management | CH-CIA-001 to 005 | 5 | Domain/Enterprise/Schema Admins count, Protected Users, AdminSDHolder |
| 2 | Service Account Security | CH-CIA-006 to 008 | 3 | gMSA usage, service account password age, unconstrained delegation |
| 3 | Authentication Hardening | CH-CIA-009 to 012 | 4 | Fine-grained password policies, KRBTGT rotation, reversible encryption, pre-auth |
| 4 | AD Infrastructure | CH-CIA-013 to 018 | 6 | Recycle Bin, functional level, stale accounts, LDAP signing/channel binding |
| 5 | Group Policy Security | CH-CIA-019 to 021 | 3 | Password length, GPO permissions, audit policy |
| 6 | Entra ID Controls | CH-CIA-022 to 028 | 7 | MFA, legacy auth, PIM, app registration, security defaults, break-glass |

## Prerequisites

### Required (Always)
- Windows 10/11 or Windows Server 2016+ **domain-joined**
- PowerShell 5.1+ with RSAT AD PowerShell tools installed
- Network connectivity to a domain controller

### Optional (For Entra ID Checks)
- PowerShell Microsoft Graph SDK installed
- Service principal with read-only Graph API permissions
- Environment variables: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`

If Entra ID environment variables are not set, AD checks (CH-CIA-001 to 021) still run normally. Entra checks (CH-CIA-022 to 028) are marked as skipped.

### RSAT Installation

```powershell
# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell
```

### Graph API Permissions (Optional)

| Permission | Type | Purpose |
|-----------|------|---------|
| Policy.Read.All | Application | Conditional Access policies |
| Directory.Read.All | Application | Directory roles, users |
| RoleManagement.Read.All | Application | PIM assignments |
| Application.Read.All | Application | App registration settings |

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 126 | COMPLIANT | All validators passed -- controls properly configured |
| 101 | NON-COMPLIANT | One or more validators failed -- security gaps detected |
| 999 | ERROR | Prerequisites not met (not domain-joined, no RSAT, or AD unreachable) |

## MITRE ATT&CK Coverage

- **T1078.002** - Valid Accounts: Domain Accounts
- **T1098.001** - Account Manipulation: Additional Cloud Credentials
- **T1098.003** - Account Manipulation: Additional Cloud Roles
- **T1558.003** - Steal or Forge Kerberos Tickets: Kerberoasting
- **T1558.004** - Steal or Forge Kerberos Tickets: AS-REP Roasting
- **T1078.004** - Valid Accounts: Cloud Accounts
- **T1556.007** - Modify Authentication Process: Hybrid Identity
- **T1484.001** - Domain Policy Modification: Group Policy Modification

## Build

```bash
cd tests_source/cyber-hygiene/602a5333-e9cf-4ddf-a132-a22aa7126447
GOOS=windows GOARCH=amd64 go build -o ../../../build/602a5333-e9cf-4ddf-a132-a22aa7126447/602a5333-e9cf-4ddf-a132-a22aa7126447.exe .
```

## Usage

```powershell
# AD-only (no Entra ID checks)
.\602a5333-e9cf-4ddf-a132-a22aa7126447.exe

# Full (AD + Entra ID checks)
$env:AZURE_TENANT_ID = "<your-tenant-id>"
$env:AZURE_CLIENT_ID = "<your-client-id>"
$env:AZURE_CLIENT_SECRET = "<your-client-secret>"
.\602a5333-e9cf-4ddf-a132-a22aa7126447.exe
```

## Output

The test produces:
1. Console output with formatted results for each validator
2. JSON log file at `C:\F0\602a5333-e9cf-4ddf-a132-a22aa7126447_execution_log.json`
3. Per-control results at `C:\F0\bundle_results.json` (28 controls)

## References

- [CIS Microsoft Windows Server Benchmark](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [CIS Microsoft 365 Foundations Benchmark](https://www.cisecurity.org/benchmark/microsoft_365)
- [Microsoft Active Directory Security Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [Group Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)

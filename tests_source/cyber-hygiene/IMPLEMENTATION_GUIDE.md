# Implementation Guide: F0RT1KA Cyber-Hygiene Controls

**Date**: February 16, 2026
**Framework**: F0RT1KA Security Testing Library
**Scope**: 98 security controls across 3 bundles -- honest assessment of implementation difficulty

---

## Purpose

This guide provides an honest, field-tested assessment of what it actually takes to implement the 98 security controls validated by the F0RT1KA Cyber-Hygiene bundles. The goal is not to discourage implementation -- the [Risk Reduction Analysis](RISK_REDUCTION_ANALYSIS.md) demonstrates 93-96% risk reduction -- but to ensure organizations embark on this journey with complete information for successful deployment.

---

## Implementation Difficulty Summary

| Control | Difficulty | Timeline (500 users) | Licensing | User Impact | Rollback |
|---------|-----------|---------------------|-----------|-------------|----------|
| Defender + Tamper Protection | Easy | 1-2 weeks | E3 | Low | Easy |
| ASR Rules (8 critical) | **Hard** | **3-6 months** | E3/E5 | Medium | Easy |
| LSASS Protection | Medium | 2-3 months | Enterprise | Medium | **Hard** |
| SMB Hardening | **Hard** | **4-9 months** | Any | Medium | Medium |
| PowerShell CLM + Logging | **Hard** | **3-6 months** | Any | **High** | Easy |
| LLMNR/NetBIOS/WPAD Disable | Medium | 5-7 weeks | Any | Low | Easy |
| Windows Audit Logging | Easy | 6-10 weeks | Any | None | Easy |
| Account Lockout + Passwords | Easy | 4 weeks | Any | Medium | Easy |
| LAPS | Easy | 5-7 weeks | Any | None | Easy |
| Print Spooler Hardening | Easy | 2 weeks | Any | **Varies** | Easy |
| MFA Enforcement | Medium | **4-8 months** | **P1/P2** | **High** | Easy |
| Block Legacy Auth | Medium | 3-4 months | P1 | Medium | Easy |
| Risk-Based Conditional Access | Medium | 8-12 weeks | **P2** | Medium | Easy |
| PIM / JIT Access | Medium | 6-10 weeks | **P2/E5** | Medium | Easy |
| Limit Global Admins | Easy | 7-11 weeks | Any | Low | Easy |
| Guest Access Restrictions | Easy | 4-5 weeks | Any | Low | Easy |
| App Consent Restrictions | Medium | 5-7 weeks | Any | **High** | Easy |
| Centralized Audit Logging | Easy | 2-3 weeks | P1/P2 | None | Easy |
| Azure AD Join / Hybrid Join | Medium | 3-4 months | E3 | Low | Medium |
| Windows Hello for Business | **Hard** | **5-7 months** | E3 | Medium | Medium |
| Intune/MDM Enrollment | **Hard** | **4-6 months** | E3 | Medium | Medium |
| PRT Protection | Medium | 7-12 weeks | P1 | Low | Easy |
| BitLocker Cloud Escrow | Medium | 6-10 weeks | E3 | Low | Medium |

**Legend**: Easy = minimal risk, straightforward deployment. Medium = requires planning, some gotchas. **Hard** = significant effort, high breakage risk, requires extensive testing.

---

## Licensing Requirements (The Hidden Cost)

Before planning any deployment, understand the licensing landscape. Many advanced controls require premium licensing that organizations often don't have.

### What You Get at Each Tier

| Tier | Monthly/User | Key Security Features Unlocked |
|------|-------------|-------------------------------|
| **Microsoft 365 E3** | ~$36 | Defender P1, basic ASR, Intune, Conditional Access (P1), BitLocker, LAPS |
| **Entra ID P1** (add-on) | $6 | Conditional Access, self-service password reset, MFA (basic) |
| **Entra ID P2** (add-on) | $9 | Risk-based CA, PIM, Identity Protection, access reviews |
| **Microsoft 365 E5** | ~$57 | Everything: Defender P2, full ASR reporting, E-Discovery, advanced compliance |

### What Breaks Without the Right License

| Control | Without License | Impact |
|---------|----------------|--------|
| Risk-based Conditional Access | Cannot detect risky sign-ins | You're blind to impossible-travel, leaked credentials |
| PIM / JIT Access | No just-in-time activation | Standing admin access = larger attack surface |
| Identity Protection | No risk-level detection | Can't auto-remediate compromised accounts |
| Advanced ASR Reporting | Rules work, but no centralized reporting | Can't measure effectiveness or tune false positives |
| Conditional Access | No policy engine at all | Cannot enforce MFA, device compliance, location restrictions |

### Budget Planning

For a 500-person organization starting from M365 E3:

| Upgrade Path | Additional Monthly Cost | Annual Cost |
|-------------|------------------------|-------------|
| Add Entra ID P2 for all users | $4,500/month | **$54,000/year** |
| Add Entra ID P2 for admins only (50) | $450/month | $5,400/year |
| Upgrade to M365 E5 for all users | $10,500/month | **$126,000/year** |
| Hybrid: E5 for 50 admins + P2 for 450 users | $5,100/month | $61,200/year |

**Recommendation**: Start with P2 for administrators and security team only. Expand as budget allows. Many tenant-level controls (PIM, risk policies) only need licensed admin accounts.

---

## Bundle 1: Windows Endpoint Hardening (52 checks)

### 1. Microsoft Defender Configuration (6 checks)

**Difficulty**: Easy | **Timeline**: 1-2 weeks | **User Impact**: Low

**What goes right**: Modern Defender is lightweight, well-integrated, and scores 100% on MITRE evaluations. Most organizations already have it enabled.

**What goes wrong**:
- Tamper Protection automatically enables Cloud Protection -- if you had Cloud Protection deliberately disabled (e.g., air-gapped environments), enabling Tamper Protection changes this without warning
- UEFI lock for Tamper Protection prevents disabling without system wipe -- **do not enable UEFI lock until you're sure**
- Legacy antivirus conflicts: if a third-party AV is installed, Defender enters passive mode and checks will fail
- Cloud Protection sends file samples to Microsoft -- organizations with strict data sovereignty requirements may object

**Deployment approach**:
1. Remove third-party AV first (clean uninstall, not just disable)
2. Enable features via GPO/Intune in this order: Real-time > Behavior monitoring > Cloud Protection > Tamper Protection
3. Leave UEFI lock disabled initially
4. Verify with `Get-MpComputerStatus` on pilot machines

---

### 2. Attack Surface Reduction Rules (8 checks)

**Difficulty**: Hard | **Timeline**: 3-6 months | **User Impact**: Medium

**This is the control most likely to break production.**

**The January 2023 Incident**: A Defender update caused ASR rules to delete desktop icons and Start Menu shortcuts across thousands of organizations globally. Microsoft issued an emergency fix, but the damage was done. This single incident taught the industry that ASR rules, while powerful, require careful management.

**What goes wrong**:
- **Line-of-business applications break**: Custom apps that spawn child processes from Office, use macro APIs, or execute scripts from email are immediately blocked
- **Administrative tools trigger false positives**: Software deployment tools (SCCM, Patch My PC), monitoring agents, and automation scripts are frequently blocked
- **Identifying which rule caused the block takes time**: Event ID 1121 in Microsoft-Windows-Windows Defender/Operational log, but correlating to the right rule requires patience
- **Users lose productivity**: Macros they've relied on for years stop working

**The mandatory approach** (skipping this guarantees incidents):
1. **Week 1-2**: Deploy ALL rules in **Audit mode** -- this logs what would be blocked without actually blocking
2. **Week 3-6**: Analyze audit logs daily, identify legitimate applications being flagged
3. **Week 6-8**: Create exclusions for verified legitimate applications
4. **Week 8-10**: Move rules to **Warn mode** -- users get a warning but can click through
5. **Week 10+**: Move rules to **Block mode** one at a time, monitoring for issues
6. **Ongoing**: Microsoft recommends 30-45 days minimum in Audit before enforcement

**Per-rule risk assessment**:

| ASR Rule | Breakage Risk | What Typically Breaks |
|----------|--------------|----------------------|
| Block Office child processes | **High** | Macros that launch PowerShell, CMD, or custom apps |
| Block macro API calls | **High** | VBA macros using Win32 API calls |
| Block email executable content | Medium | Legitimate email-delivered installers |
| Block obfuscated scripts | Medium | Obfuscated but legitimate admin scripts |
| Block JS/VBS downloads | Low | Rarely impacts modern workflows |
| Block Office code injection | Medium | Add-ins that inject into Office processes |
| Block Office executable creation | Medium | Macros that create files on disk |
| Block comms app child processes | Low | Rarely impacts standard workflows |

---

### 3. LSASS Protection -- RunAsPPL + Credential Guard (3 checks)

**Difficulty**: Medium | **Timeline**: 2-3 months | **User Impact**: Medium

**What goes wrong**:
- **Credential Guard + VMware = conflict**: Credential Guard requires Hyper-V, which conflicts with VMware Workstation and VirtualBox. Developer workstations running VMs will break. This is the #1 blocker in organizations with developer populations
- **Exchange Servers are incompatible**: Microsoft explicitly states Credential Guard should NOT be enabled on Exchange servers
- **Domain Controllers should not enable Credential Guard**: Causes application compatibility issues with Kerberos
- **Saved RDP credentials stop working**: Users who saved passwords for RDP connections get "Logon attempt failed" -- they must re-enter credentials each time
- **Third-party Security Support Providers (SSPs) are blocked**: Products that hook into LSASS (some password filters, SSO agents) stop functioning
- **NTLMv1 breaks completely**: If any systems still use NTLMv1, they lose connectivity

**The UEFI lock trap**: If you enable Credential Guard with UEFI lock and something goes wrong, the **only fix is a system wipe**. Never enable UEFI lock until you've validated in production for at least 30 days.

**Deployment approach**:
1. Inventory all systems: exclude domain controllers, Exchange servers, VMware hosts
2. Enable RunAsPPL first (lower risk, easier rollback)
3. Enable Credential Guard WITHOUT UEFI lock on a pilot group
4. Monitor for 30 days
5. Expand gradually
6. Only enable UEFI lock after full validation

---

### 4. SMB Hardening (5 checks)

**Difficulty**: Hard | **Timeline**: 4-9 months | **User Impact**: Medium

**The real challenge isn't Windows -- it's everything else.**

**What goes wrong**:
- **Printers and scanners are the #1 casualty**: Multifunction printers (MFPs) that use "scan to folder" almost universally require SMBv1. Brother, HP, Canon, Ricoh -- most models manufactured before 2018 only support SMBv1. Disabling SMBv1 kills scan-to-folder entirely
- **NAS devices lose connectivity**: Older Synology, QNAP, and NetApp devices may only support SMBv1
- **Performance impact of signing**: SMB signing adds CPU overhead. On high-throughput file servers, this is measurable. With RDMA networks, SMB signing causes fragmentation -- MTU drops from ~8,000 to 1,394 bytes, causing severe performance degradation
- **September 2025 incident**: A Windows update broke SMBv1 over NetBIOS connectivity, causing chaos in enterprises that still had legacy devices

**Before you start**: Run this PowerShell on file servers to identify SMBv1 clients:
```powershell
Get-SmbSession | Where-Object {$_.Dialect -eq '1.1'} | Select-Object ClientComputerName, ClientUserName
```

**The expensive truth**: Replacing legacy printers/scanners/NAS that only support SMBv1 can cost $10,000-$50,000+ depending on fleet size. Budget for this before starting.

**Phased approach**:
1. Enable SMBv1 audit logging (identify who's using it)
2. Replace legacy devices that can't be upgraded
3. Enforce SMB signing (lower risk than disabling SMBv1)
4. Disable SMBv1 last, after all dependencies resolved
5. Enable SMB encryption for sensitive file shares

---

### 5. PowerShell Security (4 checks)

**Difficulty**: Hard | **Timeline**: 3-6 months | **User Impact**: High

**Constrained Language Mode is the most disruptive endpoint control.**

**What goes wrong**:
- **All .NET methods are restricted**: `[System.Convert]::FromBase64String()`, `[System.IO.File]::ReadAllText()`, and similar -- scripts that use .NET classes break
- **`Add-Type` is completely disabled**: Any script that loads C# code inline fails
- **Dot-sourcing from FullLanguage scripts fails**: Module patterns that dot-source helper scripts break
- **PSAppDeployToolkit and similar frameworks break**: Enterprise software deployment tools heavily use .NET methods
- **Log volume explosion**: Script Block Logging generates up to 1 MB per minute of administrative activity -- on a 500-endpoint org, that's 720 GB per day of raw log data

**The practical reality**: Most organizations enable Script Block Logging and Module Logging (valuable for detection) but defer Constrained Language Mode to a later phase because the operational impact is too severe without extensive preparation.

**Recommended approach**:
1. **Phase 1** (Easy, do immediately): Enable Script Block Logging + Module Logging
2. **Phase 2** (Medium): Enable PowerShell Transcription to a central share
3. **Phase 3** (Hard, defer if needed): Plan Constrained Language Mode deployment
   - Inventory ALL scripts in the environment
   - Set up code signing infrastructure
   - Sign all approved scripts
   - Deploy AppLocker or WDAC policies
   - Only then enable CLM

**Log storage planning**: Budget 500 MB - 1 GB per endpoint per day for PowerShell logs. For 500 endpoints: 250-500 GB/day.

---

### 6. Network Protocol Hardening -- LLMNR/NetBIOS/WPAD (4 checks)

**Difficulty**: Medium | **Timeline**: 5-7 weeks | **User Impact**: Low

**What goes wrong**:
- **Network printer/scanner discovery breaks**: Devices found via NetBIOS name resolution disappear from network browsing
- **Miracast wireless display fails**: If mDNS is also disabled, wireless display projection stops working
- **WPAD auto-proxy detection fails**: Browsers configured to "auto-detect proxy" lose their proxy configuration
- **Name resolution slows down**: Systems that fell back to LLMNR for local name resolution now time out before falling back to DNS

**The fix is straightforward**: Ensure your DNS is comprehensive before disabling these protocols. Every device that was previously found via LLMNR/NetBIOS needs a DNS A record.

**Pre-deployment checklist**:
1. Verify all devices have DNS entries (run `nslookup` against every printer, scanner, NAS)
2. Configure DHCP option 252 for WPAD if proxy auto-configuration is needed
3. Deploy mDNS if Miracast/device discovery is required
4. Disable LLMNR first (least disruption), then NetBIOS, then WPAD

---

### 7. Windows Audit Logging (9 checks)

**Difficulty**: Easy | **Timeline**: 6-10 weeks | **User Impact**: None

**This is the easiest high-value control to deploy.**

**What goes wrong** (minor):
- Default Security log is 256 MB -- fills in hours with full auditing. Increase to 2 GB minimum
- SIEM ingestion costs increase -- plan for this in advance
- Network bandwidth for log forwarding if using Windows Event Forwarding (WEF)

**Cost planning**:
- Estimate 50-100 MB/day per endpoint for audit logs
- For 500 endpoints: 25-50 GB/day of log data
- SIEM cost varies: $1-5 per GB ingested (Sentinel, Splunk, Elastic)
- Annual SIEM cost for audit logs alone: $9,000-$90,000

**Deployment**: Configure via GPO, increase log sizes, set up forwarding. Done.

---

### 8. Account Lockout + Password Policy (5 checks)

**Difficulty**: Easy | **Timeline**: 4 weeks | **User Impact**: Medium

**What goes wrong**:
- **The Entra ID false positive incident (2025)**: Microsoft's leaked credential detection system generated 20,000+ false positive lockouts overnight. Unique, secure passwords were flagged as leaked, locking out thousands of users across multiple tenants
- **Service accounts with cached credentials**: After policy change, service accounts using old passwords lock out repeatedly. Inventory ALL service accounts first
- **Help desk ticket surge**: Expect a 40% increase in password-related tickets for the first month

**Modern guidance conflicts with traditional approach**: NIST SP 800-63B now recommends long passphrases WITHOUT mandatory complexity (no special characters required) and WITHOUT periodic expiration. The F0RT1KA baseline check validates password length (>=14) and complexity, but organizations should consider whether the NIST approach (length only, no expiration) better serves them.

---

### 9. LAPS Deployment (2 checks)

**Difficulty**: Easy | **Timeline**: 5-7 weeks | **User Impact**: None

**This is the easiest control to deploy with the best risk/effort ratio.**

**What goes wrong** (all easily fixable):
- GPO configured but "Enable password management" not checked -- policy silently does nothing
- Legacy LAPS and Windows LAPS conflict -- cannot manage the same account with both
- Password shows blank in LAPS UI -- permissions issue on the AD attribute
- AD replication delays cause password retrieval to fail temporarily

**Deployment is straightforward**:
1. Extend AD schema (one-time, requires Schema Admin)
2. Create and link GPO
3. Verify with `Get-LapsADPassword` on a test machine
4. Roll out via GPO

---

### 10. Print Spooler Hardening (2 checks)

**Difficulty**: Easy | **Timeline**: 2 weeks | **User Impact**: Varies

**The nuance**: Disabling Print Spooler entirely is only appropriate for servers that don't need to print (domain controllers, file servers, application servers). Workstations need the spooler to print.

**What to do instead on workstations**: Enable Point and Print restrictions (blocks PrintNightmare CVE-2021-34527) while keeping the spooler running. This gives protection without breaking printing.

---

## Bundle 2: Entra ID Tenant Security (26 checks)

### 1. MFA Enforcement (7 checks)

**Difficulty**: Medium | **Timeline**: 4-8 months | **User Impact**: High

**MFA is the single highest-impact control (99.9% risk reduction) but also the most user-facing change.**

**What goes wrong**:
- **Help desk ticket explosion**: Organizations report 40-60% increase in support tickets during MFA rollout. Users forget phones, get locked out, can't set up authenticator
- **FIDO2 security key costs**: At $25-60 per key and 2 keys per user (primary + backup), a 500-person deployment costs $25,000-$60,000 in hardware alone
- **Windows Hello for Business in hybrid environments**: Requires TPM 2.0, PKI infrastructure, Azure AD Connect synchronization. Older laptops (pre-2018) may not have TPM 2.0
- **Remote worker enrollment**: Users working from home struggle with initial MFA setup -- no in-person IT support available
- **MFA fatigue is real**: Before attackers even try fatigue attacks, users are genuinely fatigued by constant prompts

**Phishing-resistant MFA (FIDO2/WHfB) vs. standard MFA**:

| Factor | Standard MFA (Authenticator) | Phishing-Resistant (FIDO2/WHfB) |
|--------|-----------------------------|---------------------------------|
| Cost per user | $0 (app-based) | $50-120 (hardware keys) |
| Deployment complexity | Low | **High** |
| User training needed | Moderate | **Significant** |
| Protection against phishing | Good (number matching) | **Excellent** |
| Lost device recovery | Easy (re-enroll) | Harder (backup key needed) |

**Recommended phased approach**:
1. **Month 1**: Deploy Microsoft Authenticator with number matching for all users
2. **Month 2-3**: Enforce MFA via Conditional Access for all users
3. **Month 3-4**: Disable weak methods (SMS, voice, email OTP) for admins
4. **Month 4-6**: Deploy FIDO2/WHfB for privileged users first
5. **Month 6+**: Expand phishing-resistant MFA based on risk appetite
6. **Block device code flow** immediately (low-effort, high-value)

---

### 2. Blocking Legacy Authentication (1 check)

**Difficulty**: Medium | **Timeline**: 3-4 months | **User Impact**: Medium

**What goes wrong**:
- **Outlook 2010/2013 stops connecting**: These clients only support basic authentication. Users must upgrade to Outlook 2016+ or use Outlook on the web
- **Third-party email clients break**: Some mobile email apps only support IMAP/POP3 with basic auth
- **Automated scripts fail**: PowerShell scripts that connect to Exchange Online using basic auth (no `-UseModernAuth` flag) stop working
- **ActiveSync devices enter infinite prompt loops**: Old phones must remove and re-add the email account
- **Policy takes up to 24 hours to take full effect**: Confusing during rollout testing

**Pre-deployment**: Check Entra ID Sign-in logs for "Legacy Authentication Clients" -- this shows exactly who will be affected.

---

### 3. Risk-Based Conditional Access (3 checks)

**Difficulty**: Medium | **Timeline**: 8-12 weeks | **User Impact**: Medium | **License**: Entra ID P2 Required

**What goes wrong**:
- **The "combined risk" trap**: If you create a single CA policy requiring BOTH high sign-in risk AND high user risk, it only triggers when both conditions are true simultaneously. This creates a security gap -- a high-risk sign-in from a non-risky user sails through. Always create **separate policies** for sign-in risk and user risk
- **Legitimate travel triggers false positives**: "Impossible travel" risk detection flags users who connected via VPN in one country and then traveled to another
- **Complete tenant lockout**: If admins don't have emergency access accounts excluded from CA policies, a misconfiguration locks EVERYONE out. Recovery requires a Microsoft Support call

**Non-negotiable prerequisite**: Create 2+ emergency access (break-glass) accounts BEFORE configuring ANY Conditional Access policy. These accounts must be cloud-only, excluded from all CA policies, and monitored for usage.

---

### 4. Privileged Identity Management -- PIM (7 checks)

**Difficulty**: Medium | **Timeline**: 6-10 weeks | **User Impact**: Medium | **License**: Entra ID P2 or E5 Required

**What goes wrong**:
- **Activation delays of up to 1 hour**: After clicking "Activate" for a role, the actual permissions can take 15-60 minutes to propagate. Exchange, SharePoint, and Teams roles are the slowest. Admins performing urgent tasks (outage response) are blocked
- **Web caching delays**: Even after activation, browser caching can show "Access Denied" -- users must sign out, close browser, and sign back in
- **Cultural resistance**: Admins accustomed to permanent Global Admin access resist the friction. Executive sponsorship is critical
- **Approval workflows add latency**: If GA activation requires approval, the approver must be available -- a single point of failure for urgent operations

**Practical tip**: Set reasonable activation durations (4-8 hours) and only require approval for the most sensitive roles (Global Admin, Exchange Admin). Lower-risk roles can auto-activate.

---

### 5. Limiting Global Administrators (included in privileged access checks)

**Difficulty**: Easy | **Timeline**: 7-11 weeks | **User Impact**: Low

**What goes wrong**: Mainly organizational, not technical. People who have always had Global Admin resist losing it. The technical migration to fine-grained roles requires mapping each person's actual needs to the correct role.

**Microsoft provides 80+ built-in roles**: Almost every administrative task has a dedicated role that doesn't require Global Admin. Common mappings:

| Current Task | Replace Global Admin With |
|-------------|--------------------------|
| Manage users | User Administrator |
| Manage licenses | License Administrator |
| Reset passwords | Helpdesk Administrator |
| Manage Exchange | Exchange Administrator |
| Manage SharePoint | SharePoint Administrator |
| Manage security | Security Administrator |

---

### 6. Guest Access Restrictions (3 checks)

**Difficulty**: Easy | **Timeline**: 4-5 weeks | **User Impact**: Low

**What goes wrong**:
- Cross-tenant access settings can block B2B invitations entirely -- test with key partners before enforcement
- 15-60 minute delay after changing settings
- You can only have an allow list OR a deny list for guest domains, not both

**Low-risk deployment**: Start with "restricted to own directory objects" for guest access level, then adjust if partners report issues.

---

### 7. Application Consent Restrictions (3 checks)

**Difficulty**: Medium | **Timeline**: 5-7 weeks | **User Impact**: High

**What goes wrong**:
- **Productivity cliff**: If you block all user consent without pre-approving common apps, users can't access tools they rely on daily (Zoom, Slack integrations, CRM plugins). Help desk gets flooded with "I can't use [app]" tickets
- **Approval workflow latency**: Without an admin consent workflow, users submit requests that sit for days

**The right approach**: Before restricting consent, inventory current app consents (Entra ID > Enterprise applications > Consent and permissions) and pre-approve all legitimate apps. Then restrict new consents to verified publishers only.

---

### 8. Centralized Audit Logging (1 check)

**Difficulty**: Easy | **Timeline**: 2-3 weeks | **User Impact**: None

**What goes wrong** (cost-related):
- Free tier: 7 days retention only
- P1/P2: 30 days default, 730 days maximum
- Log Analytics Workspace is expensive for long-term storage
- Azure Storage is cheaper but less queryable

**Cost for 500-person org**:
- Log Analytics Workspace: ~$2-5/GB ingested, estimated $200-500/month
- Azure Storage (archive): ~$0.01/GB/month for long-term compliance retention

---

## Bundle 3: Identity Endpoint Posture (20 checks)

### 1. Azure AD Join / Hybrid Join (5 checks)

**Difficulty**: Medium | **Timeline**: 3-4 months | **User Impact**: Low

**What goes wrong**:
- **Hybrid Join requires line-of-sight to a domain controller** during login. Remote workers on VPN must connect VPN BEFORE signing in, which creates a chicken-and-egg problem
- **Service Connection Point (SCP) misconfiguration** is the #1 troubleshooting issue -- devices can't discover the Azure AD tenant
- **Devices flip between "Hybrid joined" and "Unjoined"** when off corporate network -- a known issue that causes intermittent Conditional Access failures
- **Azure AD Connect sync delays**: OU not selected for sync means devices silently fail to register

**Troubleshooting command**: `dsregcmd /status` -- this single command reveals device join state, PRT status, and troubleshooting hints.

---

### 2. Windows Hello for Business (5 checks)

**Difficulty**: Hard | **Timeline**: 5-7 months | **User Impact**: Medium

**The most infrastructure-intensive identity control.**

**What goes wrong**:
- **TPM 2.0 requirement**: Laptops manufactured before 2016 often lack TPM 2.0. Budget for hardware refresh
- **Hybrid deployment complexity**: Requires coordinated configuration across on-prem AD, Azure AD Connect, Entra ID, and optionally ADFS. Multiple teams must collaborate
- **PIN lockout frustration**: After 5 failed PIN attempts, TPM enforces increasing lockout periods. Users forget PINs and can't access their devices
- **Biometric hardware varies wildly**: Fingerprint readers and IR cameras from different vendors have different compatibility levels with WHfB
- **Key synchronization failures in hybrid**: User keys created on-prem may not sync to Entra ID, causing authentication failures

**Recommended approach**: Start with cloud-only deployment (simpler), expand to hybrid only if required by infrastructure.

---

### 3. Intune/MDM Enrollment (4 checks)

**Difficulty**: Hard | **Timeline**: 4-6 months | **User Impact**: Medium

**What goes wrong**:
- **SCCM to Intune migration is massively underestimated**: Organizations discover hundreds or thousands of undocumented application packages that must be converted from SCCM format to Intune format (.intunewin). Without automation, this takes 4-6 months
- **Duplicate enrollment errors**: Cloned or re-imaged devices contain enrollment artifacts from previous installations, causing "device already enrolled" errors
- **License limit reached**: Default Intune license allows 15 devices per user. Organizations with multiple devices per user hit this limit
- **iOS/Android enrollment requires additional infrastructure**: Apple Push Notification service (APNs) certificate for iOS, Android Enterprise setup for Android

**The realistic timeline**:
- Fresh Intune deployment (no SCCM): 4-8 weeks
- SCCM to Intune migration: 4-6 months (without automation), 2-4 weeks (with automation tools)

---

### 4. Cloud Credential Protection -- PRT (5 checks)

**Difficulty**: Medium | **Timeline**: 7-12 weeks | **User Impact**: Low

**What goes wrong**:
- Token Protection Conditional Access policy may block legitimate applications that don't support device-bound tokens
- Start in Report-Only mode to identify incompatible apps before enforcement

**Practical note**: PRT protection is largely automatic for Azure AD joined devices with TPM 2.0. The main deployment effort is the Token Protection CA policy.

---

### 5. BitLocker Cloud Escrow (3 checks)

**Difficulty**: Medium | **Timeline**: 6-10 weeks | **User Impact**: Low

**What goes wrong**:
- **The 200-key limit**: Each device in Entra ID has a 200 recovery key limit. Organizations that frequently rotate BitLocker keys hit this ceiling, causing silent encryption failures. Microsoft fixed this with automatic key cleanup, but older environments may still encounter it
- **Recovery key not found**: Users trigger BitLocker recovery (firmware update, TPM reset) but the recovery key wasn't escrowed to Entra ID. This is a data-loss scenario if no backup exists
- **Silent encryption fails without error**: If key escrow is required by policy but escrow fails, encryption doesn't start -- and no one notices until an audit

**Critical test**: After deploying BitLocker via Intune/GPO, verify recovery keys actually appear in Entra ID (Azure portal > Devices > [device] > BitLocker keys). Don't assume escrow works -- verify it.

---

## Recommended Deployment Sequence

Based on dependencies, risk, and value, deploy controls in this order:

### Phase 1: Foundation (Weeks 1-4) -- Quick Wins

| Control | Why First | Effort |
|---------|----------|--------|
| Emergency access accounts (2+) | Prerequisite for everything | 1 day |
| Windows Audit Logging | Zero user impact, immediate visibility | 1-2 weeks |
| LAPS deployment | Zero user impact, closes a major gap | 3-5 weeks |
| Centralized Entra ID logging | Zero user impact, enables monitoring | 1-2 weeks |
| Guest access restrictions | Low user impact, quick to implement | 1-2 weeks |

**Risk**: Minimal. These controls have no user-facing impact and provide immediate security value.

### Phase 2: Endpoint Hardening (Weeks 4-16)

| Control | Why Now | Effort |
|---------|--------|--------|
| Defender + Tamper Protection | Foundation for ASR rules | 1-2 weeks |
| ASR Rules (Audit mode) | Start the 30-45 day audit clock | 30-45 days audit |
| LLMNR/NetBIOS/WPAD disable | Low risk after DNS validation | 3-5 weeks |
| Print Spooler hardening | Quick win for servers | 1-2 weeks |
| PowerShell logging (NOT CLM yet) | Detection without disruption | 1-2 weeks |
| Account lockout + password policy | Standard hardening | 2-4 weeks |

**Risk**: Moderate. ASR rules in Audit mode are safe. LLMNR disable requires DNS validation.

### Phase 3: Identity Foundation (Weeks 16-28)

| Control | Why Now | Effort |
|---------|--------|--------|
| MFA with Authenticator (all users) | Highest risk reduction | 4-8 weeks |
| Block legacy authentication | Depends on MFA being deployed | 2-4 weeks |
| Azure AD Join / Hybrid Join | Foundation for device identity | 8-12 weeks |
| Intune/MDM enrollment | Depends on device join | 8-12 weeks |
| BitLocker with cloud escrow | Depends on device join | 4-6 weeks |
| Limit Global Administrators | Organizational change | 4-8 weeks |

**Risk**: High user impact from MFA rollout. Requires extensive communication and support planning.

### Phase 4: Advanced Security (Weeks 28-40)

| Control | Why Last | Effort |
|---------|---------|--------|
| ASR Rules (enforce) | Had months to tune in Audit mode | 2-4 weeks |
| LSASS Protection | Requires app compat validation | 4-8 weeks |
| SMB Hardening (full) | Hardware replacement may be needed | 8-16 weeks |
| Risk-based Conditional Access | Requires P2 licensing | 6-8 weeks |
| PIM / JIT Access | Requires P2 licensing | 4-6 weeks |
| Application consent restrictions | Requires app inventory | 4-6 weeks |
| Windows Hello for Business | Infrastructure-heavy | 12-20 weeks |

**Risk**: This phase has the hardest controls. Take time, pilot extensively.

### Phase 5: Lockdown (Weeks 40+)

| Control | Why Last | Effort |
|---------|---------|--------|
| PowerShell Constrained Language Mode | Requires script signing infra | Ongoing |
| Phishing-resistant MFA (FIDO2) | Hardware procurement + training | 8-16 weeks |
| Token Protection | Requires app compatibility testing | 4-8 weeks |
| Credential Guard (UEFI lock) | Only after months of validation | 2-4 weeks |

**Risk**: Highest disruption potential. Only deploy after all previous phases are stable.

---

## Common Failure Patterns

### 1. The "Big Bang" Deployment
**What happens**: Organization enables all controls simultaneously. Multiple things break, help desk drowns, and management orders everything rolled back.
**Prevention**: Follow the phased approach above. Each phase has 4-12 weeks to stabilize before the next begins.

### 2. The "Audit Mode Forever" Trap
**What happens**: ASR rules stay in Audit mode for years because no one owns the task of reviewing logs and moving to enforcement.
**Prevention**: Assign an owner with a deadline. Set calendar reminders for the 30/60/90 day review milestones.

### 3. The "No Emergency Access" Lockout
**What happens**: Admin configures Conditional Access, accidentally locks out all admin accounts. Tenant recovery requires Microsoft Support (days).
**Prevention**: Create 2+ break-glass accounts BEFORE touching Conditional Access. Test them monthly.

### 4. The "Legacy Device Discovery"
**What happens**: SMBv1 is disabled; 47 multifunction printers, 12 NAS devices, and 3 legacy apps stop working. No one knew they depended on SMBv1.
**Prevention**: Run SMB audit logging for 30 days before making changes. Budget for hardware replacement.

### 5. The "License Surprise"
**What happens**: Team plans to deploy PIM and risk-based CA, only to discover both require Entra ID P2 -- an unbudgeted $54,000/year for 500 users.
**Prevention**: Map every control to its licensing requirement BEFORE creating the project plan.

---

## Skills and Team Requirements

### Minimum Team Composition

| Role | Controls They Own | FTE Allocation |
|------|------------------|----------------|
| **Windows Admin** | Endpoint hardening (Bundle 1) | 0.5 FTE for 6 months |
| **Identity/Cloud Admin** | Entra ID (Bundle 2) + Device identity (Bundle 3) | 0.5 FTE for 8 months |
| **Help Desk** | User support during MFA/password rollout | +1 FTE temp for 3 months |
| **Security Analyst** | Log analysis, ASR tuning, false positive triage | 0.25 FTE ongoing |
| **Project Manager** | Coordination, communication, stakeholder management | 0.25 FTE for 10 months |

### Skills Gap Assessment

| Skill | Where Needed | Learning Curve |
|-------|-------------|---------------|
| Intune/Endpoint Manager | Device enrollment, compliance policies | 2-4 weeks |
| Conditional Access design | All CA-based controls | 1-2 weeks |
| PowerShell security | CLM, logging, script signing | 2-3 weeks |
| PKI / Certificate management | WHfB, code signing | 4-6 weeks |
| SIEM administration | Log ingestion, alert tuning | 4-8 weeks |

---

## Total Cost of Implementation

### For a 500-Person Organization (M365 E3 baseline)

| Category | One-Time Cost | Annual Recurring |
|----------|-------------|-----------------|
| Entra ID P2 licenses (all users) | -- | $54,000 |
| FIDO2 security keys (admins only, 50 users) | $5,000 | $1,000 (replacements) |
| Legacy hardware replacement (printers, NAS) | $15,000-$50,000 | -- |
| SIEM/Log Analytics costs | $5,000 (setup) | $12,000-$60,000 |
| Staff time (1.5 FTE for 10 months) | $125,000-$200,000 | -- |
| Help desk temp (3 months) | $15,000-$25,000 | -- |
| Training and certification | $5,000-$10,000 | -- |
| **Total** | **$170,000-$340,000** | **$67,000-$115,000** |

### ROI Comparison

The [Risk Reduction Analysis](RISK_REDUCTION_ANALYSIS.md) shows a single data breach costs $4.44M on average (IBM 2025). Full implementation of all three bundles provides 93-96% risk reduction.

| Investment | Annual Cost | Risk Reduced | Cost Per % Reduction |
|-----------|------------|-------------|---------------------|
| Year 1 (implementation) | $237,000-$455,000 | 93-96% | $2,500-$4,900 |
| Year 2+ (maintenance) | $67,000-$115,000 | 93-96% (maintained) | $700-$1,200 |
| Avoided breach (expected) | -- | -- | **$4.22M saved** |

**Payback period**: A single avoided breach pays for 4-6 years of implementation and maintenance costs.

---

## References

- Microsoft. "Attack Surface Reduction rules deployment." https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test
- Microsoft. "Credential Guard known issues." https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues
- Microsoft. "Troubleshoot Hybrid Azure AD Join." https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-hybrid-join-windows-current
- Microsoft. "Block legacy authentication." https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication
- Microsoft. "Windows LAPS troubleshooting." https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/windows-laps-troubleshooting-guidance
- Microsoft. "PIM activation delays." https://learn.microsoft.com/en-us/entra/id-protection/pim-configure
- Palantir. "ASR Rules recommendations." https://blog.palantir.com/microsoft-defender-attack-surface-reduction-recommendations-a5c7d41c3cf8
- The Register. "Microsoft Defender ASR incident (Jan 2023)." https://www.theregister.com/2023/01/13/happy_friday_13th_microsoft_defender/
- BleepingComputer. "Entra ID mass lockout incident." https://www.bleepingcomputer.com/news/microsoft/widespread-microsoft-entra-lockouts-tied-to-new-security-feature-rollout/
- Jan Bakker. "Conditional Access risk policy pitfall." https://janbakker.tech/conditional-access-risk-policies-dont-get-fooled/
- NIST SP 800-63B. "Digital Identity Guidelines." https://pages.nist.gov/800-63-3/sp800-63b.html
- Corbado. "Enterprise passkey deployment challenges." https://www.corbado.com/blog/enterprise-passkey-deployment-challenges
- Patch My PC. "BitLocker recovery key 200-key limit." https://patchmypc.com/blog/bitlocker-recovery-key-cleanup/
- 4sysops. "Windows September 2025 SMBv1 breakage." https://4sysops.com/archives/windows-september-updates-break-smbv1-shares-workarounds-and-user-feedback/

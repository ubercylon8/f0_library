# References & Sources

## Primary Source

The original threat intelligence that initiated this test's development.

| Field | Value |
|-------|-------|
| **Title** | Fake CAPTCHA led to Lumma (EdgeUpdate→Chrome remote-thread injection) |
| **Author/Organization** | NCC Group |
| **Date Published** | 2026 (exact date not listed on publication) |
| **Document Type** | threat-report |
| **URL** | https://www.nccgroup.com/research/fake-captcha-led-to-lumma/ |

Primary anchors drawn from this source: the ClickFix (fake CAPTCHA) delivery pattern, the
`MicrosoftEdgeUpdate.exe` → `chrome.exe` remote-thread injection pattern, and the
browser-credential collection objective that defines the kill chain emulated by this test.

## Supporting Resources

Additional threat intelligence, incident reports, and TTP analyses referenced during test development.

| # | Title | Type | URL |
|---|-------|------|-----|
| 1 | Lumma Stealer: Breaking down delivery techniques and capabilities (Microsoft Security Blog, 2025-05-21) | threat-report | https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer |
| 2 | ESET takes part in global operation to disrupt Lumma Stealer (C2 protocol: `act=live`, LID/`J`, hardcoded UA; 2025-05) | threat-report | https://www.welivesecurity.com/en/eset-research/eset-takes-part-global-operation-disrupt-lumma-stealer |
| 3 | Remus 64-bit Lumma variant (Gen Digital; fingerprint probe before upload) | blog-post | https://www.gendigital.com/blog/insights/research/remus-64bit-variant-of-lumma-stealer |
| 4 | Lumma: Fake CAPTCHAs & new techniques to evade detection (Netskope Threat Labs, 2025-01) | blog-post | https://www.netskope.com/blog/lumma-stealer-fake-captchas-new-techniques-to-evade-detection |
| 5 | Fake CAPTCHA Delivers Lumma Stealer (mshta→VBScript→PowerShell IWR chain; Seqrite, 2025) | blog-post | https://www.seqrite.com/blog/fake-captcha-lures-victims-lumma-stealer-abuses-clipboard-and-powershell |
| 6 | The Rise of MaaS & Lumma Info Stealer (TeslaBrowser/5.5 UA, /c2sock URI; Darktrace, 2023) | blog-post | https://www.darktrace.com/blog/the-rise-of-the-lumma-info-stealer |
| 7 | ClickFix via Windows Terminal deploys Lumma (The Hacker News, 2026-03) | news-article | https://thehackernews.com/2026/03/microsoft-reveals-clickfix-campaign.html |
| 8 | Picus Red Report 2025 (T1055 #1 technique; T1555 new at #3 — 3x rise in credential theft) | research-paper | https://www.picussecurity.com/resource/blog/red-report-2025-3x-rise-in-credential-theft |
| 9 | Chrome-App-Bound-Encryption-Decryption (IElevator COM interfaces, elevator CLSIDs/IIDs, vtable layout; xaitax, 2024–2025) | tool-release | https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption |
| 10 | Lumma Stealer — MITRE ATT&CK Software S1213 | tool-release | https://attack.mitre.org/software/S1213 |

## MITRE ATT&CK References

| Technique | Name | URL |
|-----------|------|-----|
| T1204.002 | User Execution: Malicious File | https://attack.mitre.org/techniques/T1204/002/ |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1055.003 | Process Injection: Thread Execution Hijacking | https://attack.mitre.org/techniques/T1055/003/ |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | https://attack.mitre.org/techniques/T1555/003/ |
| T1555 | Credentials from Password Stores | https://attack.mitre.org/techniques/T1555/ |
| T1005 | Data from Local System | https://attack.mitre.org/techniques/T1005/ |
| T1041 | Exfiltration Over C2 Channel | https://attack.mitre.org/techniques/T1041/ |
| T1071.001 | Application Layer Protocol: Web Protocols | https://attack.mitre.org/techniques/T1071/001/ |

## Related Advisories & News

- [ESET takes part in global operation to disrupt Lumma Stealer](https://www.welivesecurity.com/en/eset-research/eset-takes-part-global-operation-disrupt-lumma-stealer) — May 2025 law-enforcement disruption of LummaC2 infrastructure; source of the C2 protocol details (`act=live`, LID, `J`, hardcoded User-Agent) emulated by stage 4.
- [Microsoft: Lumma Stealer — delivery techniques and capabilities](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer) — 2025-05-21; Microsoft tracks the operator as Storm-2477 / Water Kurita; ClickFix campaign context.
- [The Hacker News: Microsoft reveals ClickFix campaign](https://thehackernews.com/2026/03/microsoft-reveals-clickfix-campaign.html) — 2026-03 coverage of the Windows Terminal ClickFix variant.
- [Picus Red Report 2025](https://www.picussecurity.com/resource/blog/red-report-2025-3x-rise-in-credential-theft) — industry prevalence evidence: process injection the #1 observed technique, credential-dumping attacks up ~3x, motivating T1055.003/T1555 coverage validation.

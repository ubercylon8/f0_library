# References & Sources

## Primary Source

The original threat intelligence that initiated this test's development.

| Field | Value |
|-------|-------|
| **Title** | 3CX Software Supply Chain Compromise Initiated by a Prior Software Supply Chain Compromise |
| **Author/Organization** | Mandiant (Google Cloud) |
| **Date Published** | 2023-04-20 |
| **Document Type** | threat-report |
| **URL** | https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise |

## Supporting Resources

Additional threat intelligence, incident reports, and TTP analyses referenced during test development.

| # | Title | Type | URL |
|---|-------|------|-----|
| 1 | CrowdStrike Detects and Prevents Active Intrusion Campaign Targeting 3CXDesktopApp Customers (SmoothOperator) | threat-report | https://www.crowdstrike.com/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/ |
| 2 | 3CX Security Advisory — DesktopApp Security Alert | security-advisory | https://www.3cx.com/blog/news/desktopapp-security-alert/ |
| 3 | MITRE ATT&CK — G0032 Lazarus Group | reference | https://attack.mitre.org/groups/G0032/ |
| 4 | 3CX Supply Chain Compromise Leads to ICONIC Incident (icon steganography detail) | threat-report | https://www.volexity.com/blog/2023/03/30/3cx-supply-chain-compromise-leads-to-iconic-incident/ |

## MITRE ATT&CK References

| Technique | Name | URL |
|-----------|------|-----|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | https://attack.mitre.org/techniques/T1195/002/ |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | https://attack.mitre.org/techniques/T1574/002/ |
| T1497 | Virtualization/Sandbox Evasion | https://attack.mitre.org/techniques/T1497/ |
| T1027.003 | Obfuscated Files or Information: Steganography | https://attack.mitre.org/techniques/T1027/003/ |
| T1071.001 | Application Layer Protocol: Web Protocols | https://attack.mitre.org/techniques/T1071/001/ |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | https://attack.mitre.org/techniques/T1555/003/ |
| T1217 | Browser Information Discovery | https://attack.mitre.org/techniques/T1217/ |

## Related Advisories & News

- [3CX Security Advisory — DesktopApp Security Alert](https://www.3cx.com/blog/news/desktopapp-security-alert/) — 3CX's own incident disclosure and remediation guidance for the trojanized DesktopApp installers (2023-03-29)
- [CrowdStrike — CrowdStrike Detects and Prevents Active Intrusion Campaign Targeting 3CXDesktopApp Customers](https://www.crowdstrike.com/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/) — First public detection report naming the "SmoothOperator" campaign, attributing it to a suspected North Korea-nexus actor (2023-03-29)
- [Volexity — 3CX Supply Chain Compromise Leads to ICONIC Incident](https://www.volexity.com/blog/2023/03/30/3cx-supply-chain-compromise-leads-to-iconic-incident/) — Deep-dive on the ICO-based steganographic C2 configuration technique and the ICONIC/downstream stealer payload this test's Stage 3 and Stage 4 are modeled on (2023-03-30)

# References & Sources

## Primary Source

The original incident research that initiated this test's development and supplied the affected certificate chains and validation model.

| Field | Value |
|-------|-------|
| **Title** | eMudhra Intermediate CA Compromise |
| **Author/Organization** | Dennis Jackson and contributors |
| **Date Published** | 2026-10-20 |
| **Document Type** | incident-report |
| **URL** | https://emudhra.we-have-a-problem.com/ |

## Supporting Resources

Additional incident analysis, vendor response, and technical research referenced during test development.

| # | Title | Type | URL |
|---|-------|------|-----|
| 1 | 8 eMudhra certificates are compromised. Here's what you need to know | blog-post | https://blog.cloudflare.com/emudhra-certificate-compromise |
| 2 | Microsoft's response to compromised eMudhra certificate authority keys | security-advisory | https://www.microsoft.com/en-us/msrc/blog/2026/10/microsoft-response-to-compromised-emudhra-certificate-authority-keys |
| 3 | Compromised eMudhra intermediate certificates | threat-report | https://blog.talosintelligence.com/compromised-intermediate-certificates/ |
| 4 | The private key is 4 | research-paper | https://d4.key64.com/ |
| 5 | eMudhra Statement on Recent Certificate Security Incident | security-advisory | https://emudhra.com/en/post/certificate-security-incident |

## MITRE ATT&CK References

| Technique | Name | URL |
|-----------|------|-----|
| T1557 | Adversary-in-the-Middle | https://attack.mitre.org/techniques/T1557/ |
| T1553.002 | Subvert Trust Controls: Code Signing | https://attack.mitre.org/techniques/T1553/002/ |

The T1557 mapping concerns the exposure demonstrated by acceptance of attacker-signable TLS chains; the test does not perform network interception. The T1553.002 mapping concerns Authenticode trust validation through both direct eMudhra and Sectigo AAA chains; the four harmless signed PEs are not executed.

## Related Advisories & News

- [Cloudflare — 8 eMudhra certificates are compromised](https://blog.cloudflare.com/emudhra-certificate-compromise) — Incident impact and defender guidance for the eight compromised intermediates.
- [Microsoft MSRC — Response to compromised eMudhra certificate authority keys](https://www.microsoft.com/en-us/msrc/blog/2026/10/microsoft-response-to-compromised-emudhra-certificate-authority-keys) — Microsoft trust and mitigation response relevant to Schannel and Authenticode assessment.
- [Cisco Talos — Compromised eMudhra intermediate certificates](https://blog.talosintelligence.com/compromised-intermediate-certificates/) — Independent threat analysis and affected-certificate context.
- [eMudhra — Certificate Security Incident Statement](https://emudhra.com/en/post/certificate-security-incident) — CA operator's incident statement and remediation position.

## Local Verification Evidence

The final local Linux run used execution ID `5d02ca07-4e90-404c-a592-9688d5173ccb` on 2026-11-14. It completed in 5,202 ms with phase status `success`, reached all nine discovered controls, and returned overall 101 after certifi accepted six direct chains and pip-vendored certifi accepted all 12 generated chains. Its Schema v2.0 execution log and per-control bundle were recorded as `/tmp/F0/test_execution_log.json` and `/tmp/F0/bundle_results.json` on the assessment host. MCP Schema v2.0 validation returned `ok=true` with zero schema/check errors.

The Windows `win` run used execution ID `6a458166-7460-45e9-9893-9dbd3bf9277d`, completed in 14,399 ms, rejected every chain on all five available paths, and returned 126. The Debian `debian` run used execution ID `4dda286f-132b-4474-8723-2fc8e84946ab`, completed in 9,999 ms, accepted compromised chains on all six available paths, and returned 101. Both execution logs passed Schema v2.0 validation with zero schema/check errors.

These artifacts are execution evidence, not published threat-intelligence sources. Final local and lab evidence is retained under `staging/262c6802-467c-42ed-ac3d-94e49f7d6ea4/` in the development worktree; lab results describe those hosts only, not the customer fleet.

## Detection Artifact Validation

The test bundles KQL, Elastic NDJSON, Sigma, LimaCharlie D&R YAML, and YARA detection artifacts. Independent validation parsed five Elastic rules, four Sigma documents, and the LimaCharlie YAML, and compiled the YARA rules with yara-python. YARA matching covered all incident/source/generated chains and all four decompressed Authenticode samples. Artifact validity and sample matches do not constitute live SIEM tenant firing evidence.

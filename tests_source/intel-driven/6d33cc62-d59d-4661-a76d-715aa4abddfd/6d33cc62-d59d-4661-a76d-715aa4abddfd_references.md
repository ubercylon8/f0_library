# References & Sources

## Primary Source

The original threat intelligence that initiated this test's development.

| Field | Value |
|-------|-------|
| **Title** | PII Exfiltration to External Inference Services (approved design spec) |
| **Author/Organization** | sectest-builder (brainstormed with user) |
| **Date Published** | 2026-07-07 |
| **Document Type** | research-paper (internal design) |
| **URL** | Not available — internal design doc at `docs/superpowers/specs/2026-07-07-pii-exfil-inference-services-design.md` |

## Supporting Resources

Additional threat intelligence, incident reports, and TTP analyses referenced during test development.

| # | Title | Type | URL |
|---|-------|------|-----|
| 1 | OWASP Top 10 for LLM Applications — LLM06 Sensitive Information Disclosure | research-paper | https://genai.owasp.org/ |
| 2 | MITRE ATT&CK T1567 Exfiltration Over Web Service | threat-report | https://attack.mitre.org/techniques/T1567/ |
| 3 | MITRE ATT&CK T1552.001 Unsecured Credentials: Credentials In Files | threat-report | https://attack.mitre.org/techniques/T1552/001/ |
| 4 | MITRE ATT&CK T1005 Data from Local System | threat-report | https://attack.mitre.org/techniques/T1005/ |
| 5 | MITRE ATT&CK T1119 Automated Collection | threat-report | https://attack.mitre.org/techniques/T1119/ |
| 6 | Cyberhaven — sensitive corporate data pasted into ChatGPT (shadow-AI egress research) | research-paper | https://www.cyberhaven.com/blog/4-2-of-workers-have-pasted-company-data-into-chatgpt |

## MITRE ATT&CK References

| Technique | Name | URL |
|-----------|------|-----|
| T1552.001 | Unsecured Credentials: Credentials In Files | https://attack.mitre.org/techniques/T1552/001/ |
| T1119 | Automated Collection | https://attack.mitre.org/techniques/T1119/ |
| T1005 | Data from Local System | https://attack.mitre.org/techniques/T1005/ |
| T1567 | Exfiltration Over Web Service | https://attack.mitre.org/techniques/T1567/ |

## Related Advisories & News

- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/) — LLM06 (Sensitive Information Disclosure) is the industry-standard framing for the shadow-AI data-loss failure mode this test validates; used to shape the Stage 1/Stage 2 design (credential discovery + PII collection) as precursors to the Stage 3 egress attempt.
- [Cyberhaven: "4.2% of workers have pasted company data into ChatGPT"](https://www.cyberhaven.com/blog/4-2-of-workers-have-pasted-company-data-into-chatgpt) — empirical grounding for the test's threat model: this is a high-volume, low-sophistication, insider-driven data-loss pattern rather than a targeted intrusion, which is why `THREAT_ACTOR` is `N/A` and the test targets DLP/CASB/egress-proxy coverage rather than EDR payload-blocking.

## Vendor API Documentation (identifier fidelity provenance)

The vendor hostnames, API paths, and request-body shapes exercised in Stage 3 are drawn from each provider's public API reference, cited here for identifier-fidelity traceability:

- OpenAI Chat Completions API — `https://api.openai.com/v1/chat/completions` — https://platform.openai.com/docs/api-reference/chat
- Anthropic Messages API — `https://api.anthropic.com/v1/messages` — https://docs.anthropic.com/en/api/messages
- Google Gemini generateContent API — `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent` — https://ai.google.dev/api/generate-content
- GitHub Copilot Chat Completions API — `https://api.githubcopilot.com/chat/completions` — https://docs.github.com/en/copilot

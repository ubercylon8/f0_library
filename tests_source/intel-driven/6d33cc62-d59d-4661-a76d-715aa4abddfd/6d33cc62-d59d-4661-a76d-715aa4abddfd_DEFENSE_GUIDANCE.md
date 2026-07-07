# Defense Guidance — PII Exfiltration to External Inference Services

**Test ID:** `6d33cc62-d59d-4661-a76d-715aa4abddfd`
**MITRE ATT&CK:** T1552.001 (Credentials In Files), T1119 (Automated Collection), T1005 (Data from Local System), T1567 (Exfiltration Over Web Service)
**Tactics:** credential-access, collection, exfiltration
**Platforms:** Windows, Linux
**Severity:** High
**Author:** F0RT1KA Defense Guidance Builder
**Date:** 2026-07-07

---

## 1. What this validates

This is a **data-governance / "shadow AI"** test, not an EDR payload-stopping test.
The "adversary" is typically a well-meaning insider or an app integration that
sends sensitive records to external LLM inference services (OpenAI, Anthropic,
Gemini, GitHub Copilot). The test checks whether the organization's
**DLP / CASB / egress-proxy / DNS** controls detect or block PII heading to real
AI vendor hosts — not whether an antivirus can quarantine a binary.

Because of that, effective defense lives in the **network egress and content
inspection layer**, and endpoint AV blocking is largely irrelevant to the honest
outcome. A well-defended org should produce a **BLOCK (exit 126)** because a
forward proxy/DLP intercepts the egress — *before* the bytes reach the vendor.

### Honest-outcome note (classification integrity)

The test keys its verdict on **who answered**, not on the HTTP status code:

- A vendor `401`/`403` at the vendor's auth layer means the request body already
  **crossed the boundary** → that is a **LEAK (101)**, not a block.
- A **BLOCK (126)** is only claimed on positive evidence that *your* control
  intervened: DNS resolving the vendor host to a sinkhole/RFC1918/loopback, a
  TLS-inspection certificate failure, or a proxy connection refused/reset.

Your defenses should therefore aim to produce one of those positive block signals
*at the egress layer*, since blocking at the endpoint after the request is built
is too late.

---

## 2. Kill chain and detection opportunities

| Stage | Technique | Behavior | Best detection/control layer |
|-------|-----------|----------|------------------------------|
| 1 | T1552.001 / T1119 | Stage a helper tool; scan env + config files for AI API keys | Endpoint file-access telemetry; secret-store access monitoring |
| 2 | T1005 | Collect sensitive records into an egress payload | DLP endpoint content inspection; sensitive-file access auditing |
| 3 | T1567 | Unauthenticated HTTPS POST of PII to AI vendor hosts | **Forward proxy / CASB / DLP + DNS control** (primary) |

The detection rules shipped alongside this guide target these behaviors generically:
- `*_detections.kql` — Microsoft Sentinel/Defender (network egress, key harvesting, PII-in-body)
- `*_sigma_rules.yml` — vendor-agnostic
- `*_elastic_rules.ndjson` — Elastic EQL
- `*_rules.yar` — YARA (helper tool + PII-bearing payloads)
- `*_dr_rules.yaml` — LimaCharlie D&R

---

## 3. Primary controls (in priority order)

### 3.1 Egress control for AI-vendor destinations (highest leverage)
- Route all outbound web traffic through a **forward proxy / secure web gateway /
  CASB**. Place AI inference domains in a **governed category**:
  - `api.openai.com`, `chatgpt.com`, `openai.com`
  - `api.anthropic.com`, `claude.ai`
  - `generativelanguage.googleapis.com`, `gemini.google.com`
  - `api.githubcopilot.com`, `copilot.microsoft.com`
- Default posture: **allow only sanctioned AI services via approved apps**, and
  **inspect + DLP-scan** request bodies for the rest. Block direct API egress
  (non-browser, non-sanctioned processes) outright — that yields a clean
  proxy-refused BLOCK signal.

### 3.2 DLP content inspection of AI-bound requests
- Enable **TLS inspection** on the proxy for AI-vendor categories so request
  bodies are visible to DLP.
- Author DLP policies matching PII in outbound AI requests: **SSN**, **PAN /
  credit-card (Luhn)**, **bulk email/PII volume**, source-code, secrets.
- Action: **block + alert** on PII in an AI-bound body. This is the control that
  turns a real leak into a controlled block.

### 3.3 DNS control
- Use a protective DNS resolver with an **AI-services policy**. For disallowed
  destinations, resolve to a **sinkhole** — this produces the DNS-sinkhole BLOCK
  signal and prevents the connection entirely.

### 3.4 AI-service API-key hygiene (limits Stage 1)
- Do not store provider keys in world-readable `.env`, shell history, or plaintext
  config. Use a secrets manager; scope and rotate keys.
- Monitor reads of credential stores (see `*_detections.kql` Query 2).

### 3.5 Sanctioned AI usage
- Provide an **approved enterprise AI gateway** with logging + DLP so employees
  have a compliant path; this reduces shadow-AI pressure while giving visibility.

---

## 4. Hardening scripts

- `6d33cc62-d59d-4661-a76d-715aa4abddfd_hardening.ps1` — Windows: audits proxy/DNS
  configuration, host-firewall egress rules to AI vendors, and key-store exposure.
- `6d33cc62-d59d-4661-a76d-715aa4abddfd_hardening_linux.sh` — Linux: same posture
  checks plus egress firewall guidance.

Both are **audit-first** (report posture; apply optional local egress blocks with
`-Apply` / `--apply`). They intentionally do not replace network-layer controls —
host firewalls are a compensating control, not the primary one.

---

## 5. Incident response playbook

**Trigger:** alert on AI-vendor egress from an unsanctioned process, or DLP hit on
PII in an AI-bound request.

1. **Scope** — Identify user, host, process, destination vendor, and timestamp.
   Pull the proxy/DLP record for the **request body** to determine what data left.
2. **Classify data** — Determine PII/PHI/PCI/secret categories and record count.
   Note: a vendor 4xx does **not** mean the data was not received — assume the
   body reached the vendor if any vendor response was returned.
3. **Contain** — Block the destination category at the proxy/DNS for the user/host;
   revoke any AI-service API keys found on the host; rotate exposed secrets.
4. **Eradicate** — Remove the shadow-AI helper tool; remediate key storage hygiene.
5. **Notify** — Engage privacy/legal for regulated-data exposure; the data now
   resides in a third-party vendor's request logs.
6. **Recover / Harden** — Onboard the user to the sanctioned AI gateway; add the
   process to the deny path; verify DLP policy now blocks the pattern (re-run this
   test and confirm a **126** outcome).

---

## 6. Validation

Re-run the F0RT1KA test after applying controls. Expected results:
- **126 (Protected)** — proxy/DNS/DLP intercepted the egress (positive block).
- **101 (Unprotected)** — PII reached a vendor; an AI-egress DLP gap remains.
- **999 (Inconclusive)** — prerequisites not met or an ambiguous result (never
  interpret as protection).

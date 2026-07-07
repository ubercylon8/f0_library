# PII Exfiltration to External Inference Services

## Test Information

**Test ID**: 6d33cc62-d59d-4661-a76d-715aa4abddfd
**Test Name**: PII Exfiltration to External Inference Services
**Category**: Intel-Driven / Data Exfiltration (shadow-AI)
**Severity**: High
**MITRE ATT&CK**: T1552.001, T1119, T1005, T1567
**Platforms**: Windows, Linux
**Architecture**: Multi-stage (orchestrator + 3 gzip-embedded, individually signed stage binaries)
**Threat Actor**: N/A — shadow-AI / well-meaning-insider or unsanctioned app-integration data-governance failure, not a named intrusion set
**Rubric version**: v2.1 (tiered, realism-first; signal-quality-not-tenant-defense)

## Description

This test simulates the most common real-world "shadow AI" data-loss scenario: an employee or an unreviewed application integration pastes or POSTs sensitive customer data to a public LLM inference API. Unlike most F0RT1KA tests, the adversary here is not malware and the objective is not to see whether an EDR blocks process/API primitives — it is to validate whether an organization's **DLP, CASB, or egress/forward-proxy** controls detect or block PII in flight to AI-vendor hosts. The test drops a benign shadow-AI helper artifact, discovers AI-service API keys via read-only enumeration (values never logged), generates synthetic canary PII records, and attempts real, unauthenticated HTTPS delivery of that PII to four real AI vendor hosts (OpenAI, Anthropic, Gemini, GitHub Copilot). All PII is synthetic and safety-invariant by construction (see `canary.go`): SSNs use the SSA advertising-reserved 987-65-432X range (never issued to a real person), PANs use the 4242 test BIN with a correctly-computed Luhn digit (a standard payment-processor test range), and emails use the RFC 2606 `.invalid` TLD. Every record carries a run-unique traceability marker.

## Test Score: 7.8/10

### Score Breakdown (Rubric v2.1)

| Tier | Sub-dimension | Score | Justification |
|---|---|---|---|
| **1** | Safety Gate | **PASS (documented exception)** | All writes confined to `ARTIFACT_DIR`/`LOG_DIR`; both stage 1 and stage 2 clean up their canary artifacts via `defer` and use positive `os.Stat`-based quarantine evidence only (never a default-to-block). No credential values are ever logged or transmitted (redacted counts only). No COM, service, driver, or token/privilege manipulation. **Exception**: Stage 3 performs real network egress beyond loopback — a deliberate, documented departure from the generic "no egress beyond 127.0.0.1" gate, because this test's entire purpose (validating DLP/CASB/egress-proxy coverage of AI-vendor traffic) is unobservable without real external requests to real vendor hosts. Safety is preserved by construction, not by staying on loopback: no `Authorization`/API-key header is ever sent (the vendor cannot process the "request" as real customer traffic), all PII is synthetic-but-format-valid and traceable via a run-unique marker, and the classifier never defaults ambiguous outcomes to a block. This exception mirrors the gate's own built-in precedent for "privilege-enable attempts the OS is expected to deny are allowed as telemetry" — a documented, narrow, safety-preserving carve-out for a test category (data-governance/egress-DLP validation) the generic gate wasn't written to anticipate. See "Safety Design Note" below. |
| **2a** | API Fidelity (0–2.5) | **1.8** | Stage 3 issues vendor-correct HTTPS POSTs: exact production API paths (`/v1/chat/completions`, `/v1/messages`, `:generateContent`, `/chat/completions`), correct `Content-Type`, and vendor-accurate JSON body shapes (`gpt-4o` / `claude-3-5-sonnet-20241022` / `gemini-pro` / `gpt-4` model fields, correct `messages`/`contents.parts` nesting) — matching how a real integration or a copy-pasted `curl`/SDK call would shape the request. Stage 1's credential discovery mirrors real shadow-AI harvester tradecraft: env-var iteration plus reads of the actual per-platform config/credential files real AI CLIs and IDE plugins use. Deviations, both deliberate for safety: no `Authorization` header is ever set, and the `User-Agent` is a generic `ai-assistant-helper/1.0` rather than mimicking a specific real client. |
| **2b** | Identifier Fidelity (0–1.5) | **1.4** | All four vendor hostnames and API paths are real production identifiers (`api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `api.githubcopilot.com`). Credential-file candidate paths are the real, accurate per-platform locations (`~/.aws/credentials`, `~/.config/openai/auth.json`, `~/.continue/config.json`, `~/.ollama/config.json`, `%APPDATA%\Code\User\settings.json`, `%APPDATA%\github-copilot\hosts.json`, shell history files). Key-signal matching uses real vendor key-prefix formats (`sk-proj-`, `sk-ant-`, `AIza`, `ghp_`, `gho_`). PII fields are appropriately *synthetic-but-structurally-valid* rather than real — using genuine PII would itself be a safety violation, so this is the correct identifier choice for the data payload, while all infrastructure identifiers (hosts, paths, key formats) are real. |
| **2c** | Telemetry Signal Quality (0–2.0) | **1.5** | Criterion 1 (signal richness) ✅ — every primitive emits a distinct, named signal in an appropriate telemetry surface: real DNS resolution + TLS handshake + HTTP request/response per vendor (stage 3), distinct file-write events for the canary DB and shadow-AI artifact (stages 1–2), and a distinguishable process-argv/env-scan pattern (stage 1). Criterion 2 (sensor mapping) ✅ — see the Detection Opportunity Audit below, cross-referencing each primitive to a specific rule. Criterion 3 (rule-artifact validity) ✅ — all 5 repo rule formats are now generated (`_detections.kql`, `_sigma_rules.yml`, `_rules.yar`, `_elastic_rules.ndjson`, `_dr_rules.yaml`); all are syntactically well-formed and technique-focused (keyed on real AI-vendor domains, credential-file patterns, PII regexes, and harvest signatures — not this test's specific artifact filenames). Criterion 4 (lab execution) ❌ — this test has not yet been deployed/run end-to-end in a lab environment; no `test_execution_log.json` or `bundle_results.json` exists for a real run. Per v2.1, 2c is hard-capped at **1.5** without lab evidence; with criteria 1–3 now fully met (raw sum 2.0), the hard cap itself becomes the binding constraint, so the score is exactly the cap: 1.5/2.0. |
| **2d** | Execution-Context Fidelity (0–1.0) | **0.5** | No stage branches on `IsAdmin`/`IsSystemContext` — all three stages perform identical operations (file writes to a fixed test directory, env-var reads, an outbound HTTPS POST) regardless of privilege level. This is the *realistic* shape for this specific technique: a shadow-AI insider or app-integration scenario is inherently ordinary-user-context tradecraft — a real employee pasting data into a chatbot never needs, or attempts, privilege escalation. Context-independence is therefore genuinely appropriate rather than a gap, which maps to the "handles one context well, doesn't branch, acceptable where context-independence is desirable" tier rather than full credit (no runtime context detection/branching code exists to earn 1.0). |
| **3a** | Schema & Metadata (0–1.0) | **1.0** | Schema v2.0 `InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)`; full `TestMetadata` (Version, Category, Severity, Techniques, Tactics, Score, `RubricVersion: "v2.1"`, Tags) and `ExecutionContext` (UUID `ExecutionID`, `orgInfo.UUID` — not a short name — for `Organization`, `Environment: "lab"`, `DeploymentType: "manual"`, per-stage `TimeoutMs`/`MultiStageEnabled` config). Metadata comment header present in the orchestrator `.go` file with all required fields. Stage and orchestrator binaries are signed per `build_all.sh`'s 8-step sequence (sign-before-embed, verify, gzip, sign orchestrator). |
| **3b** | Documentation Completeness (0–1.0) | **1.0** | README + this info card (with Score Breakdown table) + `<uuid>_references.md` present. MITRE mapping cites official technique IDs including the T1552.001 sub-technique. Score format validated against `**Test Score**: **7.8/10**` (README) / `## Test Score: 7.8/10` (info card) conventions. |
| **3c** | Logging & Plumbing (0–0.5) | **0.3** | `test_logger.go` v2.0 is used throughout; `test_execution_log.json` is written automatically by `SaveLog()`; per-stage `bundle_results.json` fan-out is wired via `WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)` on every exit path (blocked, error, and success). No pre/post `<uuid>_system_snapshot_{pre,post}.json` capture is wired (no Defender-status/AV-exclusion/hotfix snapshot calls in the orchestrator), which caps this sub-dimension short of full credit. |
| **3d** | Operational Hygiene (0–0.5) | **0.3** | Orchestrator binary well under budget: 6.57 MB (Windows) / 6.18 MB (Linux) — both inside the 10 MB green tier, let alone the 25 MB v2.1 threshold. All three stage binaries gzip-compress into that total, implying each is comfortably under the 5 MB per-stage threshold. Stage 3's only plausibly-hanging operation (the HTTP POST) is bounded by an explicit `http.Client{Timeout: 15 * time.Second}` — functionally a per-call timeout, though not a goroutine-based watchdog. No `time.AfterFunc`-style watchdog exists on stages 1/2 (their only wait is a fixed 3s `time.Sleep` for quarantine detection, low hang risk). Per-stage execution-time budgets are not formally documented against an enforced timeout (see Operational Notes below for estimated, not enforced, runtimes). `Endpoint.Stop()` is called immediately after `SaveLog()` on every exit path with no intervening blocking calls. |
| | **Total** | **7.8 / 10** | Realism: 5.2 / 7.0. Structure: 2.6 / 3.0. Ships (≥ 7.5 total, Realism ≥ 5.0, Structure ≥ 2.5). "Good" tier (6.0–7.9), just under the 8.0 "Advanced" threshold; a lab run (satisfying 2c criterion 4) plus system-snapshot wiring (3c) and per-stage watchdogs (3d) would likely cross into "Advanced." |

**Key Strengths**:
- Rigorous, positive-evidence-only leak/block classifier in Stage 3 that never defaults ambiguous transport outcomes to a "protected" verdict (direct implementation of CLAUDE.md Bug Prevention Rule 8) — see the dedicated Classification Integrity section below.
- Real production vendor hostnames, API paths, and vendor-correct request body shapes across all four major AI inference providers, plus real per-platform credential-file locations for two OSes.
- All 5 standard detection-rule formats generated (`_detections.kql`, `_sigma_rules.yml`, `_rules.yar`, `_elastic_rules.ndjson`, `_dr_rules.yaml`), each technique-focused rather than artifact-focused, so they would catch real-world shadow-AI PII egress regardless of tooling.
- Strong safety-by-construction design for a genuinely new test category: no auth headers ever sent, all PII fields are synthetic-but-structurally-valid with a run-unique traceability marker, credential values are never logged (redacted counts only), and canary artifacts are removed on every code path via `defer`.
- Leak-dominates aggregation semantics prevent a false "protected" reading when even one vendor received the data.
- Cross-platform (Windows + Linux) single build with per-platform credential-path candidates and correct `LOG_DIR`/`ARTIFACT_DIR` constants.

**Improvement Opportunities** (score < 9.0):
- No lab execution evidence yet — deploying this test against a real DLP/CASB/forward-proxy stack (see `debian`/`win` lab hosts) and recording `test_execution_log.json` + `bundle_results.json` would satisfy 2c criterion 4; since criteria 1–3 are now fully met, this is the *only* remaining lever on Telemetry Signal Quality (it would lift the cap itself, taking 2c from 1.5 to up to 2.0).
- No pre/post `<uuid>_system_snapshot_{pre,post}.json` capture — wiring this (Defender status, AV exclusions, hotfixes) would raise 3c to full credit.
- No per-stage watchdog goroutine — stage 3's 15s HTTP timeout bounds the only network operation, but adding a `time.AfterFunc`-based watchdog around each stage (matching the pattern used elsewhere in the repo) and documenting enforced per-stage time budgets would raise 3d.
- The three `TODO(user-adjudication)` branches in `classifyEgress` (captive-portal/SSO redirect, transparent-MITM 200 with corporate-DLP header, timeout-with-no-reset) are intentionally left as inconclusive pending an explicit user decision on their leak-vs-block mapping — resolving these (with the documented trade-offs in mind) would tighten classification precision without affecting the current score.

## Technical Details

### Attack Flow

1. **Stage 1 — Shadow-AI Staging & Key Discovery (T1552.001, T1119)**
   - Provisions `ARTIFACT_DIR` (fails to `999` if unwritable — a lab-setup issue, never a "blocked" verdict).
   - Drops an inert, never-executed `ai-assistant-helper.py` reference artifact plus a `.ai-assistant.json` config into `ARTIFACT_DIR`.
   - Sleeps 3s and re-`os.Stat`s the artifact; if it is gone, that is positive quarantine evidence (`126`).
   - Iterates `os.Environ()` and reads per-platform candidate credential files (`.env`, `.bashrc`/`.zshrc`/`.profile`/history files and `~/.aws/credentials`, `~/.continue/config.json`, `~/.ollama/config.json`, provider config JSON on Linux; `.env`, `.openai`, VS Code `settings.json`, `github-copilot/hosts.json`, `~/.aws/credentials` on Windows) looking for AI-service key name/prefix signatures.
   - Logs only **redacted counts** of candidate secrets found — never the matched values.
   - Cleans up its own artifacts via `defer` before exiting.

2. **Stage 2 — Synthetic Canary PII Collection (T1005)**
   - Generates 25 synthetic canary customer records via `canary.go` (`GenerateCanarySet`), each with a fake name, `.invalid`-TLD email, SSA-ad-reserved SSN, and Luhn-valid 4242-BIN PAN, all tagged with one run-unique marker (e.g. `F0-CANARY-a1b2c3d4`).
   - Writes a fake "customer DB" as `customer_records.csv` and `customer_records.json` into `ARTIFACT_DIR`.
   - Positive-evidence quarantine check on the CSV (`os.Stat` after a 3s sleep) — only path to `126`.
   - Collects the record set into `LOG_DIR/pii_payload.json`, the handoff artifact Stage 3 reads.
   - Removes the `ARTIFACT_DIR` canary DB files via `defer` before exiting.

3. **Stage 3 — Exfiltration to Inference Services (T1567)**
   - Reads `LOG_DIR/pii_payload.json` (falls back to generating its own 10-record canary set if run standalone).
   - Renders the records as a CSV-shaped prompt body embedded in each vendor's native chat-completion JSON schema.
   - POSTs, unauthenticated, to OpenAI, Anthropic, Gemini, and GitHub Copilot hosts with a 15s per-request timeout.
   - Classifies each attempt via `classifyEgress` (see Classification Integrity below) and aggregates leak-dominates across all four vendors.
   - Exit `0` (PII leaked to ≥1 vendor) → orchestrator reports `101` (Unprotected). Exit `126` (all attempts positively blocked) → orchestrator reports `126` (Protected), remaining stages n/a (this is the last stage). Exit `999` (no leak and no affirmative block evidence) → orchestrator reports `999` (inconclusive).

### Classification Integrity (Stage 3 leak-vs-block classifier)

`classifyEgress` in `stage-T1567.go` is the single most safety- and score-relevant function in this test. Its design principle: **key on WHO answered, not on status code.**

| Outcome | Verdict | Why |
|---|---|---|
| Any HTTP response over a TLS session that validates to the real vendor host, at *any* status code — including a vendor 401/403 at its own auth layer | **LEAK** | The request body (containing the canary PII) reached the vendor's edge and was processed enough to generate an auth-layer response. The bytes crossed the org boundary regardless of what the vendor did next. |
| Vendor hostname resolves to loopback / RFC1918 private / link-local / unspecified | **BLOCK** | Positive evidence of a DNS sinkhole or internal redirect — an org control intervened before any connection was attempted. |
| TLS certificate verification fails against a host that is normally publicly trusted | **BLOCK** | The real vendor's cert is publicly trusted; a verification failure means something re-signed the connection — an inline TLS-inspection proxy. |
| TCP connection refused/reset to a public vendor IP | **BLOCK** | An inline egress proxy or firewall actively rejected the connection to a real, routable vendor address. |
| DNS resolution failure (NXDOMAIN, resolver down, no network) | **ERROR (999)** | Ambiguous — could be a genuine network outage unrelated to any control. |
| Connection timeout with no reset | **ERROR (999)**, `TODO(user-adjudication)` | Cannot distinguish a silent egress-firewall drop from ordinary vendor slowness from the client side alone. |
| 3xx redirect to a non-vendor host (captive portal / SSO) | **ERROR (999)**, `TODO(user-adjudication)` | Cannot be certain the request body wasn't already forwarded before the redirect; mapping this to "block" risks hiding a real leak. |
| HTTP 200 carrying a narrow, known corporate-DLP header signature (Zscaler/Bluecoat/Forcepoint/Netskope/Umbrella/etc.) | **ERROR (999)**, `TODO(user-adjudication)` | Could be a transparent MITM proxy that stripped PII before forwarding, or a false positive from a benign CDN header; the narrow signature set avoids misclassifying real vendor CDN traffic (OpenAI/Anthropic sit behind Cloudflare) as interception. |
| Anything else (unrecognized transport error) | **ERROR (999)** | Never defaults to a block. |

The stage- and orchestrator-level aggregation is **leak-dominates**: if even one of the four vendors received the PII, the run is reported as a leak, even if another vendor's attempt was independently blocked. This prevents the false-reassurance failure mode CLAUDE.md Bug Prevention Rule 8 exists to catch — a partial block is not "protected."

### Key Indicators
- Outbound DNS queries and TLS connections from a non-browser process to `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `api.githubcopilot.com`.
- File creation of `ai-assistant-helper.py` / `.ai-assistant.json` in `ARTIFACT_DIR` (Stage 1) and `customer_records.csv` / `customer_records.json` in `ARTIFACT_DIR` (Stage 2).
- A single process reading 3+ distinct known AI-credential-file locations (`.env`, `.aws/credentials`, `.netrc`, shell history, IDE settings) within a short window.
- Process command-line/content referencing both an AI-vendor endpoint URL and an environment-variable-harvesting pattern (`os.environ`, `getenv`, `OPENAI_API_KEY`).
- Outbound HTTP request bodies containing SSN-shaped (`\d{3}-\d{2}-\d{4}`) or PAN-shaped (`4[0-9]{15}`) text to an AI-vendor host — visible only to a proxy/CASB with body inspection.

## Detection Opportunities

1. **Non-browser process egress to AI inference vendors (T1567)** — a process other than an approved browser/AI client connecting to any of the four vendor hostnames is the core shadow-AI egress signal. Covered by `_detections.kql` Query 1, `_sigma_rules.yml` rule `6d33cc62-sigma-001`, `_elastic_rules.ndjson` rule `6d33cc62-eql-001`, and `_dr_rules.yaml` rule `shadow-ai-egress-nonbrowser`.
2. **Automated harvesting of AI-service credential stores (T1552.001, T1119)** — a single process touching 3+ distinct known AI-credential locations within under 2 minutes. Covered by `_detections.kql` Query 2, `_sigma_rules.yml` rule `6d33cc62-sigma-002`, `_elastic_rules.ndjson` rule `6d33cc62-eql-002`, and `_dr_rules.yaml` rule `shadow-ai-key-harvest-file-read`.
3. **Staged shadow-AI helper tool (T1552.001 / T1119)** — a script/process whose command line or file content references both an AI-vendor endpoint and an env-var-harvesting pattern. Covered by `_detections.kql` Query 3, `_sigma_rules.yml` rule `6d33cc62-sigma-003`, `_elastic_rules.ndjson` rule `6d33cc62-eql-003`, `_dr_rules.yaml` rule `shadow-ai-helper-staging`, and `_rules.yar` rule `ShadowAI_Harvester_Tool` (file-content match on AI endpoints + env-key harvest strings).
4. **PII-bearing payload to an AI endpoint (T1005 → T1567)** — the true leak signal. On the network/proxy side this requires CASB/DLP body inspection to match SSN/PAN patterns in outbound request bodies to AI-vendor hosts (illustrative query template in `_detections.kql` Query 4 — adapt the table name to your proxy's content-log source). On the filesystem/content side, `_rules.yar` rules `ShadowAI_PII_Egress_Payload` (a staged file combining an AI-vendor reference with SSN/PAN/email patterns) and `ShadowAI_ChatCompletion_With_PII` (a chat-completion-shaped JSON body embedding SSN/PAN) catch the payload at rest before or during egress.
5. **Behavioral correlation** — Stage 1's credential-scan event followed within minutes by Stage 3's outbound POST to one of the same vendor hosts is a stronger composite signal than either alone; a SIEM correlation rule joining the credential-harvest detections (Query 2/3, sigma-002/003, eql-002/003) with the egress detection (Query 1, sigma-001, eql-001) by host/process within a short window would raise confidence and reduce standalone false positives.

## Expected Results

### Unprotected System (Code 101)
All three stages execute without any DLP/CASB/egress control intervening; canary PII (synthetic SSN/PAN/email records) reaches at least one AI vendor's validated TLS endpoint. AI-service API keys were discoverable on the host, sensitive-record collection was unimpeded, and PII egress to a shadow-AI endpoint was uncontrolled.

### Protected System
- **Code 126 (`Endpoint.ExecutionPrevented`)**: A control positively intervened at some stage — most commonly Stage 3 returning positive block evidence (DNS sinkhole, TLS-interception certificate failure, or a refused/reset connection to a public vendor IP), but also possible at Stage 1 or 2 if the staged artifact/canary DB is quarantined (confirmed via `os.Stat`).
- **Code 999 (`Endpoint.UnexpectedTestError`)**: Prerequisites were not met (e.g. `ARTIFACT_DIR` not provisioned/writable — see the `debian` lab host's provisioning requirement) or Stage 3's egress outcome was genuinely ambiguous (DNS failure, unrecognized transport error, or one of the three `TODO(user-adjudication)` edge cases). This is explicitly **not** a protection verdict — it means the test could not reach a confident conclusion, not that a control fired.

## References

See [`6d33cc62-d59d-4661-a76d-715aa4abddfd_references.md`](6d33cc62-d59d-4661-a76d-715aa4abddfd_references.md) for full source provenance, supporting resources, and related advisories.

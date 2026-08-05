# PII Exfiltration to External Inference Services

**Test Score**: **7.8/10**

## Overview
Simulates the "shadow AI" data-governance failure mode: a well-meaning insider or an unsanctioned app integration that (1) stages a local AI-assistant helper and discovers AI-service API keys on the host, (2) collects a batch of customer-record-shaped PII, and (3) pastes/POSTs that PII to real external LLM inference vendors (OpenAI, Anthropic, Gemini, GitHub Copilot) over unauthenticated HTTPS. The test never touches real user data — every record is a synthetic, format-valid "canary" (SSA advertising-reserved SSNs, Luhn-valid 4242-test-BIN card numbers, `.invalid`-TLD emails) tagged with a run-unique marker. It validates whether an organization's DLP, CASB, or egress-proxy controls catch PII heading to AI-service endpoints — it is **not** an EDR payload-stopping test, and no malware is dropped or executed.

## MITRE ATT&CK Mapping
- **Tactic**: Credential Access, Collection, Exfiltration
- **Technique**: T1552.001 - Unsecured Credentials: Credentials In Files
- **Technique**: T1119 - Automated Collection
- **Technique**: T1005 - Data from Local System
- **Technique**: T1567 - Exfiltration Over Web Service

## Test Execution
A 3-stage killchain (orchestrator + 3 gzip-embedded, individually signed stage binaries) simulates shadow-AI PII egress end to end:

1. **Stage 1 (T1552.001 / T1119)** — drops a benign, never-executed `ai-assistant-helper.py` artifact into `ARTIFACT_DIR`, then scans process environment variables and common per-platform config/credential paths (`.env`, `.aws/credentials`, `~/.continue/config.json`, `~/.ollama/config.json`, VS Code `settings.json`, `github-copilot/hosts.json`, etc.) for AI-service API key signatures. Only redacted match **counts** are ever logged — key values are never captured or transmitted.
2. **Stage 2 (T1005)** — generates 25 synthetic canary customer records and writes a fake "customer DB" (CSV + JSON) into `ARTIFACT_DIR`, then collects the records into an egress payload at `LOG_DIR/pii_payload.json` for Stage 3. ARTIFACT_DIR canary files are cleaned up before the stage exits.
3. **Stage 3 (T1567)** — POSTs the canary PII, embedded in a vendor-shaped chat-completion request body, over real TLS to `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, and `api.githubcopilot.com`. **No Authorization/API-key header is ever sent.** Each attempt is classified by a dedicated leak-vs-block classifier (see below) that keys on *who answered*, never on HTTP status code alone.

## Prerequisites

The orchestrator runs a **preflight** before extracting any stage binary: it creates `ARTIFACT_DIR` and then proves it is writable by writing and removing a probe file. Existence alone is not accepted — a directory that exists but denies writes to the current user (root-owned `/home/fortika-test`; an admin-created `c:\Users\fortika-test` without Users modify rights) would otherwise pass `os.MkdirAll` and fail later, mid-stage.

If the preflight fails the test stops immediately with `Endpoint.UnexpectedTestError` (result code **999**; process exit code `1`, and `exitCode: 1` in `test_execution_log.json` — the Prelude constant is 1, per framework convention) and prints the platform-specific provisioning commands. This is explicitly *not* a protection verdict — no stage ran, and no stage PEs were dropped to `LOG_DIR`.

Creating `ARTIFACT_DIR` requires elevation on both platforms (`C:\Users` denies directory creation to standard users; `/home` is root-owned). Running the orchestrator as SYSTEM/admin — the normal ProjectAchilles agent deployment — provisions it automatically. To run as a non-admin user, provision once beforehand:

```powershell
# Windows (elevated, once)
mkdir "c:\Users\fortika-test"
icacls "c:\Users\fortika-test" /grant Users:(OI)(CI)M
```
```bash
# Linux (once)
sudo mkdir -p /home/fortika-test && sudo chmod 777 /home/fortika-test
```

`LOG_DIR` needs no provisioning — the test creates it.

## Expected Outcomes
- **Protected**: A DLP/CASB/egress control positively intervenes (DNS sinkhole to a non-routable address, TLS-interception certificate failure, or a proxy connection refused/reset to a public vendor IP) — the killchain halts before any data crosses the boundary.
- **Unprotected**: No control intervenes; canary PII reaches at least one AI vendor's validated TLS endpoint (including a vendor 401/403 response — the bytes still crossed the boundary).
- **Inconclusive**: Prerequisites unmet (e.g., `ARTIFACT_DIR` not provisioned) or the egress outcome is genuinely ambiguous (DNS failure, connection timeout with no reset, captive-portal/SSO redirect, transparent-MITM 200 with a corporate-DLP header signature). The test never guesses a block verdict from ambiguous evidence.

## Classification Integrity (Stage 3 / T1567)

`stage-T1567.go`'s `classifyEgress` function is the integrity-critical logic in this test and deliberately implements CLAUDE.md Bug Prevention Rule 8 ("classify blocked only on positive evidence"). It performs the DNS-sinkhole check itself, then delegates response and transport-error classification to the `classifier/` subpackage, which exists separately so this decision is unit-testable in isolation (`go test ./classifier/`) — the test directory itself has multiple `package main` entrypoints and cannot be `go test`ed directly.

- **LEAK** is declared for *any* HTTP response received over a TLS session that validates to the real vendor host — including a vendor 401/403 at its own auth layer. A rejected-for-no-API-key response still means the request body reached the vendor's edge; that is a leak, not a block.
- **BLOCK** requires affirmative evidence that an *org* control intervened: the vendor hostname resolving to loopback/RFC1918/link-local (DNS sinkhole), a TLS certificate verification failure against a publicly-trusted vendor host (TLS-inspection proxy), or a TCP connection refused/reset to a public vendor IP (inline egress proxy).
- **Everything ambiguous defaults to inconclusive (999) — never to a block.** DNS resolution failures, connection timeouts with no reset, captive-portal/SSO redirects to non-vendor hosts, and transparent-MITM 200 responses carrying a narrow allowlist of corporate-DLP header signatures have each been **adjudicated and deliberately resolved to inconclusive**, with the trade-off reasoning retained inline at every branch in `classifier/classifier.go`. None of them may map to a block: for the transparent-MITM case in particular, a 200 carrying a DLP signature cannot reveal whether the gateway dropped the request or forwarded it to the vendor, and that disposition is unobservable from the client.
- **Aggregation is leak-dominates.** If any one of the four vendors received the PII, the stage (and orchestrator) report a leak even if another vendor's attempt was independently blocked — reporting "protected" while data actually left the network would be a false reassurance.

## Build Instructions
```bash
# Build single self-contained binary (both platforms)
./tests_source/intel-driven/6d33cc62-d59d-4661-a76d-715aa4abddfd/build_all.sh

# Or manually:
./utils/gobuild build tests_source/intel-driven/6d33cc62-d59d-4661-a76d-715aa4abddfd/
./utils/codesign sign build/6d33cc62-d59d-4661-a76d-715aa4abddfd/6d33cc62-d59d-4661-a76d-715aa4abddfd.exe
```

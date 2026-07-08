# Design: PII Exfiltration to External Inference Services

- **Test UUID:** `6d33cc62-d59d-4661-a76d-715aa4abddfd`
- **Category:** intel-driven
- **Date:** 2026-07-07
- **Author:** sectest-builder (design brainstormed with user)
- **Status:** Approved design — pending implementation

## 1. Purpose

Help organizations understand whether they are **leaking PII to external AI inference
services** ("shadow AI" data governance). Employees and applications increasingly paste
customer records, source code, and secrets into ChatGPT, Claude, Gemini, and Copilot,
where the data leaves the organization's control boundary. This test simulates that
egress and validates whether the org's **DLP / CASB / egress-proxy / EDR** controls
detect or block PII heading to real AI vendor hosts.

The "adversary" here is typically a well-meaning insider or an app integration, not
malware. The test therefore validates **detection/DLP coverage of AI egress**, not an
EDR's ability to stop a payload.

## 2. Scope & Key Decisions (from brainstorming)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Test layer | **Combined killchain** | Exercises discovery AND egress detection across stages. |
| Exfil destination | **Real AI vendor hosts** | Real SNI/DNS/TLS + destination reputation exercises the true DLP/CASB surface. |
| Credentials | **No keys ever** | Fan out to real hosts unauthenticated; PII rides in the request body and is inspected by egress DLP before the vendor 401s at auth — so the vendor never fully ingests the body. |
| PII type | **Synthetic canary records** | Fake but format/checksum-valid (SSN, Luhn-valid PAN, emails). Traceable; no real person's data ever transmitted. |
| Platform | **Windows + Linux** | `win` lab = real Defender/DLP detonation; `debian` lab = behavior/exit-code smoke (no EDR). Per-OS build tags. |
| Architecture | **Multi-stage** (3 techniques) | Orchestrator + 3 signed, gzip-embedded stage binaries. |

## 3. Architecture

Multi-stage pattern per `sample_tests/multistage_template/` and the modern 8-step
`build_all.sh` (build stages → sign → gzip → embed → sign orchestrator).

```
orchestrator (6d33cc62…)
 ├── stage1_shadowai   — T1552.001, T1119  (shadow-AI staging & key discovery)
 ├── stage2_collect    — T1005             (synthetic canary PII collection)
 └── stage3_exfil      — T1567             (exfiltration to inference services)
```

### Stages

| Stage | MITRE | Behavior |
|-------|-------|----------|
| 1 — Shadow-AI staging & key discovery | T1552.001 (Credentials in Files), T1119 (Automated Collection) | Drops an "ai-assistant" tool artifact into `ARTIFACT_DIR`; scans env vars and common config paths (`.env`, `~/.config`, `~/.aws`, shell history on Linux; user profile + env on Windows) for AI-service API keys. Simulates how shadow-AI tooling harvests creds. |
| 2 — PII collection | T1005 (Data from Local System) | Generates synthetic **canary** PII records (fake customer DB: names, SSNs with valid area/group rules, emails, PANs passing the Luhn check) into `ARTIFACT_DIR`, then collects them into a payload buffer. Each canary is tagged with a run-unique marker for traceability. |
| 3 — Exfiltration to inference services | T1567 (Exfiltration Over Web Service) | Builds a realistic chat-completion JSON body embedding the canary PII and POSTs it over real TLS, in sequence, to OpenAI, Anthropic, Gemini, and Copilot hosts. Classifies each attempt (see §4). |

**Tactics:** collection, credential-access, exfiltration.
**Severity:** high. **Complexity:** medium. **Target:** windows-endpoint, linux-endpoint.

## 4. Result Classification (load-bearing logic)

The Stage 3 classifier is the integrity-critical component. It MUST distinguish
"the org's controls intervened" (block) from "the PII reached the vendor" (leak).
Per CLAUDE.md Bug Prevention Rule 8, a block code is returned ONLY on positive evidence.

| Outcome | Code | Evidence |
|---------|------|----------|
| **Leaked** | **101** `Endpoint.Unprotected` | Any HTTP response received from the real vendor host — **including a vendor 401/403 at its auth layer**. The bytes crossed the boundary; DLP did not catch them. |
| **Prevented** | **126** `Endpoint.ExecutionPrevented` | Positive evidence *the org's* controls intervened: proxy connection refused/reset, TLS-inspection denial (cert/handshake block), DNS resolving the vendor host to a sinkhole/RFC1918/loopback, or an HTTP block-page from a DLP forward proxy. |
| **Error** | **999** `Endpoint.UnexpectedTestError` | No network at all, `ARTIFACT_DIR` unprovisioned, or an ambiguous/unrecognized failure that is not affirmative block evidence. |

**Critical trap to avoid:** a `401 Unauthorized` returned *by the vendor* means the PII
was transmitted and reached the vendor — that is a **LEAK (101)**, never a block. A block
is a `403`/reset/redirect emitted by *your* forward proxy or DLP, distinguishable by the
responding host / TLS peer identity, not by status code alone. The classifier must key on
**who** answered (vendor endpoint vs. interception layer), not merely the status code.

**Ambiguous edge cases (user to adjudicate at implementation time):**
- Transparent MITM proxy that *is* the org DLP, returning `200` after stripping/redacting PII.
- Captive-portal / SSO redirect intercepting the request.
- Connection timeout with no RST (could be silent drop by egress firewall, or vendor slowness).

Default for anything not matching an affirmative block signal: **999**, never 126.

## 5. Exit Code Logic (orchestrator)

- Aggregate across stages. Exit **126** if any stage produced affirmative block evidence
  (a critical protection layer worked).
- Exit **101** if all egress attempts leaked (PII reached at least one vendor, no controls fired).
- Exit **999** if prerequisites were not met (e.g., `ARTIFACT_DIR` unprovisioned, no network).
- Never hardcode; evaluate actual per-stage results.

## 6. Safety Invariants (non-negotiable)

1. **Canary-only PII** — synthetic, format-valid, tagged, corresponds to no real person.
2. **No credentials transmitted** — hosts are hit unauthenticated; the vendor never ingests/logs a valid-auth body.
3. **Residual governance note (owned decision):** the test does populate a third-party
   vendor's request logs with a request originating from the org. This is accepted as an
   explicit, authorized trade-off for real-destination fidelity. Documented here so it is
   not a silent side effect.
4. **Artifact cleanup** — canary files removed from `ARTIFACT_DIR` after run.

## 7. Compliance Requirements (F0RT1KA framework)

- Schema v2.0 `InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)`; RubricVersion `v2.1`.
- Organization UUID support via `org_resolver.go` + `github.com/google/uuid`.
- Metadata comment header in the main Go file (all v2.0 fields).
- Per-platform logger files (`test_logger_windows.go`, `test_logger_linux.go`).
- Binaries drop to `LOG_DIR`; canary artifacts to `ARTIFACT_DIR`.
- Multi-stage gzip-embed pattern; dual/F0RT1KA signing for Windows stages; Linux signing is a no-op.
- `io.MultiWriter` stdout/stderr capture for embedded binaries.
- Kill-chain diagram (mandatory for multi-stage tests).
- Binary size budget: target 🟢 ≤ 10 MB (Go-only, achievable).

## 8. Deliverables (per CLAUDE.md "Required Files")

`6d33cc62…/` dir, main `.go`, `test_logger.go` + platform files, `org_resolver.go`,
`README.md`, `<uuid>_info.md`, `go.mod`, `<uuid>_references.md`, `build_all.sh`,
plus detection rules, defense guidance, and a kill-chain diagram.

## 9. Lab Validation Plan

- **`debian`** — provision `ARTIFACT_DIR` (`sudo mkdir -p /home/fortika-test && sudo chmod 777`),
  ship Linux binary, run. Confirms stages reach, canary generation works, egress attempts
  fire, and exit-code logic is correct. Does **not** prove DLP fires (no EDR/DLP on box).
- **`win`** — provision `ARTIFACT_DIR` (`c:\Users\fortika-test`), ship signed binary, detonate.
  Real Defender ON. Expected honest result: **101 (leaked)** unless a DLP/egress proxy is present —
  which correctly demonstrates an AI-egress DLP gap. Do not raise telemetry-signal-quality score
  past the no-lab cap without a protected host actually blocking.

## 10. Out of Scope

- Model memorization / training-data extraction (research-grade, poor fit for endpoint detonation).
- macOS target (lab is a placeholder; would ship untested).
- Real authenticated delivery that completes end-to-end (rejected for safety).

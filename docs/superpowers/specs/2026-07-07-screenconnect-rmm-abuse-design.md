# Design: ScreenConnect Unsanctioned RMM Abuse for Third-Party Access

- **Test UUID:** `208ef54b-06bc-4610-87b6-520aea57517e`
- **Category:** intel-driven
- **Date:** 2026-07-07
- **Author:** sectest-builder (design brainstormed with user)
- **Status:** Approved design — pending implementation

## 1. Purpose

Help organizations understand whether their **AV/EDR detects a legitimate, signed remote
monitoring & management (RMM) agent being installed and used for unsanctioned third-party
access**. ConnectWise ScreenConnect is the single most-abused RMM in 2023–24 access-broker
and ransomware intrusions (Black Basta and others; mass-exploited post CVE-2024-1709). The
tradecraft is "living off trusted software": attackers install a *signed vendor agent* to
get durable, encrypted, allow-listed remote access that blends into normal IT operations.

The detection challenge is the same trust-inheritance problem as the 3CX test, from the
other direction: here the binary is genuinely benign and signed by the vendor — the test
validates whether controls flag the **anomalous install + service creation + relay** of an
unsanctioned RMM, not whether they block the agent's hash (they shouldn't).

## 2. Scope & Key Decisions (from brainstorming)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| RMM tool | **ScreenConnect (real signed MSI embed)** | Most-abused RMM in real intrusions; realism-first, matches the Tailscale `.msi` embed precedent. |
| Relay depth | **Local install + service validation (no live relay)** | Relay pointed at an unreachable/controlled URL. Exercises the high-value endpoint telemetry (vendor MSI silent install, service creation, signed-binary anomaly) with no infra to stand up and **no relay secrets committed** — the Tailscale-authkey lesson. |
| Kill-chain scope | **Include follow-on exfil stage** | Completes the chain the way RMM abuse actually ends (data theft / ransomware staging). |
| MSI acquisition | **User fetches out-of-band** | ConnectWise trial/free ScreenConnect MSI is a public vendor artifact; user stages it into the test dir before build. NOT committed if licensing disallows redistribution — treat as a local build asset. |
| Threat actor | **Black Basta** | Documented ScreenConnect abuser; concrete IOC/detection provenance. |
| Platform | **Windows only** | `win` lab = real Defender detonation; ScreenConnect abuse is overwhelmingly Windows. |
| Subcategory | **c2** | RMM functions as the command channel. |
| Architecture | **Multi-stage** (3 techniques) | Orchestrator + signed, gzip-embedded stages; embeds the real MSI as a resource. |

## 3. Architecture

Multi-stage pattern per `sample_tests/multistage_template/` and the modern 8-step
`build_all.sh`. Mirrors the Tailscale test's structure (embedded vendor MSI + `cleanup_utility.go`).

```
orchestrator (208ef54b…)
 ├── stage-T1219       — silent install of embedded signed ScreenConnect MSI
 ├── stage-T1543.003   — Windows service creation + relay/session attempt
 └── stage-T1567.002   — follow-on staging + exfil over the RMM foothold
 └── cleanup_utility   — uninstall agent + remove service post-run
```

### Stages

| Stage | MITRE | Behavior |
|-------|-------|----------|
| 1 — Silent RMM install | T1219 (Remote Access Software) | `msiexec /qn` installs the embedded, vendor-signed ScreenConnect agent from LOG_DIR. Detonation signal: an MSI silent-install of a remote-access agent that was not deployed by IT. |
| 2 — Service creation + relay attempt | T1543.003 (Windows Service), T1219 | Verifies ScreenConnect's `ScreenConnect Client (…)` service was created and is running, then the agent attempts its outbound relay against an **unreachable/controlled URL**. Logs service creation + the outbound DNS/connection attempt. No live relay. |
| 3 — Follow-on exfil | T1567.002 (Exfiltration to Cloud Storage) / T1041 (Exfil over C2) | Simulates the operator using the RMM foothold to collect **decoy data staged in ARTIFACT_DIR** and exfil it to a benign endpoint. File-collection + egress telemetry — the payoff stage. |

**Trusted-relationship framing technique:** T1199 (Trusted Relationship) — carried in metadata.
**Tactics:** command-and-control, persistence, exfiltration.
**Severity:** high. **Complexity:** medium. **Target:** windows-endpoint.
**Threat actor:** Black Basta. **Subcategory:** c2.

## 4. Result Classification (load-bearing logic)

Per CLAUDE.md Bug Prevention Rule 8, a block code is returned ONLY on positive evidence.

| Outcome | Positive evidence required | Code |
|---------|----------------------------|------|
| Blocked | MSI or agent quarantined (confirmed via `time.Sleep(3s)` + `os.Stat`); `msiexec` install denied by an OS/AV-emitted block; service creation refused by tamper protection with the agent confirmed NOT running. | 126 `ExecutionPrevented` (or 105 on quarantine) |
| Unprotected | Agent installs, service runs, exfil stage completes; no intervention. | 101 `Endpoint.Unprotected` |
| Test error | MSI not staged, `msiexec` returns an ambiguous non-block error, ARTIFACT_DIR not provisioned. Benign failures land here — NEVER a block code. | 999 `UnexpectedTestError` |

**Banned:** treating an empty/unclear `msiexec` or `sc.exe` result as a block. Corroborate
with positive evidence (re-query the service; confirm the agent is/ isn't running) per Bug
Prevention Rules 5 & 8.

## 5. Safety & Realism

- **Real signed vendor agent, benign use.** The MSI is ConnectWise's own signed installer; no
  live relay, so no real remote-control session is established.
- **No committed secrets.** Relay config points at an unreachable/controlled URL; any real
  relay/instance config (if the user later opts into live relay) stays out-of-band and is
  never committed.
- **Cleanup is mandatory and destructive-aware.** `cleanup_utility.go` uninstalls the agent
  and removes the service. This test *really installs software* → **snapshot the `win` VM
  before running** and revert after.
- **Lab.** Deploy to `win` (Defender ON). Provision ARTIFACT_DIR (`c:\Users\fortika-test`)
  with decoys; `LOG_DIR` (`C:\F0`) is self-created.

## 6. Deliverables (full artifact suite)

Required file set per CLAUDE.md (orchestrator `.go`, `stage-*.go`, `cleanup_utility.go`,
`test_logger.go` + `test_logger_windows.go`, `org_resolver.go`, `go.mod`, `build_all.sh`,
`README.md`, `<uuid>_info.md`, `<uuid>_references.md`) **plus** RubricVersion **v2.1**, the
detection suite (KQL / YARA / Sigma / Elastic EQL / LimaCharlie D&R), defense guidance +
hardening PS1 + IR playbook, and a kill-chain diagram.

## 7. Build / Size Notes

Embeds a real ScreenConnect MSI (~a few MB) → expected 🟢 Green / low 🟡 Yellow. The build
agent MUST read the produced orchestrator size and, if 🟡+, note the justification (real
vendor MSI required for fidelity) in `<uuid>_info.md`. Gzip-embed pattern mandatory for the
stage binaries; the MSI is embedded as a resource and dropped to LOG_DIR at runtime.

## 8. Implementation Path

Built via `@agent-sectest-builder`. **Build prerequisite:** the user stages the ConnectWise
ScreenConnect MSI into the test directory before the build completes; sectest-builder should
scaffold everything else and flag the missing MSI as the one manual gate.

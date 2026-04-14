# HONESTCUE LLM-Assisted Runtime C# Compilation

**Test Score**: **8.9/10**

## Overview

Simulates the HONESTCUE malware family disclosed by the Google Threat Intelligence Group (GTIG) in February 2026. HONESTCUE is a downloader/launcher framework that treats a cloud LLM API (Gemini) as a *live runtime dependency*: the malware sends a prompt, receives C# source code as the response, compiles it in-memory via `CSharpCodeProvider`, reflectively loads the resulting assembly with `Assembly.Load(byte[])`, and invokes its entry point. HONESTCUE also fetches follow-on payloads from trusted-looking web services (Discord CDN) to blend with benign network traffic.

This test models all three phases of that chain as independent, signed, gzip-compressed stage binaries embedded in a single orchestrator executable:

- **Stage 1 (T1071.001)** — Spins up a loopback mock Gemini server with a self-signed certificate pinned in the client's `TLSClientConfig`. Issues an HTTPS POST with a HONESTCUE-style prompt, receives C# source in a Gemini-schema response, and hands off the source to stage 2 via disk.
- **Stage 2 (T1027.004 + T1027.010 + T1620)** — Invokes `powershell.exe` with a loader script that uses `System.CodeDom.CSharpCodeProvider` (`GenerateInMemory=true`) to compile the LLM-sourced C#, round-trips the bytes through `Assembly.Load(byte[])` to exercise AMSI/ETW reflective-load telemetry, and invokes the entry point. The compiled code reads `HKLM\SOFTWARE\Microsoft\Windows Defender\Features` and writes a marker to `c:\Users\fortika-test\honestcue_marker.txt`.
- **Stage 3 (T1105 + T1583.006 + T1565.001)** — Backs up and modifies `C:\Windows\System32\drivers\etc\hosts` to redirect `cdn.discordapp.com` to 127.0.0.1, spins up a loopback Discord-CDN lookalike with a self-signed cert, issues an HTTPS GET for a CDN-shaped attachment URL, drops an UNSIGNED benign payload to `%TEMP%`, and executes it. Hosts-file restoration happens on every exit path (defer, panic recovery, signal handler, normal exit).

## MITRE ATT&CK Mapping

| Stage | Tactic | Technique | Name |
|-------|--------|-----------|------|
| 1 | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols (LLM API abuse) |
| 2 | Defense Evasion | T1027.004 | Obfuscated Files or Information: Compile After Delivery |
| 2 | Defense Evasion | T1027.010 | Obfuscated Files or Information: Command Obfuscation |
| 2 | Defense Evasion | T1620 | Reflective Code Loading |
| 2 | Execution | T1059.001 | Command and Scripting Interpreter: PowerShell (loader host) |
| 3 | Command and Control | T1105 | Ingress Tool Transfer |
| 3 | Resource Development | T1583.006 | Acquire Infrastructure: Web Services (Discord CDN abuse) |
| 3 | Impact | T1565.001 | Data Manipulation: Stored Data Manipulation (hosts file) |

## Test Architecture

Multi-stage (3 stages) with per-stage ES fan-out for technique-level detection precision. Each stage is built as an independent signed PE, gzip-compressed, and embedded in the orchestrator. The orchestrator extracts each stage on demand to `c:\F0`, executes it, and aggregates results.

**Single-binary deployment**: one signed `.exe` contains everything needed on the target.

## Test Execution

```bash
# Build (F0RT1KA-only signing - default)
./tests_source/intel-driven/e5472cd5-c799-4b07-b455-8c02665ca4cf/build_all.sh

# Deploy to target (requires administrator context on target)
# Copy build/e5472cd5-c799-4b07-b455-8c02665ca4cf/e5472cd5-c799-4b07-b455-8c02665ca4cf.exe
# to c:\F0\ on the Windows target and execute as Administrator.
```

## Prerequisites (Enforced by Orchestrator)

- Administrator context (required for hosts-file write in stage 3)
- `powershell.exe` available on PATH (required for stage 2 compile loader)
- .NET Framework 4.x installed (required for `CSharpCodeProvider` in stage 2)

If any prerequisite is missing, the test exits `999` (UnexpectedTestError) with a clear message — never `126` (blocked), so prerequisite gaps cannot be confused with EDR protection.

## Expected Outcomes

- **Protected (Exit 126)** — EDR detected and blocked at least one stage. Likely detection points: HTTPS POST to loopback LLM from non-browser process, `powershell.exe` + `Add-Type`/`CompilerParameters`, csc.exe child process spawning, `Assembly.Load(byte[])` AMSI event, hosts-file write by non-installer process, unsigned PE drop to `%TEMP%`, or `cdn.discordapp.com` request path.
- **Unprotected (Exit 101)** — All 3 stages completed; complete HONESTCUE chain successful. Marker files written to `c:\Users\fortika-test\honestcue_marker.txt` and `c:\Users\fortika-test\honestcue_cdn_marker.txt`.
- **Error (Exit 999)** — Prerequisites not met (missing admin context, missing .NET 4.x, missing PowerShell, port-bind failure). Environmental, not a protection signal.

## Safety Mechanisms

1. **Hosts-file backup & restoration** — Orchestrator copies the live hosts file to `c:\F0\hosts.bak` before any stage runs and restores on every exit path (`defer`, `recover()`, `SIGTERM`/`SIGINT` handler, normal exit, blocked-stage exit, error-stage exit).
2. **Loopback-only TLS servers** — Both mock LLM and mock Discord-CDN bind to 127.0.0.1 on high ports (48443, 48444). No external network traffic.
3. **Self-signed certs pinned client-side** — No TLS trust changes to the target system.
4. **Benign marker payloads** — Stage 2's reflectively-loaded assembly and stage 3's dropped executable only write timestamped marker files to `c:\Users\fortika-test`. No system modification beyond the hosts file (which is restored).
5. **Per-stage bundle results** — Each stage writes its own ES document so blue teams can see per-technique block/success outcomes in dashboards.
6. **Blame-keyword-free errors** — Exit-code determination follows Bug Prevention Rule 1: error messages describe the operation, never blame a cause.

## Detection Opportunities

A minimum of five high-signal detection opportunities across the three stages — see `e5472cd5-c799-4b07-b455-8c02665ca4cf_detections.kql` and `_sigma_rules.yml`:

1. Process spawning `powershell.exe` with `-File` pointing at `c:\F0\*.ps1`
2. `Add-Type` / `CompilerParameters` + `csc.exe` parent-of-powershell child trees
3. `[System.Reflection.Assembly]::Load([byte[]])` AMSI scan event
4. Non-installer write to `C:\Windows\System32\drivers\etc\hosts`
5. Unsigned PE-extension write to `%TEMP%` followed by execution
6. Outbound HTTPS to `cdn.discordapp.com` where DNS resolved to a loopback or RFC1918 address
7. Non-browser process issuing POST to LLM API endpoints (shape heuristics)

## References

- Primary source: [GTIG AI Threat Tracker — Distillation, Experimentation, and (Continued) Integration of AI for Adversarial Use](https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use) (Google Threat Intelligence Group, February 2026)
- MITRE ATT&CK — T1071.001: https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK — T1027.004: https://attack.mitre.org/techniques/T1027/004/
- MITRE ATT&CK — T1620: https://attack.mitre.org/techniques/T1620/
- MITRE ATT&CK — T1105: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK — T1583.006: https://attack.mitre.org/techniques/T1583/006/
- MITRE ATT&CK — T1565.001: https://attack.mitre.org/techniques/T1565/001/

See `e5472cd5-c799-4b07-b455-8c02665ca4cf_references.md` for full source provenance and supporting references.

# HONESTCUE LLM-Assisted Runtime C# Compilation (v2)

**Test Score**: **9.4/10**
**Version**: 2.0.0

## Overview

Simulates the HONESTCUE malware family disclosed by the Google Threat Intelligence Group (GTIG) in February 2026. HONESTCUE is a downloader/launcher framework that treats a cloud LLM API (Gemini) as a *live runtime dependency*: the malware sends a prompt, receives C# source code as the response, compiles it in-memory, reflectively loads the resulting assembly with `Assembly.Load(byte[])`, and invokes its entry point. HONESTCUE also fetches follow-on payloads from trusted-looking web services to blend with benign network traffic.

**v2 changes from v1** (see `_info.md` § "Changes from v1"):
- **Real wire-level IOCs**: Stages 1 and 3 now issue genuine HTTPS GETs to `raw.githubusercontent.com`, producing authentic TLS handshakes, JA3/JA4 fingerprints, DNS EventID 22 entries, and SNI values that EDR/NDR products can observe. v1's loopback mock-server approach never reached the network stack in a way NDR could see.
- **Native C# Roslyn Stage 2**: Stage 2 is now a .NET 8 self-contained single-file executable using `Microsoft.CodeAnalysis.CSharp` (Roslyn) for in-memory compilation via `CSharpCompilation.Create().Emit(MemoryStream)`. Real HONESTCUE on older hosts uses .NET Framework 4.x `CSharpCodeProvider`; on modern .NET 8 systems that API throws `PlatformNotSupportedException`, so Roslyn is the modern-runtime equivalent. The ATT&CK mapping (T1027.004 + T1027.010 + T1620) is unchanged — only the API surface is modernized.
- **No hosts-file manipulation**: All hosts-file backup/modify/restore logic is removed. Admin context is no longer required.
- **Exact GTIG prompts embedded**: All three GTIG HONESTCUE prompts (Prompts 1, 2, 3) are quoted verbatim in Stage 1 source as string constants. Prompt 3 is the "active" reference even though the GET does not send it in body — documented as a deliberate IOC-in-source choice in `_info.md`.

## Test Architecture

Three signed, gzip-compressed stage binaries embedded in a single orchestrator executable:

| Stage | Technique | Name |
|-------|-----------|------|
| 1 (Go) | T1071.001 | LLM API Fetch — GitHub-Raw GET |
| 2 (C# .NET 8) | T1027.004 + T1027.010 + T1620 | Roslyn In-Memory Compile & Reflective Load |
| 3 (Go) | T1105 + T1204.002 | GitHub-Raw PE Fetch & Execute |

**Single-binary deployment**: one signed `.exe` (~46 MB) contains everything needed on the target.

## MITRE ATT&CK Mapping

| Stage | Tactic | Technique | Name |
|-------|--------|-----------|------|
| 1 | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols (LLM API abuse) |
| 1 | Command and Control | T1105 | Ingress Tool Transfer (Gemini-shaped JSON from GitHub raw) |
| 2 | Defense Evasion | T1027.004 | Obfuscated Files or Information: Compile After Delivery |
| 2 | Defense Evasion | T1027.010 | Obfuscated Files or Information: Command Obfuscation |
| 2 | Defense Evasion | T1620 | Reflective Code Loading |
| 2 | Execution | T1059.001 | Command and Scripting Interpreter: PowerShell (prereq check) |
| 3 | Command and Control | T1105 | Ingress Tool Transfer (PE from GitHub raw) |
| 3 | Execution | T1204.002 | User Execution: Malicious File |

## Test Execution

```bash
# Build (F0RT1KA-only signing - default). Requires .NET 8 SDK + Go 1.21+.
./tests_source/intel-driven/e5472cd5-c799-4b07-b455-8c02665ca4cf/build_all.sh

# Deploy to target (administrator context NOT required)
# Copy build/e5472cd5-c799-4b07-b455-8c02665ca4cf/e5472cd5-c799-4b07-b455-8c02665ca4cf.exe
# to c:\F0\ on the Windows target and execute.
```

## Lab Asset Setup (One-Time)

The test fetches two static assets from GitHub raw-hosting. Reference copies ship under `lab_assets/`. See `lab_assets/README.md` for upload instructions.

| File | Purpose |
|------|---------|
| `gemini_response.json` | Pre-staged Gemini-shaped JSON hosting the C# source for stage 2 |
| `stage2_payload.exe` | F0RT1KA-signed benign marker PE dropped by stage 3 |

Update these constants in the Go source before rebuilding:

| Constant | File | Default |
|----------|------|---------|
| `STAGE1_LLM_RESPONSE_URL` | `stage-T1071.001.go` | `https://raw.githubusercontent.com/F0RT1KA/lab-assets/main/honestcue/v2/gemini_response.json` |
| `STAGE3_PAYLOAD_URL` | `stage-T1105.go` | `https://raw.githubusercontent.com/F0RT1KA/lab-assets/main/honestcue/v2/stage2_payload.exe` |

If the assets are not reachable at test time, the affected stage exits **999** (UnexpectedTestError), never **126** (blocked) — asset propagation gaps are never confused with EDR protection.

## Prerequisites (Enforced by Orchestrator)

- `powershell.exe` available on PATH (sanity check for Windows target)
- .NET 8 **runtime** is NOT required on the target — Stage 2 is self-contained
- **Administrator context is NOT required** (v2 removed hosts-file modification)

If any prerequisite is missing, the test exits `999` (UnexpectedTestError) with a clear message.

## Expected Outcomes

- **Protected (Exit 126)** — EDR detected and blocked at least one stage. Likely detection points: real HTTPS GET to `raw.githubusercontent.com` from a non-browser/non-git process, `Microsoft.CodeAnalysis.CSharp.dll` image load in a non-dev context, `Assembly.Load(byte[])` AMSI event, unsigned (or non-whitelisted) PE drop to `c:\Windows\Temp`, process execution from `%TEMP%`.
- **Unprotected (Exit 101)** — All 3 stages completed; complete HONESTCUE v2 chain successful. Marker files written to `c:\Users\fortika-test\honestcue_marker.txt` and `c:\Users\fortika-test\honestcue_payload_marker.txt`.
- **Error (Exit 999)** — Prerequisites not met (missing PowerShell, lab asset URL unreachable, .NET 8 runtime missing in rare self-contained edge cases). Environmental, not a protection signal.

## Safety Mechanisms

1. **No system-config mutation** — v2 removed all hosts-file, registry-tamper, and persistence mechanisms from the v1 design. The test only drops files under `c:\F0\`, `c:\Users\fortika-test\`, and `c:\Windows\Temp\`.
2. **Graceful asset-missing mode** — Lab asset URL unreachable at test time maps to exit 999, never 126. Prerequisite gaps cannot be confused with EDR protection.
3. **Real TLS, no cert pinning** — Uses system trust store. No trust-store modifications.
4. **Benign marker payloads** — Stage 2's reflectively-loaded assembly and stage 3's dropped PE only write timestamped marker files to `c:\Users\fortika-test`. No system modification.
5. **Per-stage bundle results** — Each stage writes its own ES document so blue teams can see per-technique block/success outcomes in dashboards.
6. **Blame-keyword-free errors** — Exit-code determination follows Bug Prevention Rule 1: error messages describe the operation, never blame a cause.

## Detection Opportunities

A minimum of seven high-signal detection opportunities across the three stages — see `e5472cd5-c799-4b07-b455-8c02665ca4cf_detections.kql` and `_sigma_rules.yml`:

1. Non-browser / non-git process issuing HTTPS GET to `raw.githubusercontent.com` (DNS EventID 22 + ProcessStart pivot)
2. TLS ClientHello with SNI `raw.githubusercontent.com` from an unusual UA
3. `Microsoft.CodeAnalysis.CSharp.dll` image load in a non-IDE, non-build-server process
4. `[System.Reflection.Assembly]::Load([byte[]])` AMSI scan event
5. PE-extension file write under `c:\Windows\Temp\` from a non-installer process
6. Process creation of a PE dropped under `c:\Windows\Temp\`
7. In-memory strings / YARA match on any of the three embedded exact GTIG HONESTCUE prompts

## References

- Primary source: [GTIG AI Threat Tracker — Distillation, Experimentation, and (Continued) Integration of AI for Adversarial Use](https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use) (Google Threat Intelligence Group, February 2026)
- MITRE ATT&CK — T1071.001: https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK — T1027.004: https://attack.mitre.org/techniques/T1027/004/
- MITRE ATT&CK — T1620: https://attack.mitre.org/techniques/T1620/
- MITRE ATT&CK — T1105: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK — T1204.002: https://attack.mitre.org/techniques/T1204/002/

See `e5472cd5-c799-4b07-b455-8c02665ca4cf_references.md` for full source provenance and supporting references.

# PROMPTFLUX v1 — LLM-Assisted VBScript Dropper

**Test Score**: **9.4/10**

## Overview

Simulates the PROMPTFLUX malware family disclosed by the Google Threat Intelligence Group (GTIG) in November 2025 — a VBScript dropper that uses the Google Gemini API at runtime to metamorphically rewrite its own body on an hourly cadence (the "Thinging" module), persists via the user Startup folder, and enumerates removable and network drives via WMI for propagation. This test reproduces the **shape** of those behaviours — real HTTPS fetch, wscript.exe staging, on-disk overwrite, Startup folder drop, WMI enumeration — while substituting benign VBS payloads and stopping at enumeration-only for the propagation step.

## MITRE ATT&CK Mapping

| Stage | Tactic | Technique | Name |
|-------|--------|-----------|------|
| 1 | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols |
| 2 | Defense Evasion | T1027.001 | Obfuscated Files or Information: Binary Padding (metamorphic rewrite) |
| 3 | Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| 4 | Lateral Movement | T1091 | Replication Through Removable Media (enumeration-only) |

Supporting techniques observed but not primary:
- T1074.001 (Local Data Staging) — `%TEMP%\thinking_robot_log.txt` raw LLM response drop
- T1059.005 (Command and Scripting Interpreter: Visual Basic) — wscript.exe execution in stages 1 and 2

## Test Architecture

Multi-stage (4 stages) with per-stage ES fan-out (`WriteStageBundleResults`) for technique-level detection precision. Stage binaries are gzip-compressed and embedded in the orchestrator; decompression and execution happen from `c:\F0` after signature-verify.

Static lab assets live in **ProjectAchilles** at `lab-assets/promptflux/v1/`:
- `gemini_response.json` — Gemini-shaped JSON envelope fetched by stage 1
- `variant_thinging.vbs` — metamorphic variant fetched by stage 2

Both are served from `https://raw.githubusercontent.com/projectachilles/ProjectAchilles/main/lab-assets/promptflux/v1/` so the test produces real TLS handshakes, DNS lookups, and SNI values observable by EDR/NDR.

## Test Execution

```bash
# Build (requires F0RT1KA.pfx in signing-certs/)
./tests_source/intel-driven/0a749b39-409e-46f5-9338-ee886b439cfa/build_all.sh

# Deploy single binary to target
# Copy build/0a749b39-409e-46f5-9338-ee886b439cfa/0a749b39-409e-46f5-9338-ee886b439cfa.exe to C:\F0\
```

## Expected Outcomes

- **Protected (Exit 126)**: EDR detects and blocks at least one stage (HTTPS fetch to GitHub raw by non-browser, wscript.exe spawned from an unsigned binary in c:\F0, VBS write to user Startup folder, or WMI Win32_LogicalDisk enumeration from a c:\F0 binary). Stage 4 specifically treats WMI permission-denied / empty-output as **blocked** per CLAUDE.md Rule 5.
- **Unprotected (Exit 101)**: All 4 stages complete without prevention — full PROMPTFLUX killchain simulated (minus the actual copy in stage 4, which is intentionally out of scope).
- **Error (Exit 999)**: Prerequisites not met — typically a lab-asset URL unreachable, wscript.exe missing, or WMI service down for a non-protection reason.

## Detection Opportunities

Detection rules are provided in 5 formats (KQL, YARA, Sigma, Elastic EQL, LimaCharlie D&R) covering:

1. Non-browser process issuing HTTPS GET to `raw.githubusercontent.com/projectachilles/ProjectAchilles` — the LLM-proxy fetch IOC
2. Write of `.vbs` file to `c:\F0\` followed by wscript.exe execution of that same file
3. Write of `thinking_robot_log.txt` to `%TEMP%` — exact GTIG PROMPTFLUX IOC
4. Overwrite of a VBS file with different content-hash twice within the same test window — the metamorphic/Thinging behavioural signal
5. VBS file dropped into any Startup folder (user or All-Users) by a non-installer process — especially filename `ScreenRecUpdater.vbs`
6. `wmic.exe logicaldisk get ... /format:csv` spawned as child of a binary under `c:\F0`
7. Combined behavioural correlation: stages 1-4 IOCs co-occurring on the same host within 5 minutes

## Safety

All payloads in this test are **benign** — the VBS bodies only echo a marker string and write a marker file. The orchestrator cleans up every artefact on every exit path (normal return, panic, SIGINT, SIGTERM). The propagation stage enumerates drives but **never copies** anything. No registry writes. No scheduled tasks. No network egress beyond two GitHub-raw GETs. No destructive APIs.

## References

- MITRE ATT&CK — Techniques: [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | [T1027.001](https://attack.mitre.org/techniques/T1027/001/) | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [T1091](https://attack.mitre.org/techniques/T1091/)
- Primary source: GTIG (Google Threat Intelligence Group) — PROMPTFLUX disclosure, November 2025 (see `0a749b39-409e-46f5-9338-ee886b439cfa_references.md` for full citation and canonical URL)
- Lab assets: [`projectachilles/ProjectAchilles/lab-assets/promptflux/v1/`](https://github.com/projectachilles/ProjectAchilles/tree/main/lab-assets/promptflux/v1)

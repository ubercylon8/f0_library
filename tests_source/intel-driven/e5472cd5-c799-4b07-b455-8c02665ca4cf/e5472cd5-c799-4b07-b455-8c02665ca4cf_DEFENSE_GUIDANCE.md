# Defense Guidance — HONESTCUE LLM-Assisted Runtime C# Compilation

**Test ID**: e5472cd5-c799-4b07-b455-8c02665ca4cf
**MITRE ATT&CK**: T1071.001, T1027.004, T1027.010, T1620, T1105, T1583.006, T1565.001
**Threat Class**: LLM-as-runtime-component malware (HONESTCUE, PROMPTFLUX, and successors)
**Date**: 2026-04-13

## Threat Summary

HONESTCUE represents a new class of malware that treats a commercial LLM API (Google's Gemini) as a live runtime dependency rather than a developer convenience. On each execution the malware:

1. Sends a prompt to the Gemini API (T1071.001).
2. Receives C# source code as the response.
3. Compiles the source in-memory via `CSharpCodeProvider` (T1027.004).
4. Reflectively loads the compiled assembly via `Assembly.Load(byte[])` (T1620).
5. Invokes the loaded assembly's entry point to carry out stage-two actions.

Related HONESTCUE-class behaviors (confirmed and expected):

- Payload staging via abuse of trusted CDNs such as Discord's (T1583.006, T1105).
- Hosts-file redirection to spoof trusted CDN hostnames (T1565.001).
- AMSI-hostile patterns in the loader (indirect invocation, string concatenation).

## Defense Strategy Summary

**Top priorities for this threat class:**

1. **Deny runtime C# compilation on endpoints.** Enforce WDAC / AppLocker rules that prevent csc.exe from being invoked by PowerShell outside approved developer contexts.
2. **Monitor LLM API egress from non-browser clients.** The definitional signal for this threat class is a non-browser process contacting `generativelanguage.googleapis.com` (or equivalents).
3. **Protect the hosts file.** Strict file-integrity monitoring on `C:\Windows\System32\drivers\etc\hosts` detects the CDN-spoofing prerequisite.
4. **AMSI + ETW coverage for `Assembly.Load(byte[])`.** Modern EDR AMSI integration surfaces this reliably if script-block logging is enabled.
5. **Unsigned-PE execution blocking in %TEMP%.** A common stage-3 landing pattern; block where possible, alert always.

## Platform-Specific Hardening

This test targets Windows; see `e5472cd5-c799-4b07-b455-8c02665ca4cf_hardening.ps1` for the executable hardening script.

### Key Windows Controls

| Control | Purpose | Reference |
|---------|---------|-----------|
| PowerShell ScriptBlock Logging | Captures reflective-load and compile patterns for EDR/SIEM ingest | `Microsoft-Windows-PowerShell/Operational` event 4104 |
| PowerShell Constrained Language Mode | Blocks Add-Type / reflective Assembly.Load when combined with AppLocker | `__PSLockdownPolicy` env var + AppLocker |
| AppLocker / WDAC | Denies csc.exe execution from non-developer contexts | policy XML |
| Attack Surface Reduction rule `d1e49aac-8f56-4280-b9ba-993a6d77406c` | Blocks processes from running executable content from PSExec/WMI | Defender ASR |
| Attack Surface Reduction rule `3b576869-a4ec-4529-8536-b80a7769e899` | Blocks Office child process creation | Defender ASR |
| File Integrity Monitoring on hosts file | Detects T1565.001 hosts-file redirect | EDR FIM + Sysmon FileCreate event |
| Network egress allowlist for LLM endpoints | Restricts generativelanguage.googleapis.com / api.openai.com to approved clients | Firewall FQDN rules / Proxy policy |
| Windows Defender tamper protection | Prevents LLM-sourced code from disabling Defender | Defender policy |

## Incident Response Playbook

### Phase 1 — Triage (first 15 minutes)

1. Confirm the alert source — which of the detection rules fired?
2. Isolate the affected host from network (EDR network isolation).
3. Pull the following artifacts to IR workstation:
   - `C:\Windows\System32\drivers\etc\hosts` (current content)
   - PowerShell ScriptBlockLogging events (event 4104) from the last 4 hours
   - Process tree for the parent launcher process
   - Any PE files in `C:\Windows\Temp` and `C:\Users\<affected>\AppData\Local\Temp` (hash + submit)

### Phase 2 — Scope (next 60 minutes)

1. Query EDR / SIEM for the same behavior pattern on peer hosts:
   - Same parent process name
   - Same LLM API endpoint
   - Same hosts-file modification pattern
2. Collect memory image of the affected host if available.
3. Enumerate all PowerShell ScriptBlockLogging events containing `CSharpCodeProvider`, `GenerateInMemory`, or `Assembly.Load` across the fleet for the past 7 days.

### Phase 3 — Containment

1. Restore hosts file from known-good baseline. Confirm via FIM alert clearance.
2. Kill the parent launcher process and any csc.exe / powershell.exe children.
3. Remove dropped PEs from `%TEMP%`.
4. Block the LLM API endpoint at egress for the affected process / host pending further investigation. Note: do not block organization-wide unless justified.
5. Rotate any credentials the affected user had access to.

### Phase 4 — Eradication

1. Identify the initial access vector (email attachment? drive-by? supply chain?) — trace the parent process chain to its root.
2. Reimage the affected host.
3. Add hash-based IOCs to EDR block lists for any recovered HONESTCUE-family binaries.
4. Update the allowlist in rule 6 to only permit approved AI tooling; adjust the allowlist in rule 4 to only permit approved installer processes.

### Phase 5 — Recovery & Reporting

1. Restore host from known-good image.
2. Re-enable the hardening script on the restored host before reconnecting to network.
3. File incident report with:
   - Initial access vector
   - Affected hosts
   - Data accessed / exfiltrated (check reflective-load outputs in scriptblock logs)
   - Root cause and remediation timeline
4. Conduct tabletop exercise within 30 days on LLM-abuse scenarios.

## Detection Coverage Reference

| Detection Format | File | Count |
|------------------|------|-------|
| Microsoft Sentinel / Defender KQL | `e5472cd5-c799-4b07-b455-8c02665ca4cf_detections.kql` | 8 queries |
| YARA | `e5472cd5-c799-4b07-b455-8c02665ca4cf_rules.yar` | 5 rules |
| Sigma | `e5472cd5-c799-4b07-b455-8c02665ca4cf_sigma_rules.yml` | 7 rules |
| Elastic SIEM (EQL) | `e5472cd5-c799-4b07-b455-8c02665ca4cf_elastic_rules.ndjson` | 7 rules |
| LimaCharlie D&R | `e5472cd5-c799-4b07-b455-8c02665ca4cf_dr_rules.yaml` | 7 rules |

## Known Limitations of Detection

- **False positives in developer environments** — compile-from-PowerShell is a legitimate pattern on developer workstations. Tune allowlists accordingly or exclude developer OUs.
- **Encrypted LLM traffic** — detection of LLM API egress relies on DNS query visibility or SNI inspection. HTTPS body content is not visible without TLS interception (which is not recommended for LLM API endpoints due to privacy policies).
- **Offline / self-hosted LLMs** — adversaries can shift to open-source LLM runtimes (Ollama, llama.cpp, vLLM) that run on their own infrastructure. Rule 6 will not fire; supplement with detection of unusual outbound TLS to high ports.
- **Allowlist drift** — the browser/AI-tooling allowlist in Sigma rule 6 and D&R rule 6 requires ongoing maintenance as new AI clients proliferate.

## References

- GTIG AI Threat Tracker: https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use
- MITRE ATT&CK T1027.004: https://attack.mitre.org/techniques/T1027/004/
- MITRE ATT&CK T1620: https://attack.mitre.org/techniques/T1620/
- MITRE ATT&CK T1565.001: https://attack.mitre.org/techniques/T1565/001/
- Microsoft: CSharpCodeProvider API — https://learn.microsoft.com/en-us/dotnet/api/microsoft.csharp.csharpcodeprovider

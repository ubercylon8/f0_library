# Defense Guidance — HONESTCUE v2 LLM-Assisted Runtime C# Compilation

**Test ID**: e5472cd5-c799-4b07-b455-8c02665ca4cf
**Version**: 2.1.0
**MITRE ATT&CK**: T1071.001, T1027.004, T1027.010, T1620, T1105, T1204.002, T1059.001
**Threat Class**: LLM-as-runtime-component malware (HONESTCUE, PROMPTFLUX, and successors)
**Date**: 2026-04-13

## Threat Summary

HONESTCUE represents a new class of malware that treats a commercial LLM API (Google's Gemini) as a live runtime dependency rather than a developer convenience. On each execution the malware:

1. Sends a prompt to the Gemini API (T1071.001) — or, in HONESTCUE v2's trusted-hosting variant, fetches a pre-staged Gemini-shaped JSON response from a trusted CDN.
2. Receives C# source code as the response.
3. Compiles the source in-memory via `CSharpCodeProvider` (.NET Framework) or `Microsoft.CodeAnalysis.CSharp` / Roslyn (.NET 8+) — both map to T1027.004.
4. Reflectively loads the compiled assembly via `Assembly.Load(byte[])` (T1620).
5. Invokes the loaded assembly's entry point to carry out stage-two actions.
6. For stage-three staging, fetches additional payloads from trusted-hosting infrastructure (historically Discord CDN; increasingly GitHub raw, Cloudflare pages, Azure blob — T1105) and drops to `c:\Windows\Temp` before execution (T1204.002).

## Defense Strategy Summary

**Top priorities for this threat class:**

1. **Deny runtime C# compilation on endpoints.** Enforce WDAC / AppLocker rules that prevent Roslyn (`Microsoft.CodeAnalysis.CSharp.dll`) from being loaded by non-developer processes, and prevent `csc.exe` from being invoked by PowerShell outside approved contexts.
2. **Monitor trusted-hosting CDN egress from non-browser clients.** The definitional signal for this threat class is a non-browser / non-git process fetching from `raw.githubusercontent.com`, `cdn.discordapp.com`, `generativelanguage.googleapis.com`, etc.
3. **AMSI + ETW coverage for `Assembly.Load(byte[])`.** Modern EDR AMSI integration surfaces this reliably if script-block logging is enabled.
4. **Unsigned-PE execution blocking in %TEMP%.** A common stage-3 landing pattern; block where possible, alert always.
5. **String-based YARA on disk & memory for embedded GTIG HONESTCUE prompts.** The class name `HonestcueStage2` and the distinctive prompt phrases are high-quality IOCs.

## Platform-Specific Hardening

This test targets Windows; see `e5472cd5-c799-4b07-b455-8c02665ca4cf_hardening.ps1` for the executable hardening script.

### Key Windows Controls

| Control | Purpose | Reference |
|---------|---------|-----------|
| PowerShell ScriptBlock Logging | Captures reflective-load and compile patterns for EDR/SIEM ingest | `Microsoft-Windows-PowerShell/Operational` event 4104 |
| PowerShell Constrained Language Mode | Blocks Add-Type / reflective Assembly.Load when combined with AppLocker | `__PSLockdownPolicy` env var + AppLocker |
| AppLocker / WDAC for Roslyn | Denies Microsoft.CodeAnalysis.CSharp.dll load in non-developer contexts | AppLocker DLL rules, WDAC signed-file policy |
| AppLocker / WDAC for csc.exe | Denies csc.exe execution from non-developer contexts | policy XML |
| Attack Surface Reduction rule `d1e49aac-8f56-4280-b9ba-993a6d77406c` | Blocks processes from running executable content from PSExec/WMI | Defender ASR |
| Attack Surface Reduction rule `01443614-cd74-433a-b99e-2ecdc07bfc25` | Blocks executable files from running unless they meet prevalence/age/trusted-list criteria | Defender ASR |
| Sysmon EventID 22 DNS logging | Captures real-DNS IOCs for raw.githubusercontent.com from non-standard processes | Sysmon config |
| Network egress allowlist for trusted-hosting services | Restricts `raw.githubusercontent.com`, `cdn.discordapp.com`, `generativelanguage.googleapis.com` to approved clients | Firewall FQDN rules / Proxy policy |
| Windows Defender tamper protection | Prevents LLM-sourced code from disabling Defender | Defender policy |
| File Integrity Monitoring on c:\Windows\Temp (PE writes) | Detects stage-3 PE drops | EDR FIM + Sysmon FileCreate event |

## Why GitHub Raw Detection Rules Matter

Security teams often allowlist `raw.githubusercontent.com` because it supports legitimate developer workflows (package managers, dotfiles, CI scripts). HONESTCUE v2 (and increasingly real-world threat actor tradecraft) weaponizes this trust signal.

**The detection pivot**: don't alert on GitHub-raw fetches per se — alert on GitHub-raw fetches **by processes that are not browsers, git clients, or known package managers**. The KQL, Sigma, Elastic EQL, and LimaCharlie rules shipped with this test all use that filter-pattern. Tune the allowlist to your environment's real AI/dev tooling inventory.

## Incident Response Playbook

### Phase 1 — Triage (first 15 minutes)

1. Confirm the alert source — which of the detection rules fired?
2. Isolate the affected host from network (EDR network isolation).
3. Pull the following artifacts to IR workstation:
   - Process tree for the parent launcher process + all children
   - PowerShell ScriptBlockLogging events (event 4104) from the last 4 hours
   - Sysmon EventID 7 (image loads) for `Microsoft.CodeAnalysis.CSharp.dll`
   - Sysmon EventID 22 (DNS queries) for `raw.githubusercontent.com`, `cdn.discordapp.com`, `generativelanguage.googleapis.com`
   - File listing of `c:\Windows\Temp\*.exe` and `c:\F0\*`
   - Any file at `c:\F0\honestcue_stage2_source.cs` or `c:\F0\gemini_response.json`
   - `%TEMP%` directory listing with MAC timestamps

### Phase 2 — Scoping (15–60 minutes)

1. Search SIEM for the same IOCs across the fleet:
   - Processes loading `Microsoft.CodeAnalysis.CSharp.dll` outside the dev allowlist
   - Processes connecting to `raw.githubusercontent.com` outside the browser/git allowlist
   - AMSI events containing `Assembly.Load` + `byte[]`
   - PE drops under `c:\Windows\Temp` followed by execution within 10 minutes
2. Correlate parent launcher processes to identify delivery vector.
3. Check for concurrent alerts referring to the same endpoints (likely related).

### Phase 3 — Containment (1–4 hours)

1. Block outbound access to any suspicious GitHub repository identified in step 2.
2. Hunt for the Gemini-shaped JSON on disk: YARA rule 5 from this package (`Gemini_Shaped_Response_Hosting_CSharp_Source`) matches the schema.
3. Hunt in memory for the exact GTIG prompts: YARA rule 1 (`HONESTCUE_Exact_GTIG_Prompts`).
4. If any host found with these IOCs, isolate and proceed to eradication.

### Phase 4 — Eradication (varies)

1. Kill all related processes identified in the process tree.
2. Delete `c:\F0\*`, `c:\Windows\Temp\honestcue_payload.exe`, `c:\Users\fortika-test\*.txt` (and any variant-named marker files).
3. Review the lab asset propagation — if your organization has a lab using this test, ensure asset URLs are only accessible to authorized test hosts.
4. Regenerate any credentials that may have been exposed via the LLM prompt path.
5. Update AppLocker / WDAC policies to block the observed launcher binary hash.

### Phase 5 — Recovery (varies)

1. Restore affected endpoint from known-good backup OR re-image.
2. Re-enable network connectivity after validating clean state.
3. Push hardening script (`_hardening.ps1`) to the affected host and to similarly-configured hosts.
4. Re-execute this test after hardening to confirm detection coverage.

### Phase 6 — Lessons Learned (1–2 weeks)

1. Did any detection rule fire? If not, tune.
2. Was the endpoint running a configuration that should have blocked any phase? If so, fix the gap.
3. Share IOCs (lab asset URLs, launcher hashes, prompt variants) with peer CTI circles.
4. Update the internal "trusted hosting CDN" allowlist policy if this campaign exposed a gap.

## Test-Specific Notes

- This F0RT1KA v2 test uses real HTTPS to `raw.githubusercontent.com` — the TLS+DNS+SNI observables are genuine.
- Lab asset URL constants live in Stage 1 (`STAGE1_LLM_RESPONSE_URL`) and Stage 3 (`STAGE3_PAYLOAD_URL`) source files. The default points to `github.com/projectachilles/ProjectAchilles` (path `lab-assets/honestcue/v2/`). Operators may fork/relocate the assets; see `lab_assets/README.md`.
- Exit code 999 always means "environmental prerequisite missing" (no PowerShell, lab asset unreachable) — never confuse with exit 126 (EDR blocked).
- Stage 2 is a .NET 8 self-contained single-file executable (~80 MB before gzip). Large binary size is inherent to the self-contained bundle; this is real-HONESTCUE-like for modern-runtime targets.

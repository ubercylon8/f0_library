# Defense Guidance — TclBanker Brazilian Banking Trojan

**Test UUID**: `bf448c7a-307e-4458-ba36-341d6d8e671b`
**Threat Actor**: TclBanker (Brazilian banking-trojan family)
**Source**: [Elastic Security Labs](https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan)
**Date**: 2026-05-11

This document is for SOC analysts and IR teams responding to TclBanker activity.
It pairs the test simulation with the controls that prevent, detect, and respond
to real TclBanker intrusions.

## Threat Summary

TclBanker is a .NET-based banking trojan targeting Brazilian banking customers.
Despite its name ("Tcl"), it has **nothing** to do with the Tcl scripting language
— the prefix refers to the .NET assembly namespaces `Tcl.Agent` and `Tcl.WppBot`.
Distribution is ZIP-wrapped MSI installers impersonating signed Logitech updates,
with the malicious payload executed via DLL sideloading from a renamed signed
Microsoft binary (`LogiAiPromptBuilder.exe` loading `screen_retriever_plugin.dll`).
Persistence is established via the COM Task Scheduler interface using the
distinctive task name `RuntimeOptimizeService`. C2 is hosted on Cloudflare
Workers (account `ef971a42`) and uses HMAC-SHA256-signed WebSocket handshakes.

## Attack Chain (with defense opportunities)

```
1. Phishing email / drive-by                 ← user awareness, email gateway
       ↓
2. ZIP wrapper / Logitech_Update_*.msi       ← gateway scanning, AMSI, ASR
       ↓
3. msiexec /i Logitech_Update_*.msi          ← AppLocker / WDAC, ASR
       ↓
4. Drop %LocalAppData%\LogiAI\ payload tree  ← Defender real-time, EDR file rules
       ↓
5. LogiAiPromptBuilder.exe loads             ← image-load telemetry,
   screen_retriever_plugin.dll                 EDR sideload heuristics
       ↓
6. Tcl.Agent / Tcl.WppBot decrypt + load     ← AMSI, .NET ETW, in-memory scan
       ↓
7. Brazilian locale + timing-VM gate         ← (no telemetry — silent)
       ↓
8. schtasks / COM RegisterTaskDefinition →   ← scheduled-task audit channel,
   RuntimeOptimizeService                      Sysmon event 4698
       ↓
9. UI Automation polling +                    ← UIA telemetry,
   WPF overlay + WH_KEYBOARD_LL                hook-install events
       ↓
10. DNS → *.workers.dev /                    ← DNS sinkholing, TLS inspection,
    WebSocket /ws + HMAC bearer                C2 detection rules
       ↓
11. Credentials exfiltrated +                ← banking app session monitoring,
    fraud transactions submitted               step-up auth, MFA
```

## Detection Coverage Provided

This test ships five rule formats covering the indicators above:

- **KQL** (`*_detections.kql`) — Microsoft Sentinel / Defender Advanced Hunting (11 queries)
- **YARA** (`*_rules.yar`) — file/memory scanning (8 rules incl. composite killchain rule)
- **Sigma** (`*_sigma_rules.yml`) — vendor-agnostic (7 rules)
- **Elastic EQL** (`*_elastic_rules.ndjson`) — Elastic SIEM (7 rules incl. sequence rule)
- **LimaCharlie D&R** (`*_dr_rules.yaml`) — LC tenants (7 rules)

The composite/sequence rules (YARA `TclBanker_Killchain_Composite`, EQL
`tclbanker-eql-007`, KQL rule 11) fire only when multiple stages line up — they
are the highest-confidence detection surface and should be wired to your highest
priority alert channel.

## Prevention Controls

### 1. Attack Surface Reduction (ASR)

Enable Defender ASR rules that block TclBanker's exact tradecraft:

- **`d4f940ab-401b-4efc-aadc-ad5f3c50688a`** — Block all Office applications from creating child processes (mitigates Office-borne ZIP delivery)
- **`d3e037e1-3eb8-44c8-a917-57927947596d`** — Block JavaScript or VBScript from launching downloaded executable content
- **`b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4`** — Block untrusted and unsigned processes that run from USB
- **`e6db77e5-3df2-4cf1-b95a-636979351e5b`** — Block persistence through WMI event subscription
- **`56a863a9-875e-4185-98a7-b882c64b5ce5`** — Block abuse of exploited vulnerable signed drivers
- **`c1db55ab-c21a-4637-bb3f-a12568109d35`** — Block Adobe Reader from creating child processes
- **`75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84`** — Block Office applications from injecting code into other processes

These can be applied automatically via `*_hardening.ps1`.

### 2. Software Restriction (AppLocker / WDAC)

The TclBanker chain only succeeds if the renamed `LogiAiPromptBuilder.exe`
running from `%LocalAppData%\` is permitted. WDAC policies that require
executables to be signed by trusted publishers and reside in trusted paths
prevent the entire DLL-sideloading stage. At minimum:

- Block executable launch from `%LocalAppData%`, `%AppData%`, `C:\ProgramData\`
- Allowlist Logitech executables only from `\Program Files\Logitech*\`

### 3. Scheduled Task Lockdown

Audit logs for the Microsoft-Windows-TaskScheduler/Operational channel
(events 106 = registered, 140 = updated) and alert on:

- Tasks named `RuntimeOptimizeService` (TclBanker signature)
- Any task with logon trigger, hidden flag, AND action targeting an executable
  in `%LocalAppData%\` or `%AppData%\`
- Any task registered by a non-administrator process

### 4. Network Egress Controls

Cloudflare Workers (`*.workers.dev`) is **easy to block at the egress proxy**.
Real Workers traffic for the org should come from a tightly-defined allowlist
of business-justified Workers apps. Treat any other `*.workers.dev` traffic
as suspicious.

### 5. Banking Site Step-Up Auth

The credential-capture surface only matters if the banking application has not
hardened against overlay-based session theft. Brazilian banks supporting any
of: device fingerprint, transaction signing, behavioral biometrics, or
out-of-band confirmation defeat the overlay-fraud step entirely.

## Detection Tuning Notes

- **False positives**: Cloudflare Workers is broadly used for legitimate apps —
  the C2 rule narrows to *.workers.dev with the account string `ef971a42` or
  TclBanker domain shapes. Tune the broader UIA-from-non-System32 KQL rule (#10)
  by joining to process parentage in your environment.
- **Tcl.Agent / Tcl.WppBot**: these specific .NET namespaces are unique to
  TclBanker — high-confidence signal, no expected FPs.
- **`RuntimeOptimizeService`**: not a Microsoft Windows task name. Any
  occurrence in a production environment should be investigated.

## Incident Response Playbook

### IR Step 1 — Contain
1. Isolate the affected host from the network (preserve volatile state — DO NOT shut down)
2. Disable the user's banking application access (notify fraud-prevention team)
3. Force-rotate any credentials the user entered post-infection

### IR Step 2 — Collect Evidence
1. Pull the scheduled task XML:
   ```powershell
   schtasks /query /tn RuntimeOptimizeService /xml > evidence_runtimeopt_task.xml
   ```
2. Snapshot `%LocalAppData%\LogiAI\` (and `%AppData%\LogiAI\`) and any
   `Logitech_Update_*.msi` in `%TEMP%` / Downloads / Outlook attachments
3. Capture process tree of `LogiAiPromptBuilder.exe` and its image-load list
4. Export network connections to `*.workers.dev` from the last 7 days
5. Pull `C:\temp\tcl-debug.txt` if present (high-confidence TclBanker artifact)

### IR Step 3 — Eradicate
1. Remove persistence: `schtasks /delete /tn RuntimeOptimizeService /f`
2. Quarantine `screen_retriever_plugin.dll`, `LogiAiPromptBuilder.exe`,
   any `Tcl.Agent.dll` / `Tcl.WppBot.dll` instances
3. Block the C2 domain at egress proxy / DNS resolver
4. Hunt for additional infected hosts using the composite YARA rule:
   `TclBanker_Killchain_Composite`

### IR Step 4 — Recover
1. Rebuild the affected host from a known-good image (TclBanker has been
   observed with stage payloads that drop additional capability — full
   rebuild is the safe option)
2. Re-issue the user's banking credentials with mandatory step-up auth
3. Review the user's banking-app login history for the previous 30 days

### IR Step 5 — Notify
1. **If the victim is a banking customer**: notify their financial institution
   so the bank can review recent transactions and flag the account
2. **If multiple users affected**: investigate the email gateway / phishing
   vector. TclBanker is typically spread via targeted phishing in Brazil
3. **If an enterprise endpoint**: notify CISO and consider regulatory
   reporting obligations (LGPD in Brazil, GDPR in EU if EU customers
   affected, SEC Form 8-K materiality for US-listed entities)

## Hunt Queries — Past 30 Days

```kql
// Hunt: TclBanker indicators across the fleet, past 30 days
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName matches regex @"(?i)^Logitech_Update_.+\.msi$"
    or FileName =~ "screen_retriever_plugin.dll"
    or FileName =~ "tcl-debug.txt"
    or FileName has_any ("Tcl.Agent", "Tcl.WppBot")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256
| order by Timestamp desc
```

## References

- Elastic Security Labs — TclBanker: A Brazilian Banking Trojan
  https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan
- MITRE ATT&CK Group/Software pages for related banking-trojan families
  (Mispadu, Grandoreiro, Casbaneiro) — common Brazilian-banking TTPs
- Microsoft Defender ASR rules reference
  https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference

# PROMPTFLUX v1 — Defense Guidance

**Test UUID**: `0a749b39-409e-46f5-9338-ee886b439cfa`
**Threat Model**: PROMPTFLUX — VBScript dropper with runtime LLM abuse (GTIG, Nov 2025)
**MITRE ATT&CK**: T1071.001 · T1027.001 · T1547.001 · T1091

This document gives defenders a concrete checklist for preventing, detecting,
and responding to PROMPTFLUX-class intrusions.

---

## 1. Prevention

### 1.1 Disable WSH on systems that don't need it

The single highest-impact control against VBScript droppers is disabling the
Windows Script Host engine. For any endpoint fleet where VBS / JS scripts are
not an operational requirement:

```
HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings
    Enabled = 0  (REG_DWORD)
```

Effect: wscript.exe and cscript.exe refuse to run any script. PROMPTFLUX stages
1 and 2 fail at the wscript invocation step.

### 1.2 Attack Surface Reduction (ASR) — block JS/VBS from running downloaded content

Microsoft Defender ASR rule **"Block JavaScript or VBScript from launching downloaded executable content"** (GUID `D3E037E1-3EB8-44C8-A917-57927947596D`) directly addresses the VBScript-launcher pattern PROMPTFLUX uses.

```powershell
Set-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
```

Complement with these ASR rules:
- `56a863a9-875e-4185-98a7-b882c64b5ce5` — Block abuse of exploited vulnerable signed drivers
- `3b576869-a4ec-4529-8536-b80a7769e899` — Block Office applications from creating executable content
- `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` — Block credential stealing from LSASS (unrelated to PROMPTFLUX but a strong baseline)

### 1.3 Prevent writes to user Startup folders by non-installer processes

Use a file-integrity rule (Applocker / WDAC / third-party FIM) to treat the
following paths as write-protected for any process other than MSI installers
and `explorer.exe`:

```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\
%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp\
```

PROMPTFLUX stage 3 fails at the write.

### 1.4 Block LLM-proxy hosting via network egress controls

If developer productivity doesn't mandate raw-GitHub access for all
endpoints, consider blocking `raw.githubusercontent.com` at the proxy /
NGFW for user-persona traffic, or restricting it to Git and IDE processes
only via process-aware egress policy.

### 1.5 AppLocker / WDAC — block unsigned EXE launch from user paths

A policy that blocks execution of any EXE in:

```
c:\F0\ (test-specific)
c:\Users\<*>\AppData\Local\Temp\
c:\Users\<*>\AppData\Roaming\
c:\ProgramData\ (except approved software)
c:\Users\Public\
```

unless signed by a whitelisted publisher stops PROMPTFLUX at the orchestrator
step — before any stage fires.

---

## 2. Detection

Five-format detection rule bundle is provided alongside this document:

| File | Format | Best for |
|------|--------|----------|
| `0a749b39-409e-46f5-9338-ee886b439cfa_detections.kql` | KQL | Microsoft Sentinel, Defender XDR, Log Analytics |
| `0a749b39-409e-46f5-9338-ee886b439cfa_rules.yar` | YARA | Endpoint memory scanning, file-quarantine inspection |
| `0a749b39-409e-46f5-9338-ee886b439cfa_sigma_rules.yml` | Sigma | Vendor-agnostic SIEM portability |
| `0a749b39-409e-46f5-9338-ee886b439cfa_elastic_rules.ndjson` | Elastic EQL | Elastic SIEM |
| `0a749b39-409e-46f5-9338-ee886b439cfa_dr_rules.yaml` | LimaCharlie D&R | LC tenants |

**Deploy at minimum these three high-fidelity rules**:

1. **thinking_robot_log.txt creation** — should never fire in a clean baseline; every hit should be investigated.
2. **VBScript written to Startup folder by non-installer** — rare enough in modern baselines that a small allow-list makes this high-fidelity.
3. **Killchain correlation** — 2+ of the PROMPTFLUX-signal buckets within a 5-minute window.

The remaining rules (GitHub-raw fetch, wscript staging, wmic logicaldisk) produce some baseline noise; tune parent-process and user filters against your fleet before promoting them to alerting rules.

---

## 3. Response

### 3.1 Containment checklist

If detection fires on a host:

1. **Isolate** the host from the network (EDR live-response / Defender ASR isolation / LimaCharlie `contain`).
2. **Collect** before remediation:
   - `c:\F0\*` — the full PROMPTFLUX artefact set (dropper, markers, logs)
   - `%TEMP%\thinking_robot_log.txt` — Gemini API raw response (contains prompt metadata and token counts)
   - Any `.vbs` in user Startup folders
   - `c:\F0\stage4_propagation_targets.json` — target list the operator had
   - Memory dump of any suspicious process with `.vbs` on its command line
3. **Hunt** for propagation: check the enumerated target drives from the propagation_targets file for copies of the dropper under non-standard names.
4. **Identify the operator channel**: the gemini_response.json URL points to the attacker-controlled staging CDN — get the URL, IP, and TLS fingerprint from `stage1_network.log` / network telemetry and consider blocking at the perimeter.

### 3.2 Remediation

1. Remove all three file classes:
   - Dropper: `c:\F0\crypted_ScreenRec_webinstall.vbs` (and any copies on enumerated targets)
   - Staging log: `%TEMP%\thinking_robot_log.txt`
   - Persistence: `<any Startup folder>\ScreenRecUpdater.vbs`
2. Scheduled tasks were not used by PROMPTFLUX v1, but confirm with `schtasks /query /fo LIST /v | find /i "wscript"`.
3. Reboot and confirm no Startup VBS fires (the persistence hook only activates at next logon — a between-collection reboot is the cleanest confirmation).

### 3.3 Attribution / next steps

PROMPTFLUX is currently unattributed. The defining IOC for attribution collaboration with GTIG / threat-intel partners is the full URL / IP set used for the Gemini-shaped response fetch — share that (not the Gemini API endpoint itself, which is legitimate Google infrastructure).

---

## 4. Exercise / Tabletop

Run this F0RT1KA test on a sacrificial endpoint paired with your SIEM / EDR
to validate that:

1. At least one of the three high-fidelity detection rules above fires.
2. The killchain correlation rule fires at stage 4 (all 4 signals are present by then).
3. Your EDR either blocks the wscript invocation at stage 1 (exit 126) or the Startup-folder write at stage 3 (exit 126). If it does neither, the test exits 101 (`Unprotected`) and the report tells you exactly which stage was not defended.

The test cleans itself up on every exit path. No manual cleanup is required
unless the test crashes between stage 3 (Startup drop) and the cleanup defer —
in which case remove `<APPDATA>\Microsoft\Windows\Start Menu\Programs\Startup\ScreenRecUpdater.vbs` manually before the next user logon.

---

## 5. Platform-Specific Hardening

Accompanying this document:

- `0a749b39-409e-46f5-9338-ee886b439cfa_hardening.ps1` — Windows hardening script with WSH disable, ASR rule enable, Startup-folder FIM, and AppLocker rule stubs. Run elevated.

---

## 6. References

- GTIG — PROMPTFLUX disclosure, November 2025 (see `_references.md` for canonical URL)
- MITRE ATT&CK — T1071.001, T1027.001, T1547.001, T1091
- Microsoft Docs — Attack Surface Reduction Rules reference
- Microsoft Docs — Disabling WSH via registry (KB2268596, archived)

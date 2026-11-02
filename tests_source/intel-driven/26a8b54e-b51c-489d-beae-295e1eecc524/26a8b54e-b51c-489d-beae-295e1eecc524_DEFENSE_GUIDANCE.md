# Defense Guidance: Lumma-Style Infostealer — Browser Credential Theft via Process Injection

## Executive Summary

This document provides defense, hardening, and incident-response guidance for the **LummaC2 (Lumma Stealer) / Water Kurita** infostealer kill chain emulated by F0RT1KA test `26a8b54e-b51c-489d-beae-295e1eecc524`. It is written for financial-institution CISOs, SOC leads, and desktop-engineering teams. Lumma is the dominant infostealer of 2024–26: a Russian-speaking malware-as-a-service (from ~USD 250/month) with roughly **394,000 infections across two law-enforcement takedowns**, rebuilt infrastructure, and continued ClickFix delivery campaigns through 2026. StealC and Vidar share the same chain — controls built against this playbook cover the class.

Infostealers are not ransomware. The objective is **silent collection and exfiltration in minutes**: browser-stored passwords, session cookies (which bypass MFA entirely), autofill data, crypto-wallet stores, KeePass databases, and 2FA-extension seeds — followed by HTTP POST exfiltration to rotating Cloudflare-fronted C2s. For a bank, the direct outcomes are account takeover of internal and customer credentials, payment fraud, and a reportable data breach — often without any visible endpoint disruption. **Every stage of the emulated chain is detectable with native telemetry**; the question this test answers is whether your stack actually sees it.

**Key findings the kill chain evaluates:**

1. **Delivery is social engineering on the clipboard (ClickFix).** A fake-CAPTCHA page tells the user to press Win+R and paste — the page has already poisoned the clipboard with a hidden encoded PowerShell download cradle (recent variants abuse `wt.exe`; older chains use `mshta.exe` → VBScript → PowerShell). No exploit is needed: the user runs the stager for the attacker. User training plus LOLBin execution controls are the only stage-1 defenses.
2. **The stealer runs under a browser-named process.** Recent Lumma builds copy themselves as `MicrosoftEdgeUpdate.exe` and remote-thread inject into `chrome.exe` — collection then happens inside a trusted, browser-adjacent process. Behavioral detection of cross-process injection (`VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, thread-context hijacking) into browser binaries is the highest-value stage-2 control.
3. **Browser credential stores are the crown jewels.** Lumma copies the locked SQLite databases (`Login Data`, `Network\Cookies`, `Web Data`), unwraps the DPAPI-protected master key from `Local State` via `CryptUnprotectData`, and decrypts the AES-256-GCM `v10` blobs — the exact same primitives a legitimate browser uses. App-Bound Encryption (Chrome/Edge 127+) forces the stealer into a noisy COM-elevation bypass against the browser's `elevation_service` — a detection gift **if** you watch for it. KeePass `.kdbx`, Gecko `key4.db`/`logins.json`, and wallet/2FA extension directories are collected whole.
4. **Stolen cookies are stolen sessions.** Password rotation alone does not remediate a Lumma compromise — cookie and token theft means the attacker holds authenticated sessions that MFA has already satisfied. Session invalidation and conditional-access re-evaluation are mandatory IR steps.
5. **Exfiltration has a signature.** The C2 channel uses a hardcoded `TeslaBrowser/5.5` User-Agent, the `/c2sock` URI, an `act=live` handshake, `LID`/`J` form parameters, and a fingerprint probe before upload — all visible at the proxy. Egress filtering plus these indicators give you a deterministic network tripwire.

**Priority recommendations:** disable browser password storage enterprise-wide (Chrome/Edge `PasswordManagerEnabled=0` policy) and deploy an enterprise password manager with hardware-backed MFA/passkeys; keep browsers current so App-Bound Encryption is in force; deploy EDR behavioral rules for cross-process injection into browser binaries and for non-browser reads of `Login Data`/`Local State`/`CryptUnprotectData`; block/alert on ClickFix LOLBins (`mshta` URL invocation, hidden `-EncodedCommand` PowerShell); alert on `TeslaBrowser/5.5` and `/c2sock` at the proxy; and pre-build the credential/session-rotation IR runbook — an infostealer incident is a rotation race, not a rebuild. The companion script `26a8b54e-b51c-489d-beae-295e1eecc524_hardening.ps1` implements the endpoint-local subset idempotently with rollback.

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | 26a8b54e-b51c-489d-beae-295e1eecc524 |
| **Test Name** | Lumma-Style Infostealer: Browser Credential Theft via Process Injection |
| **MITRE ATT&CK** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1055.003](https://attack.mitre.org/techniques/T1055/003/), [T1555.003](https://attack.mitre.org/techniques/T1555/003/), [T1555](https://attack.mitre.org/techniques/T1555/), [T1005](https://attack.mitre.org/techniques/T1005/), [T1041](https://attack.mitre.org/techniques/T1041/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| **Severity** | High |
| **Threat Actor** | LummaC2 / Water Kurita (Lumma Stealer, [MITRE S1213](https://attack.mitre.org/software/S1213); Microsoft tracks the operator as Storm-2477). Representative of the Lumma / StealC / Vidar MaaS class. |
| **Subcategory** | Infostealer / Credential Theft |
| **Platform** | Windows endpoint |
| **Context** | Dominant MaaS infostealer 2024–26; ClickFix/fake-CAPTCHA delivery; ~394K infections across two takedowns; rebuilt infrastructure and 64-bit "Remus" variant through 2026 |

### Emulated Kill Chain (as implemented in the test)

| Stage | Objective | Simulated Behaviors |
|-------|-----------|---------------------|
| 1 | ClickFix delivery | Real campaign-shaped cradle string written to the clipboard via `SetClipboardData`; execution as `powershell.exe -WindowStyle Hidden -EncodedCommand` with a WebClient download cradle; secondary `mshta.exe http://` fetch variant (T1204.002 / T1059.001) |
| 2 | Process injection | Self-copies staged as `MicrosoftEdgeUpdate.exe` (injector) and `chrome.exe` (decoy host) — the documented EdgeUpdate→chrome pattern; `OpenProcess → VirtualAllocEx(RWX) → WriteProcessMemory → CreateRemoteThread` with PEB-walking shellcode, then thread execution hijacking (`OpenThread → SuspendThread → GetThreadContext → SetThreadContext → ResumeThread`) (T1055.003) |
| 3 | Browser credential theft | Copy of locked SQLite stores; `Local State` → `os_crypt.encrypted_key` → `CryptUnprotectData` (DPAPI) → AES-256-GCM `v10` decryption of `Login Data`/`Cookies`; `Web Data` autofill; wholesale collection of KeePass `.kdbx`, Gecko `logins.json`/`key4.db`, wallet + 2FA extension dirs; App-Bound-Encryption bypass attempt via COM activation of the browser elevation service (`IElevator::DecryptData`) (T1555.003 / T1555) |
| 4 | Collection & exfiltration | In-memory zip staging; fingerprint probe GET; `act=live` handshake POST; multipart upload with hardcoded `TeslaBrowser/5.5` User-Agent to `/c2sock` with `LID`/`hwid` form parameters (T1005 / T1041 / T1071.001) |

## MITRE ATT&CK Mapping

| Technique | Tactic | Applicable Mitigations |
|-----------|--------|------------------------|
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) — User Execution: Malicious File | Execution | [M1017](https://attack.mitre.org/mitigations/M1017/) User Training (ClickFix awareness), [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention (mshta/wt.exe controls), [M1021](https://attack.mitre.org/mitigations/M1021/) Restrict Web-Based Content |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) — PowerShell | Execution | [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention (AppLocker/WDAC/Constrained Language Mode), [M1047](https://attack.mitre.org/mitigations/M1047/) Audit (Script Block Logging), [M1042](https://attack.mitre.org/mitigations/M1042/) Disable or Remove Feature or Program |
| [T1055.003](https://attack.mitre.org/techniques/T1055/003/) — Process Injection: Thread Execution Hijacking | Defense Evasion | [M1040](https://attack.mitre.org/mitigations/M1040/) Behavior Prevention on Endpoint (EDR injection detection), [M1038](https://attack.mitre.org/mitigations/M1038/) Execution Prevention (WDAC blocks user-writable-path binaries), [M1026](https://attack.mitre.org/mitigations/M1026/) Privileged Account Management (standard-user least privilege) |
| [T1555.003](https://attack.mitre.org/techniques/T1555/003/) — Credentials from Web Browsers | Credential Access | [M1027](https://attack.mitre.org/mitigations/M1027/) Password Policies (disable browser storage, enterprise password manager), [M1051](https://attack.mitre.org/mitigations/M1051/) Update Software (App-Bound Encryption in current Chrome/Edge), [M1048](https://attack.mitre.org/mitigations/M1048/) Application Isolation and Sandboxing, [M1047](https://attack.mitre.org/mitigations/M1047/) Audit (credential-store access telemetry) |
| [T1555](https://attack.mitre.org/techniques/T1555/) — Credentials from Password Stores | Credential Access | [M1027](https://attack.mitre.org/mitigations/M1027/) Password Policies, [M1041](https://attack.mitre.org/mitigations/M1041/) Encrypt Sensitive Information, [M1053](https://attack.mitre.org/mitigations/M1053/) Data Backup (KeePass/database hygiene) |
| [T1005](https://attack.mitre.org/techniques/T1005/) — Data from Local System | Collection | [M1047](https://attack.mitre.org/mitigations/M1047/) Audit (file-access telemetry on credential/wallet paths), [M1026](https://attack.mitre.org/mitigations/M1026/) Privileged Account Management |
| [T1041](https://attack.mitre.org/techniques/T1041/) — Exfiltration Over C2 Channel | Exfiltration | [M1037](https://attack.mitre.org/mitigations/M1037/) Filter Network Traffic (egress filtering, proxy allowlists), [M1031](https://attack.mitre.org/mitigations/M1031/) Network Intrusion Prevention, [M1021](https://attack.mitre.org/mitigations/M1021/) Restrict Web-Based Content |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) — Web Protocols | Command and Control | [M1037](https://attack.mitre.org/mitigations/M1037/) Filter Network Traffic, [M1020](https://attack.mitre.org/mitigations/M1020/) SSL/TLS Inspection, [M1015](https://attack.mitre.org/mitigations/M1015/) Domain Blocking (newly registered / Cloudflare-fronted rotation) |

## Hardening Recommendations

### Quick Wins (Immediate — Low Impact)

1. **Disable browser password storage enterprise-wide** via Chrome/Edge policy (`PasswordManagerEnabled=0`) and deploy an approved enterprise password manager. This single control empties the `Login Data` target the entire stage-3 chain depends on. Implemented in the companion script.
2. **Enforce browser auto-update** (Chrome/Edge update policies, `UpdateDefault` forced). App-Bound Encryption (Chrome/Edge 127+) wraps the v20 key at SYSTEM scope and forces stealers into the noisy COM-elevation bypass — but only if browsers are current.
3. **Enable PowerShell Script Block + Module Logging** (4104/4103): the encoded-command cradle, the `WebClient`/`Invoke-WebRequest` download, and AMSI contexts all surface here. Implemented in the companion script.
4. **Enable process command-line auditing** (4688 with `ProcessCreationIncludeCmdLine_Enabled=1`) — required to see `powershell -w hidden -enc`, `mshta http://`, and updater-masquerade process names.
5. **ASR rules in Block mode** — verified-GUID set implemented in the companion script:
   - `5beb7efe-fd9a-4556-801d-275e5ffc04cc` — Block execution of potentially obfuscated scripts (hits the encoded cradle)
   - `d4f940ab-401b-4efc-aadc-ad5f3c50688a` — Block all Office applications from creating child processes (adjacent delivery vectors)
   - `9e6c4e1f-7d60-472a-bbaa-a39f66977d63` — Block credential stealing from LSASS (general credential-access hygiene for the same actor class)
6. **Defender cloud-delivered protection, sample submission, PUA, and network protection ON** — network protection is what lets web-content indicators (fake-CAPTCHA pages) fire in real time. Implemented in the companion script.
7. **Constrain the ClickFix LOLBins**: block `mshta.exe` URL invocation and hidden `-EncodedCommand` PowerShell for standard users via AppLocker/WDAC (enterprise control), with the per-user `DisallowRun` fallback for `mshta` implemented in the companion script. Note `wt.exe` (Windows Terminal) is legitimately used — control via WDAC script rules, not blanket blocking.

### Medium-Term (1–2 Weeks — Medium Impact)

1. **EDR behavioral detection for browser injection** (stage 2): cross-process `VirtualAllocEx`+`CreateRemoteThread` or thread-context rewrite targeting `chrome.exe`/`msedge.exe`/updater binaries, and RWX allocation inside browser processes. Most modern EDRs ship this — verify it is enabled and not tuned to silent.
2. **File-access telemetry on credential stores** (stage 3): alert when a process other than the browser binaries reads `%LOCALAPPDATA%\Google\Chrome\User Data\...\Login Data`, `Local State`, `Network\Cookies`, or calls `CryptUnprotectData` on browser key material; alert on `Local Extension Settings` bulk reads (wallet/2FA harvest). Sysmon EID 1/10/11 or EDR file sensors.
3. **ABE-bypass tripwire**: alert on COM activation of `elevation_service.exe` by non-browser callers (Sysmon EID 1 with `Elevation:Administrator!new:` or the elevator CLSIDs `{708860E0-F641-4611-8895-7D867DD3675B}` / `{1FCBE96C-1697-43AF-9140-2897C7C69767}` on the command line of public PoC tooling).
4. **Egress filtering + C2 indicators** (stage 4): proxy alert/block on `TeslaBrowser/5.5` User-Agent, `/c2sock` URI, `act=live` + `LID` form patterns; treat newly-registered and bulk-Cloudflare-fronted domains from endpoints as suspicious; consider forcing all endpoint egress through the authenticated proxy.
5. **Session hygiene**: shorten web-session TTLs for internal apps, deploy token-binding/conditional-access device compliance so stolen cookies replay poorly, and document the per-application "invalidate all sessions" procedure for IR.
6. **KeePass and wallet policy**: prohibit `.kdbx` storage on endpoints outside approved encrypted stores; prohibit browser wallet extensions (MetaMask et al.) and hot wallets on corporate endpoints by extension blocklist policy (`ExtensionInstallBlocklist`).
7. **Deception grid**: deploy canary browser profiles (decoy `Login Data` with honeytoken credentials) wired to P1 alerts — near-zero false positives, fires at stage-3 first touch.

### Strategic (1–3 Months — Requires Planning)

1. **WDAC or enforced AppLocker** application control: signed/approved binaries only, no execution from user-writable paths — this kills the `MicrosoftEdgeUpdate.exe` self-copy masquerade and the ClickFix downloader outright.
2. **Passkeys / FIDO2 phish-resistant MFA** for internal and customer high-value flows, with device-bound credentials — reduces the replay value of both stolen passwords and stolen cookies.
3. **Enterprise secret management**: vault-based credential workflows so no credentials ever live in a browser profile; integrate SSO so `Login Data` stores stay empty by construction.
4. **DLP + CASB**: classify credential/wallet file patterns (`Login Data`, `key4.db`, `.kdbx`, extension dirs) for egress inspection; block unsanctioned archive-upload sequences.
5. **Fraud-analytics integration**: stolen customer and operator credentials surface as fraud, not as security alerts — connect infostealer IOC feeds to the fraud-monitoring pipeline for immediate watch-listing.
6. **Continuous adversary-emulation**: rerun this Lumma chain after every control change; track per-stage block rates (delivery / injection / credential theft / exfil) as the board-level KPI for credential-theft readiness.

## Hardening Scripts

> **Note:** Only scripts for the test's target platform(s) are included. This is a Windows-endpoint test — no Linux/macOS scripts are provided.

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `26a8b54e-b51c-489d-beae-295e1eecc524_hardening.ps1` | Idempotent PowerShell hardening with `-WhatIf` preview and `-Undo` rollback (state captured in `%ProgramData%\LummaDefenseHardening`) |

The script is production-ready and tool-agnostic: it contains **no references to the test, its paths, or its binaries** — every control targets the underlying technique (browser password-storage policy, ASR, PowerShell logging, mshta constraints, command-line auditing, Defender cloud/network protection), so it protects against any actor using the same playbook. Enterprise policy delivery (GPO/Intune) is preferred over local execution where available.

## Incident Response Playbook

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| ClickFix encoded cradle | 4688: `powershell.exe` with `-WindowStyle Hidden` + `-enc`/`-EncodedCommand` and parent `explorer.exe` (Run dialog) or `cmd.exe`; 4104 script-block decode showing `WebClient`/`Invoke-WebRequest` download | High | P1 |
| mshta remote fetch | 4688/Sysmon EID 1: `mshta.exe` with an `http(s)://` argument | High | P1 |
| Updater masquerade | Process named `MicrosoftEdgeUpdate.exe`/`GoogleUpdate.exe` executing from a user-writable path (`%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, profile dirs) rather than `Program Files` | High | P1 |
| Browser injection | EDR behavioral: `VirtualAllocEx`+`WriteProcessMemory`+`CreateRemoteThread` into `chrome.exe`/`msedge.exe`; `SetThreadContext` RIP rewrite on another process; RWX allocation inside a browser process | High | P1 |
| Credential-store access | Sysmon EID 11/1: non-browser process creating copies of `Login Data`, `Network\Cookies`, `Web Data`; reads of `Local State` followed by `CryptUnprotectData`; SQLite open of copied browser DBs | High | P1 |
| KeePass/Gecko/wallet harvest | EID 11: `.kdbx`, `key4.db`, `logins.json`, `Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn` accessed by non-browser processes | High | P1 |
| ABE bypass attempt | COM activation of `elevation_service.exe` by non-browser caller; `CoSetProxyBlanket` dynamic-cloaking patterns; elevator CLSIDs on tool command lines | Medium-High | P2 |
| LummaC2 channel | Proxy: `TeslaBrowser/5.5` User-Agent; `/c2sock` URI; `act=live` + `LID` form POST; fingerprint GET then multipart upload burst from one host | High | P1 |
| Bulk staging + upload | In-memory/mass archive creation followed immediately by outbound POST to a newly-registered domain; DNS/HTTP to Cloudflare-fronted rotating infrastructure | Medium | P2 |

### Containment (First 15 Minutes — assume exfiltration already occurred)

- [ ] **Isolate the host immediately** — MDE/Falcon isolate or NIC cut. Infostealers complete collection and exfiltration in minutes; by detection time the data is likely gone. Isolation stops second-stage payload delivery (Lumma loaders commonly deliver additional malware).
- [ ] **Snapshot volatile evidence before remediation**: process list, network connections, browser-profile last-write timestamps:
  ```powershell
  Get-Process | Export-Clixml C:\IR\processes.xml
  Get-NetTCPConnection | Export-Csv C:\IR\netconn.csv
  Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Include 'Login Data','Local State','Cookies' |
      Select-Object FullName,LastWriteTime | Export-Csv C:\IR\browser-stores.csv
  ```
- [ ] **Identify the C2 destination** from proxy telemetry (destination domain/IP, first-seen time) and block/sinkhole it fleet-wide.
- [ ] **Do NOT assume a clean scan means safety** — Lumma is memory-resident after injection; the on-disk footprint is minimal. Isolation and rotation, not AV sweeps, are the response.

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Browser stores (timestamps) | `%LOCALAPPDATA%\{Google\Chrome,Microsoft\Edge}\User Data\...\{Login Data, Local State, Network\Cookies, Web Data}` | Export file listings + LastWriteTime; copy stores for offline inspection (they evidence the theft scope) |
| Extension stores | `...\Default\Local Extension Settings\` | Inventory directories (wallet/2FA extensions present = expanded rotation scope) |
| KeePass / Gecko | Profile dirs, `*.kdbx`, `logins.json`, `key4.db` | `Get-ChildItem -Path C:\Users -Recurse -Include *.kdbx,key4.db,logins.json -ErrorAction SilentlyContinue \| Export-Csv C:\IR\secret-stores.csv` |
| Security + PowerShell logs | System | `wevtutil epl Security C:\IR\Security.evtx; wevtutil epl Microsoft-Windows-PowerShell/Operational C:\IR\PS-Operational.evtx` |
| EDR telemetry | Console | Timeline around first detection: process tree (cradle → injector → browser), injection events, DPAPI calls |
| Proxy/NetFlow | Proxy/SIEM | Filter: host + `TeslaBrowser/5.5`, `/c2sock`, destination domain; establish exfil window and volume |
| Prefetch / AmCache | System | `copy C:\Windows\Prefetch\*.pf C:\IR\prefetch\` — evidence of `mshta`/`powershell`/masqueraded binaries |

### Eradication

- Terminate the injected browser processes and masqueraded updater binaries (`MicrosoftEdgeUpdate.exe` outside `Program Files`); delete staged payload copies from user-writable paths.
- Verify the real browser installations are clean ( binaries under `Program Files` with valid signatures) — the stealer impersonates, not infects, the browser.
- Remove any follow-on payloads delivered by the loader (Lumma MaaS bundles often include additional downloaders — review post-exfil process creations).
- Reset the local machine's DPAPI context only as a last resort (it invalidates user-encrypted data); document before doing so.

### Recovery — the rotation runbook (this is the core of infostealer IR)

- [ ] **Rotate every credential that could have been in the browser profile**: internal apps, SSO, email, social/media, cloud consoles — assume the full `Login Data` set is compromised.
- [ ] **Invalidate all sessions, not just passwords**: stolen cookies are pre-authenticated sessions. Force global sign-out / refresh tokens per application; for customer-facing sessions, force re-authentication wave.
- [ ] **Re-enroll 2FA** for any account whose 2FA-extension seed or recovery codes could have been harvested; treat TOTP seeds in browser extensions as compromised.
- [ ] **Assess wallet exposure**: if any wallet extension store was present, treat keys/seed phrases as compromised and move funds (this is why corporate endpoints should not hold hot wallets).
- [ ] **KeePass databases**: rotate every credential inside any `.kdbx` that touched the endpoint (collection is wholesale; cracking happens off-host).
- [ ] **Feed fraud monitoring**: watch-list accounts whose credentials were in scope; the attack surface shifts from IT to fraud ops.
- [ ] **Regulatory notification**: evaluate data-breach obligations — exfiltrated browser stores contain customer credentials and PII.
- [ ] Re-baseline with the companion hardening script and rerun the emulation to confirm per-stage visibility improved.

### Post-Incident

1. Which stage produced the first alert — delivery, injection, credential theft, or exfil? Which stages produced none?
2. Was the C2 channel (`TeslaBrowser/5.5`, `/c2sock`) visible at the proxy, and was anyone alerting on it before the incident?
3. How much of the browser profile was populated in the first place? (Empty `Login Data` stores would have made stage 3 moot — measure policy adoption.)
4. Did ABE hold (browser current) and did the COM-elevation attempt generate telemetry?
5. What was detection-to-isolation time versus the exfil window (goal: P1 → isolation < 15 min, accepting the exfil race is usually lost)?
6. Which hardening-script controls would have flipped the test from 101 (unprotected) to 126 (prevented), and what is the rollout plan/date for each?

## References

- MITRE ATT&CK: techniques listed above; software entry [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213)
- NCC Group: [Fake CAPTCHA Attack Leads to Lumma Malware](https://www.nccgroup.com/research/fake-captcha-led-to-lumma) (EdgeUpdate→chrome remote-thread injection)
- Netskope Threat Labs: [Lumma Stealer: Fake CAPTCHAs & New Techniques to Evade Detection](https://www.netskope.com/blog/lumma-stealer-fake-captchas-new-techniques-to-evade-detection)
- Microsoft Security Blog: [Lumma Stealer — delivery techniques and capabilities](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer) (Storm-2477, C2 infrastructure)
- ESET WeLiveSecurity: [ESET takes part in global operation to disrupt Lumma Stealer](https://www.welivesecurity.com/en/eset-research/eset-takes-part-global-operation-disrupt-lumma-stealer) (C2 protocol: `act=live`, LID/J, hardcoded UA)
- Darktrace: [The Rise of MaaS & Lumma Info Stealer](https://www.darktrace.com/blog/the-rise-of-the-lumma-info-stealer) (`TeslaBrowser/5.5`, `/c2sock`)
- Seqrite: [Fake CAPTCHA Delivers Lumma Stealer](https://www.seqrite.com/blog/fake-captcha-lures-victims-lumma-stealer-abuses-clipboard-and-powershell) (mshta→VBScript→PowerShell chain)
- Gen Digital: [Remus — 64-bit variant of Lumma Stealer](https://www.gendigital.com/blog/insights/research/remus-64bit-variant-of-lumma-stealer)
- xaitax: [Chrome-App-Bound-Encryption-Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) (IElevator COM interface research)
- Picus Security: [Red Report 2025](https://www.picussecurity.com/resource/blog/red-report-2025-3x-rise-in-credential-theft) (T1055 #1, T1555 #3 prevalence)
- Microsoft Learn: [ASR rules reference](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference), [Chrome/Edge browser policy cloud docs for PasswordManagerEnabled](https://chromeenterprise.google/policies/#PasswordManagerEnabled)

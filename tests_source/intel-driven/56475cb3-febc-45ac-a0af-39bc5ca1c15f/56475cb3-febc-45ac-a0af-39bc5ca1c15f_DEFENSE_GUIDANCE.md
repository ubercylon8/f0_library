# Defense Guidance: 3CX 3CXDesktopApp Cascading Supply-Chain Compromise

- **Test ID:** `56475cb3-febc-45ac-a0af-39bc5ca1c15f`
- **MITRE ATT&CK:** T1195.002, T1574.002, T1497, T1027.003, T1071.001, T1555.003, T1217
- **Threat Actor:** Lazarus / UNC4736 (DPRK)
- **Platform:** Windows endpoint
- **Severity:** Critical

## 1. Threat Overview

In March 2023, the DPRK-nexus actor Lazarus (tracked as UNC4736) trojanized the
**validly code-signed** `3CXDesktopApp` VoIP client at the vendor's build
pipeline and shipped it to customers as a routine update. It was the first
widely-documented **cascading** supply-chain compromise: a prior breach of
Trading Technologies (X_TRADER) was used to breach 3CX, whose signed product
then breached 3CX's own customers.

The defensive challenge is that **every artifact the endpoint sees is trusted**:
a signed parent process, a normal-looking DLL, and HTTPS to GitHub. Signature-
and reputation-based controls do not fire. Detection must focus on the
**anomalous behavior of a trusted binary**, not on a known-bad hash.

### Attack chain modeled by this test

| Stage | Technique | Behavior |
|-------|-----------|----------|
| 1 | T1574.002 | Signed parent (3CXDesktopApp) side-loads `d3dcompiler_47.dll` / `ffmpeg.dll` from a user-writable app directory. |
| 2 | T1497 | Sandbox/VM fingerprint + ~7-day dormancy before beaconing. |
| 3 | T1027.003 / T1071.001 | Fetches `*.ico` from `raw.githubusercontent.com` (IconStorages repo); AES-encrypted C2 config is appended **after** the legitimate icon image and decoded locally. |
| 4 | T1555.003 / T1217 | ICONIC stealer collects browser credential/history stores (Chrome/Edge/Brave/Firefox). |

## 2. Detection Strategy

Detection artifacts shipped with this test (all technique-focused, not test-artifact-focused):

- `56475cb3-febc-45ac-a0af-39bc5ca1c15f_detections.kql` — Microsoft Sentinel / Defender XDR
- `56475cb3-febc-45ac-a0af-39bc5ca1c15f_sigma_rules.yml` — vendor-agnostic Sigma
- `56475cb3-febc-45ac-a0af-39bc5ca1c15f_elastic_rules.ndjson` — Elastic EQL
- `56475cb3-febc-45ac-a0af-39bc5ca1c15f_dr_rules.yaml` — LimaCharlie D&R
- `56475cb3-febc-45ac-a0af-39bc5ca1c15f_rules.yar` — YARA (file/artifact scanning)

### Highest-value detections

1. **Signed binary loads a non-system DLL from its own writable directory**
   (T1574.002). The single most reliable signal — a trusted parent resolving
   `d3dcompiler_47.dll` / `ffmpeg.dll` from `%LOCALAPPDATA%` / an app dir rather
   than `System32` or `Program Files`.
2. **Non-browser process reading multiple browser credential stores**
   (T1555.003). Benign apps read only their own store; a stealer walks them all.
3. **Non-browser process resolving/fetching `.ico` from `raw.githubusercontent.com`**
   (T1071.001 / T1027.003). Correlate with an ICO file that has high-entropy
   data appended past the declared icon image (YARA `ICO_Steganography_*`).
4. **Correlation** — any two of the above on one host within ~30 min should
   escalate to Critical (see KQL Query 6).

## 3. Hardening

Apply `56475cb3-febc-45ac-a0af-39bc5ca1c15f_hardening.ps1` (run as admin). It is
idempotent and reports current posture before changing anything. Key controls:

### Supply-chain / trusted-binary risk
- Maintain an **allowlist (WDAC / AppLocker)** that pins vendor apps to their
  signed install path so a trojanized update or a relocated copy running from a
  user-writable directory is blocked.
- Subscribe to vendor security advisories and threat-intel feeds; be prepared to
  **revoke trust in a vendor certificate** quickly when a build-pipeline breach
  is disclosed.

### DLL side-loading (T1574.002)
- Enable **Microsoft Defender ASR rule** "Block executable files from running
  unless they meet a prevalence, age, or trusted list criterion" and
  "Block untrusted and unsigned processes that run from USB" where applicable.
- Set `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode = 1`.
- Deny write + execute on application directories for standard users; separate
  writable data dirs from executable-code dirs.

### C2 / steganography (T1071.001 / T1027.003)
- Route egress through a **TLS-inspecting proxy**; alert on non-browser processes
  fetching `.ico`/asset files from code-hosting CDNs.
- Scan downloaded/stored `.ico` files for trailing data past the icon image
  (YARA rule provided).

### Browser credential theft (T1555.003)
- Enable Chrome/Edge **App-Bound Encryption** so credential blobs cannot be
  decrypted outside the browser process context.
- Deploy an EDR file-access rule denying non-browser processes read access to
  `Login Data` / `key4.db` / `logins.json`.
- Prefer enterprise SSO / passwordless where possible to reduce the value of
  browser-stored credentials.

### Sandbox-evasion resilience (T1497)
- Ensure detonation sandboxes randomize uptime, user artifacts, and delay-aware
  execution so long-dormancy implants still detonate under analysis.

## 4. Incident Response Playbook

### Phase 1 — Triage & Scope
1. Confirm the alerting process and its **signer**. A *signed* vendor binary
   loading an untrusted DLL is the hallmark — do not dismiss because it is signed.
2. Pull the loaded DLL path(s). If `d3dcompiler_47.dll` / `ffmpeg.dll` (or any
   companion DLL) resolved from a user-writable directory, treat as confirmed
   side-load.
3. Identify the software vendor and version; cross-check against known
   supply-chain compromise advisories for that product.

### Phase 2 — Contain
1. **Network-isolate** the host via EDR.
2. Block egress to the observed C2 / CDN paths at the proxy/firewall.
3. If the trojanized product is enterprise-wide, **quarantine the vendor version
   fleet-wide** (WDAC deny rule on the affected file hashes/signer) — assume all
   installs of that version are compromised.

### Phase 3 — Eradicate
1. Remove the trojanized application and all side-loaded DLLs; reinstall a
   known-good version only after vendor confirmation.
2. Hunt for persistence dropped after the beacon (run keys, scheduled tasks,
   services) and secondary payloads.
3. **Rotate all credentials accessible from affected browsers** (T1555.003 means
   assume browser-stored credentials are stolen), plus any session cookies.

### Phase 4 — Recover & Report
1. Restore from clean images where eradication confidence is low.
2. Reset browser credential stores; force re-authentication.
3. Report to the vendor and relevant authorities; preserve the trojanized binary
   and ICO artifacts for forensics.

### Phase 5 — Lessons Learned
- Validate that WDAC/AppLocker path-pinning and browser App-Bound Encryption
  were in place; close gaps.
- Re-run this test after remediation to confirm the detections fire.

## 5. Validation

Re-run `56475cb3-febc-45ac-a0af-39bc5ca1c15f.exe` on a protected host and confirm:
- Stage 1 raises a signed-binary side-load alert.
- Stage 3 raises GitHub `.ico` egress + (if scanned) ICO-stego YARA hit.
- Stage 4 raises browser-credential-collection alerts.
A protected endpoint should interrupt the chain (test exit code 126/105); an
unprotected endpoint completes all four stages (exit 101).

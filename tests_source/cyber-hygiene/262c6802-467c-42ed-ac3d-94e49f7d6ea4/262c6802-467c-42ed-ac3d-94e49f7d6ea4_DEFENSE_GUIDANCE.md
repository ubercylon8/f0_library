# Defense Guidance: eMudhra Compromised CA Trust Exposure Assessment

## Executive Summary

Eight eMudhra intermediate CA private keys—six for TLS and two for code signing—were compromised through weak key generation. An attacker who can redirect or intercept traffic can use a fraudulent certificate to impersonate a service, read or modify TLS traffic, and steal credentials. The code-signing keys can make malicious content appear legitimately signed. Direct eMudhra chains, Sectigo `AAA Certificate Services` cross-signs, and key-rollover paths must all be considered.

**The primary remediation is supported vendor updates for every actual OS, runtime, application, appliance, and container trust path.** Do not respond by removing every eMudhra certificate. Blocking the eight compromised intermediates and their eight cross-signed representations is distinct from the later decision to remove additional roots. Microsoft removed seven certificates associated with the affected hierarchies in October and announced removal of the remaining eMudhra roots starting November 16, 2026; that broader root-trust change must be planned and tested separately.

The accompanying scripts provide an **optional, explicit local mitigation**, not a substitute for vendor servicing:

- Windows imports the exact 16 affected intermediate certificates into `LocalMachine\Disallowed`, covering Schannel and Authenticode without removing roots.
- Linux uses exact intermediate blocklists on p11-kit systems. On Debian/Ubuntu, the interim fallback distrusts `emSign ECC Root CA - G3`; distrusting `AAA Certificate Services` is a separate, explicitly acknowledged compatibility-impacting option.

Never disable TLS or signature verification to suppress post-remediation certificate errors.

## Threat Overview

| Field | Value |
|---|---|
| **Test ID** | `262c6802-467c-42ed-ac3d-94e49f7d6ea4` |
| **Test Name** | eMudhra Compromised CA Trust Exposure Assessment |
| **MITRE ATT&CK** | [T1557 — Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/), [T1553.002 — Subvert Trust Controls: Code Signing](https://attack.mitre.org/techniques/T1553/002/) |
| **Tactics** | Credential Access, Defense Evasion |
| **Severity** | Critical |
| **Threat Actor** | N/A — compromised CA key material, not an actor-specific campaign |
| **Platforms** | Windows and Linux endpoints; independently bundled runtimes and applications |

The [incident disclosure](https://emudhra.we-have-a-problem.com/) reports that the keys were recoverable from certificates created in April 2025. Browser blocking does not protect every non-browser client, and Certificate Transparency enforcement is not universal. [Cisco Talos](https://blog.talosintelligence.com/compromised-intermediate-certificates/) highlights exposure in VPNs, gateways, CI/CD, package managers, embedded systems, and applications with stale trust bundles. [Cloudflare](https://blog.cloudflare.com/emudhra-certificate-compromise) similarly emphasizes validating the verification path beneath each SDK rather than assuming an OS or browser update protects every application.

### Exact affected certificate inventory

SHA-256 below is the fingerprint of the DER-encoded certificate. Both rows for an intermediate are required: the same compromised public key appears in direct and cross-signed certificates with different serial numbers and fingerprints.

| Usage | Intermediate | Issuer | Serial (hex) | Certificate SHA-256 |
|---|---|---|---|---|
| TLS | EM DV TLS CA - G3B | emSign Root TLS CA - G3 | `A4AEE678F23362B4C0E460B772F214` | `42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493` |
| TLS | EM DV TLS CA - G3B | AAA Certificate Services | `A024FDF4BA665C785CE4A020483858B7` | `45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE` |
| TLS | EM OV TLS CA - G3B | emSign Root TLS CA - G3 | `6CADA367FB1C100088120EA202D568` | `98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B` |
| TLS | EM OV TLS CA - G3B | AAA Certificate Services | `E94223BDE92F914E5AB9ACABFDAC3710` | `5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699` |
| TLS | EM EV TLS CA - G3B | emSign Root TLS CA - G3 | `C7C41EFE92D825F05EAE841A4A82C1` | `E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838` |
| TLS | EM EV TLS CA - G3B | AAA Certificate Services | `D8F8685E4F2BD9D82402A85A1C1EB731` | `579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512` |
| TLS | EM DV TLS CA - G3C | emSign Root TLS CA - G3 | `588B2E3C2BB8CDA13E1A1209254321` | `0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19` |
| TLS | EM DV TLS CA - G3C | AAA Certificate Services | `91F347F1A5B7D39962B95E0EE4E299D1` | `62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72` |
| TLS | EM OV TLS CA - G3C | emSign Root TLS CA - G3 | `296926C227A3A1526392B19482A504` | `CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F` |
| TLS | EM OV TLS CA - G3C | AAA Certificate Services | `8D5A4811939EF447D77111CDD9849AE9` | `7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489` |
| TLS | EM EV TLS CA - G3C | emSign Root TLS CA - G3 | `8009928A64107601AF05FA2F19F109` | `432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3` |
| TLS | EM EV TLS CA - G3C | AAA Certificate Services | `05F078752DECE7A1BB8595D303167171` | `FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F` |
| Code signing | EM OV CS CA - G3B | emSign Root CS CA - G3 | `7818933F8F85B4619A2B35FBA83D0A` | `9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4` |
| Code signing | EM OV CS CA - G3B | AAA Certificate Services | `41E32B73AC185D6CE0D7480BACF84E69` | `A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8` |
| Code signing | EM OV CS CA - G3C | emSign Root CS CA - G3 | `544B7F922C31AE220A4A922916F6E6` | `4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1` |
| Code signing | EM OV CS CA - G3C | AAA Certificate Services | `D6A5EF613B390F32EF9CDF349F772841` | `84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD` |

Relevant chain anchors in the incident assets are `emSign Root TLS CA - G3` (`7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D`), `emSign Root CS CA - G3` (`F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5`), rollover/cross-signer `emSign ECC Root CA - G3` (`86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B`), and `AAA Certificate Services` (`D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4`). These identifiers are for dependency mapping; their presence alone does not prove acceptance of a compromised intermediate.

## MITRE ATT&CK Mapping

| Technique | Tactic | Applicable mitigations and defensive interpretation |
|---|---|---|
| [T1557 — Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) | Credential Access | **M1041 — Encrypt Sensitive Information:** maintain authenticated TLS, but recognize that encryption without sound certificate validation is insufficient. **M1037 — Filter Network Traffic** and **M1031 — Network Intrusion Prevention:** restrict unnecessary interception/redirection paths and inspect alerts. **M1030 — Network Segmentation:** limit an attacker's ability to position between clients and services. |
| [T1553.002 — Subvert Trust Controls: Code Signing](https://attack.mitre.org/techniques/T1553/002/) | Defense Evasion | **M1045 — Code Signing:** enforce signature validation while maintaining trusted-root, disallowed-certificate, and revocation state. A valid cryptographic signature is not sufficient when its issuing hierarchy is compromised. |

The immediate technique-specific controls are timely trust-store updates, exact intermediate distrust, application-path validation, and replacement of organization-owned dependent certificates. Network segmentation and intrusion prevention are useful compensating controls, not substitutes for remediating trust.

## Hardening Recommendations

### Quick Wins (Immediate — Low Impact)

1. **Keep Windows automatic certificate trust updates enabled.** Permit the Windows automatic certificate trust update endpoint through controlled egress. Do not disable AuthRoot auto-update or restore removed roots merely to avoid an application error. Microsoft published the Disallowed Certificate Trust List update on October 20 and the October 26 out-of-band update; the November 10 cumulative update also carries the earlier removals for disconnected devices. See the [Microsoft response](https://www.microsoft.com/en-us/msrc/blog/2026/10/microsoft-response-to-compromised-emudhra-certificate-authority-keys).
2. **Service disconnected Windows devices explicitly.** Import the October 26 OOB package or November 10 cumulative update through the approved offline servicing process, and distribute the current Disallowed CTL through the organization's disconnected-root-update mechanism. Do not infer CTL freshness from the OS build alone.
3. **Update Edge and WebView2 components.** Allow Edge component updates and check **PKI Metadata** in `edge://components`; update WebView2 Runtime through its supported component/update channel. Microsoft states that the compromised-intermediate blocks were delivered separately from a full browser version upgrade.
4. **Install distribution `ca-certificates` updates.** Use the vendor security channel for Debian/Ubuntu, RHEL-family, SUSE, Arch, Alpine, or the deployed distribution. Refresh generated bundles and restart or reload consumers. Do not hand-edit generated bundle files because the next update can overwrite the change.
5. **Update independent runtimes and packages.** Prioritize Node.js, Python `certifi`, pip's vendored `certifi`, Java, curl CA bundles, Electron applications, and container base images. Updating only pip does not prove every virtual environment is fixed; updating only the OS does not fix a bundled runtime.
6. **Inventory application overrides.** Review `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `NODE_EXTRA_CA_CERTS`, Java `javax.net.ssl.trustStore`, application-specific CA files, and TLS-inspection proxy configuration. An added root or custom bundle can bypass the path that was patched.

### Medium-Term (1–2 Weeks — Medium Impact)

1. **Map real trust paths.** For each service, record the executable/interpreter, loaded HTTP/TLS library, effective CA file or OS store, revocation behavior, container image, and restart requirement. Include Java keystores, Node's built-in roots, Python virtual environments, pip, curl, Electron applications, proxies, VPNs, and build agents.
2. **Replace organization-owned dependent certificates.** Inventory public and private certificates chaining to the affected direct, AAA cross-signed, or rollover hierarchies. Obtain replacement leaf and intermediate chains from a trusted issuer, deploy complete replacement chains, and schedule consumers to reload them. Do not restore trust in an affected hierarchy as a compatibility shortcut.
3. **Rebuild Java trust deliberately.** Prefer an updated Java runtime. [Adoptium's Temurin guidance](https://adoptium.net/en-GB/news/2026/10/temurin-october-2026-emudhra) lists fixed October releases and confirms that Temurin uses Mozilla CA data. On Debian/Ubuntu, `ca-certificates-java` may not refresh `/etc/ssl/certs/java/cacerts` after either a package fix or a manual root change. Back up the keystore, recreate it with the distribution procedure, and restart Java consumers; preserve locally added enterprise CAs.
4. **Rebuild and redeploy containers and bundled applications.** Update base-image CA packages and language dependencies, rebuild images, and redeploy. Electron applications need a release built on a patched Electron version; updating the host browser is insufficient.
5. **Use the optional local scripts only as a controlled bridge.** Run check mode first, test in a representative ring, retain backups, and monitor TLS and Authenticode compatibility. Vendor updates remain the desired end state.

### Strategic (1–3 Months — Requires Planning)

1. Establish centralized ownership and update SLAs for every non-OS trust store, including appliance firmware and long-lived build images.
2. Add trust-path inventory and compromised-chain validation to image build, endpoint compliance, and application release gates.
3. Preserve package lockfile hashes, artifact signatures, provenance checks, and application allowlisting as independent supply-chain controls; do not rely solely on TLS or publisher identity.
4. Monitor certificate-chain and trust-store drift, unexpected local root additions, disabled revocation/verification settings, and repeated validation failures after remediation.
5. Plan Microsoft's separately announced remaining-root removals starting November 16 as a distinct compatibility project. Identify dependencies before the automatic Windows and Edge/WebView2 changes arrive.

## Hardening Scripts

Only the test's target platforms are included. Both scripts are offline in check mode, require elevated privileges, make no change without an explicit apply switch, are idempotent, and retain rollback state. Neither script installs vendor updates, disables certificate verification, nor removes every eMudhra certificate.

| Platform | Script | Optional mitigation and rollback |
|---|---|---|
| Windows | `262c6802-467c-42ed-ac3d-94e49f7d6ea4_hardening.ps1` | Imports all 16 exact intermediate variants into `LocalMachine\Disallowed`; undo removes only entries added by the script. |
| Linux | `262c6802-467c-42ed-ac3d-94e49f7d6ea4_hardening_linux.sh` | Uses exact intermediate blocklists on p11-kit systems; Debian/Ubuntu root fallback is explicitly scoped. Undo restores only script-owned changes. |

### Windows usage

Run from an elevated PowerShell 5.1+ session. The process-only execution-policy setting does not alter machine policy.

```powershell
# Read-only local audit; no network requests
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\262c6802-467c-42ed-ac3d-94e49f7d6ea4_hardening.ps1 -Check

# Optional exact-intermediate mitigation; backs up state before changing the store
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\262c6802-467c-42ed-ac3d-94e49f7d6ea4_hardening.ps1 -Apply

# Preview without changing the store
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\262c6802-467c-42ed-ac3d-94e49f7d6ea4_hardening.ps1 -Apply -WhatIf

# Roll back only certificates previously added by this script
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\262c6802-467c-42ed-ac3d-94e49f7d6ea4_hardening.ps1 -Undo -Apply
```

State and certificate backups are under `%ProgramData%\emudhra-ca-trust-hardening`. Existing Microsoft or administrator-created Disallowed entries are treated as pre-existing and are **not** removed by undo. The mitigation covers Windows chain consumers, including Schannel TLS and Authenticode; independent Java, Node, Python, pip, curl, Electron, proxy, and container stores still require their own updates.

### Linux usage

Run as root. Check mode performs no external network calls and does not rewrite trust configuration.

```bash
# Read-only local audit
sudo ./262c6802-467c-42ed-ac3d-94e49f7d6ea4_hardening_linux.sh --check

# Apply the supported exact-intermediate blocklist on p11-kit systems
sudo ./262c6802-467c-42ed-ac3d-94e49f7d6ea4_hardening_linux.sh --apply

# Debian/Ubuntu fallback: also distrust AAA Certificate Services
# WARNING: this can break unrelated sites and services that still chain to AAA.
sudo ./262c6802-467c-42ed-ac3d-94e49f7d6ea4_hardening_linux.sh --apply \
  --include-aaa --acknowledge-aaa-impact

# Explicitly rebuild Debian/Ubuntu Java cacerts after backing it up
sudo ./262c6802-467c-42ed-ac3d-94e49f7d6ea4_hardening_linux.sh --apply \
  --rebuild-java-cacerts

# Roll back only script-owned changes
sudo ./262c6802-467c-42ed-ac3d-94e49f7d6ea4_hardening_linux.sh --undo --apply
```

On p11-kit systems, all 16 affected intermediate variants are placed in the distribution blocklist and the normal trust generator is run. No root is removed, including AAA. On Debian/Ubuntu, the default fallback prefixes only `mozilla/emSign_ECC_Root_CA_-_G3.crt` with `!` in `/etc/ca-certificates.conf`; `--include-aaa --acknowledge-aaa-impact` additionally excludes `mozilla/Comodo_AAA_Services_root.crt`. **Without the AAA option, the Debian/Ubuntu fallback does not locally distrust the AAA cross-signed path.** Use distribution updates and validate every affected runtime rather than treating partial fallback coverage as complete remediation.

The Java rebuild option is limited to `/etc/ssl/certs/java/cacerts` and `update-ca-certificates --fresh`. Back up and recreate any locally added enterprise CAs as part of the change. Runtime/application updates remain necessary even after a system store change.

Rollback records and backups are under `/var/lib/emudhra-ca-trust-hardening` and `/var/backups/emudhra-ca-trust-hardening`. Undo refuses to overwrite a file that an administrator changed after the script's apply operation; reconcile that drift manually from the retained backup.

## Incident Response Playbook

### Detection Triggers

These are investigation cues, not stand-alone proof of compromise.

| Trigger | Criteria | Confidence | Priority |
|---|---|---|---|
| Compromised chain accepted | An actual application accepts a chain containing any listed SPKI or certificate fingerprint | High | P1 |
| Unexpected eMudhra/AAA chain | TLS telemetry shows an affected intermediate for a service that should use another issuer | High when chain evidence is retained | P1 |
| Suspicious signed content | Authenticode validation or captured signature chain contains either compromised code-signing intermediate | High | P1 |
| Trust configuration drift | Auto-update is disabled, a removed root is restored, a custom CA bundle appears, or verification is disabled | Medium; investigate origin and intent | P2 |
| Post-update certificate failures | Failures begin after trust updates and affect services with dependent certificate chains | Medium for compatibility exposure, not attack proof | P2 |

### Containment (First 15 Minutes)

- [ ] Isolate a host only when there is evidence of active interception, forged signed content, or malicious execution; do not disrupt every endpoint merely because an unpatched trust store is found.
- [ ] Suspend the affected TLS-consuming job or signed-content execution path while preserving its configuration and logs.
- [ ] Block the affected network path at a controlled proxy or network enforcement point when active interception is suspected. Preserve the redirect/DNS/proxy evidence before changing it.
- [ ] Revoke sessions and rotate credentials or tokens that may have traversed a confirmed intercepted connection. Use a known-good host and network path.
- [ ] Quarantine suspected forged signed files by hash for analysis; do not trust publisher display names.

### Evidence Collection

Collect the actual certificate chain and effective runtime configuration, not just a browser result.

| Artifact | Location / method | Example command |
|---|---|---|
| Windows affected-store entries | LocalMachine Disallowed and AuthRoot configuration | `Get-ChildItem Cert:\LocalMachine\Disallowed; Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' -ErrorAction SilentlyContinue` |
| Windows file signature and chain | Preserve the file, signature status, signer, and chain | `Get-AuthenticodeSignature -LiteralPath '<file>' | Format-List *` |
| Windows servicing evidence | Installed updates and Edge/WebView2 component inventory | `Get-HotFix; Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients' -ErrorAction SilentlyContinue` |
| Linux trust configuration | Distribution bundle, p11-kit anchors/blocklists, CA configuration | `trust list; update-ca-trust dump 2>/dev/null; cat /etc/ca-certificates.conf 2>/dev/null` |
| Runtime trust paths | Java, Node, Python, pip, curl versions and effective CA paths | `java -version; node --version; python3 -c 'import certifi; print(certifi.where())'; pip --version; curl --version` |
| Network evidence | DNS answers, proxy/VPN logs, packet capture, observed peer chain, timestamps, destination and client identity | Export through the existing network sensor/proxy console; preserve original logs and packet captures |
| Application evidence | Environment variables, service unit/launcher, loaded runtime, container image digest, CA-file contents | Record configuration read-only before restarting or rebuilding |

Hash collected executables and CA bundles, preserve timestamps, and record the user/service account under which the application ran. A test under an administrator's personal runtime does not establish the service account's trust path.

### Investigation: Possible MITM or Forged Signed Content

1. Reproduce the chain from retained telemetry or a controlled capture and compare certificate SHA-256 and SPKI SHA-256 against the incident inventory.
2. Determine whether interception was possible through DNS manipulation, proxy/VPN policy, routing, Wi-Fi/LAN position, or a deliberately installed enterprise inspection root.
3. Identify data sent during the suspect session: credentials, cookies, tokens, package downloads, source code, updates, and signed installers. Distinguish encrypted-but-unauthenticated exposure from a mere failed handshake.
4. Search for executions or downloads associated with the suspect session and verify independent artifact hashes/provenance. A valid signature alone does not clear content chained to a compromised code-signing CA.
5. Review whether the application checked revocation, consumed Windows Disallowed/CRLSet or another rapid blocklist, enforced CT, or used a static CA bundle. Record the exact verifier behavior rather than inferring it from the OS patch level.

### Eradication and Recovery

- [ ] Apply supported OS/runtime/application updates to every identified trust path.
- [ ] Remove unauthorized restored roots, custom bundles, or verification-bypass settings only after preserving evidence and identifying their owner.
- [ ] Replace organization-owned certificates chaining to affected hierarchies; deploy the full new chain and reload dependent services.
- [ ] Rebuild Java `cacerts` where required, rebuild container/Electron/application bundles, and restart or redeploy consumers.
- [ ] Rotate exposed secrets and revoke active sessions when interception is confirmed or strongly suspected.
- [ ] Restore normal networking only after the malicious redirection/interception mechanism is removed and ordinary trusted TLS connections succeed.

### Validate Remediation with the Test

1. Run the supplied read-only, loopback-only assessment on the remediated host under the same execution context used for the original finding.
2. Review every applicable control rather than only the overall exit code:
   - `CH-EMC-001`: native direct eMudhra G3 TLS chains.
   - `CH-EMC-002`: native Sectigo AAA cross-signed TLS chains.
   - `CH-EMC-003`: native key-rollover chains.
   - `CH-EMC-004` on Windows: Authenticode code-signing intermediates.
   - `CH-EMC-010` through `CH-EMC-015`: discovered Node, Java, Python default, Python `certifi`, pip-vendored `certifi`, and curl paths.
3. A compliant control requires **every tested compromised chain to be rejected with certificate-validation evidence**. Any accepted chain is exposed. An inconclusive result is not a pass; diagnose the runtime/probe error and rerun. A skipped runtime is not assessed.
4. Repeat the assessment for separately installed or service-account runtimes, custom application bundles, and rebuilt container images. PATH discovery does not certify undiscovered runtimes, custom applications, proxies, or containers.
5. Perform positive compatibility tests against ordinary trusted HTTPS services and known-good signed software. Remediation is complete only when compromised chains fail and legitimate chains still succeed.

### Post-Incident

1. Which actual trust paths were exposed, and how were they discovered?
2. Was any credential, token, package, or executable delivered across a confirmed intercepted session?
3. How long did OS, runtime, application, and container updates take to reach each path?
4. Did any team disable verification or restore broad root trust as a workaround, and has that exception been removed?
5. What inventory, update SLA, or release-gate change would prevent recurrence?

## References

- [eMudhra compromise disclosure, affected assets, patched-version inventory, and interim guidance](https://emudhra.we-have-a-problem.com/)
- [Microsoft response to compromised eMudhra certificate authority keys](https://www.microsoft.com/en-us/msrc/blog/2026/10/microsoft-response-to-compromised-emudhra-certificate-authority-keys)
- [Cloudflare: eMudhra certificate compromise](https://blog.cloudflare.com/emudhra-certificate-compromise)
- [Cisco Talos: compromised intermediate certificates](https://blog.talosintelligence.com/compromised-intermediate-certificates/)
- [Adoptium: October 2026 Temurin releases and eMudhra guidance](https://adoptium.net/en-GB/news/2026/10/temurin-october-2026-emudhra)
- [MITRE ATT&CK T1557 — Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [MITRE ATT&CK T1553.002 — Subvert Trust Controls: Code Signing](https://attack.mitre.org/techniques/T1553/002/)

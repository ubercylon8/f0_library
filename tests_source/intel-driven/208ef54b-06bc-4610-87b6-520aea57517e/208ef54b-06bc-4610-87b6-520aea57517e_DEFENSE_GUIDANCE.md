# Defense Guidance — ScreenConnect Unsanctioned RMM Abuse for Third-Party Access

- **Test UUID:** `208ef54b-06bc-4610-87b6-520aea57517e`
- **Techniques:** T1199 (Trusted Relationship), T1219 (Remote Access Software), T1543.003 (Windows Service), T1567.002 (Exfiltration to Cloud Storage)
- **Threat actor:** Black Basta (RMM abuse; mass-exploited post CVE-2024-1709)
- **Platform:** Windows endpoint
- **Primary source:** CISA/NSA/MS-ISAC AA23-025A — *Protecting Against Malicious Use of Remote Monitoring and Management Software*

---

## 1. The defensive problem (trust inheritance)

ConnectWise ScreenConnect is a **legitimate, vendor-signed** RMM tool. Attackers
(access brokers, Black Basta and other ransomware crews) install a signed vendor
agent to obtain durable, encrypted, often allow-listed remote access that blends
into normal IT operations — "living off trusted software."

The detection objective is therefore **NOT** to block the ScreenConnect binary by
hash or signer (that breaks sanctioned IT usage and produces noise). It is to flag
the **anomalous install + service creation + relay + follow-on exfil of an
UNSANCTIONED RMM**. Every control below is governance/behavior based, not a vendor
block.

**Central control: maintain an authoritative inventory of your sanctioned RMM tools
and the specific instances (relay hosts / instance-ids) they use.** Anything outside
that allow-list is the signal.

---

## 2. Kill chain and detection opportunities

| Stage | Technique | Behavior | Best detection surface |
|-------|-----------|----------|------------------------|
| 1 | T1219 | `msiexec /qn` silent install of the ScreenConnect agent | Process creation: `msiexec.exe` + silent flag + ScreenConnect/ConnectWise package |
| 2 | T1543.003 | Windows service `ScreenConnect Client (<instance-id>)` created & started | Service install events: System 7045 / Security 4697 |
| 2 | T1219 | Agent relay egress to the ScreenConnect relay | Network: `ScreenConnect.ClientService.exe` → `*.screenconnect.com:443/8041` |
| 3 | T1567.002 | Collect data + upload to cloud storage over the foothold | File-create of archive by/under the agent + upload egress |

The strongest single detection is **Stage 2 service creation** — the instance-id in
the service name uniquely ties the endpoint to an external ScreenConnect instance.

---

## 3. Preventive controls (hardening)

Apply via `208ef54b-06bc-4610-87b6-520aea57517e_hardening.ps1` (run as Administrator).

1. **Application control (WDAC / AppLocker) with RMM allow-listing.**
   Permit only your sanctioned RMM (by publisher AND product/instance where
   possible); deny all other RMM agents. The desired outcome when this test runs
   against a hardened host is `msiexec` returning **1625 (ERROR_INSTALL_PACKAGE_REJECTED
   — forbidden by system policy)** — the test classifies that as a genuine block.
2. **Restrict `msiexec` silent installs by non-IT accounts.** Alert on / deny
   interactive-user-initiated silent MSI installs of remote-access packages.
3. **Service-creation monitoring.** Ensure System 7045 and (audit-policy) Security
   4697 are collected; alert on service names matching `ScreenConnect Client (*`.
4. **Egress governance.** From endpoints without a sanctioned RMM, block/alert
   outbound connections to RMM relay domains (`*.screenconnect.com`,
   `relay.screenconnect.com`) at the proxy/firewall.
5. **DLP / cloud-storage egress monitoring** for large archive uploads from
   endpoints, especially originating under an RMM agent process tree.
6. **Patch the initial-access vector.** ScreenConnect self-hosted servers must be
   patched for CVE-2024-1709 (auth bypass) / CVE-2024-1708; this is a primary way
   attackers gain the ability to push agents in the first place.

---

## 4. Detection rules shipped with this test

| Format | File |
|--------|------|
| Microsoft Sentinel / Defender KQL | `208ef54b-06bc-4610-87b6-520aea57517e_detections.kql` |
| YARA | `208ef54b-06bc-4610-87b6-520aea57517e_rules.yar` |
| Sigma | `208ef54b-06bc-4610-87b6-520aea57517e_sigma_rules.yml` |
| Elastic EQL | `208ef54b-06bc-4610-87b6-520aea57517e_elastic_rules.ndjson` |
| LimaCharlie D&R | `208ef54b-06bc-4610-87b6-520aea57517e_dr_rules.yaml` |

All are technique-focused. Before enabling any **responsive** action, add your
sanctioned-RMM allow-list (instance-id, relay host, deploy account) as a filter so
legitimate IT usage is not disrupted.

---

## 5. Incident Response Playbook

### Trigger
An alert fires for an unsanctioned ScreenConnect install, a `ScreenConnect Client (*`
service creation, or agent relay egress on a host not authorized for ScreenConnect.

### Phase 1 — Verify & scope (first 15 min)
1. Confirm ScreenConnect is **not** your sanctioned RMM on this host (check the RMM
   inventory / allow-list).
2. Identify the **instance-id** from the service name `ScreenConnect Client (<id>)`
   and the relay host from the agent config / network logs. The instance-id maps to
   the attacker's ScreenConnect instance.
3. Determine install time and initiating account (from the msiexec process event) —
   pivot to how the account/session was obtained (initial access).

### Phase 2 — Contain
4. **Isolate the host** (EDR network containment) to cut the relay session.
5. Block the relay host/instance at the proxy/firewall for the whole environment;
   hunt for the same instance-id on other endpoints (attacker reuse).

### Phase 3 — Eradicate
6. Stop and delete the service(s): `sc stop "ScreenConnect Client (<id>)"` then
   `sc delete`. Uninstall the agent (`msiexec /x` or Win32_Product uninstall).
   The bundled `cleanup_utility.exe` performs all of this.
7. Remove install/data directories: `C:\Program Files (x86)\ScreenConnect Client (*`,
   `C:\ProgramData\ScreenConnect Client (*`.

### Phase 4 — Assess impact & recover
8. Review Stage-3-style activity: what data was **collected/staged/archived**, and
   whether any **cloud-storage upload** succeeded. Scope potential data theft.
9. If collection/exfil occurred or the session was interactive, **rotate
   credentials** exposed on the host and any that the operator could have harvested.
10. Patch/verify the ScreenConnect server (CVE-2024-1709) if self-hosted; review how
    the operator authenticated to push the agent.

### Phase 5 — Lessons learned
11. Add the observed relay host/instance-id to blocklists and detections.
12. Close the gap that allowed an unsanctioned RMM install (application control /
    RMM governance) so `msiexec` is rejected by policy next time.

---

## 6. Notes on this test's safety scaffolding (not IOCs)

The F0RT1KA test uses **unreachable RFC 2606 `.invalid`** relay/exfil hosts and a
`c:\Users\fortika-test\shared_finance_export` decoy path with clearly-synthetic
`*_DECOY` files. These are **test scaffolding for lab validation only** — do not
promote them to production IOCs. The production signals are the behaviors in
sections 2–3.

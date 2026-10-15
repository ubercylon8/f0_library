# Defense Guidance: Kothamine Tailcat Encrypted C2 Channel and Data Exfiltration

## Executive Summary

Kothamine is an unattributed RAT distributed through malicious npm packages. Its
defining evasion trait is that it routes command-and-control and data
exfiltration through **tailcat** — Tailscale's control-plane-less,
WireGuard-encrypted netcat — instead of attacker-registered C2 domains. All
traffic is encrypted, NAT-traversing, and carried over Tailscale's legitimate
internet DERP relay infrastructure, so conventional domain/IP blocklists, TLS
inspection, and reputation feeds never see a destination worth blocking. Some
Kothamine builds download tailcat directly from the official GitHub releases at
runtime and expose an **unauthenticated SSH shell** reachable from anywhere on
the internet, then move files in and out with `tailcat cp` (scp/SFTP over the
encrypted tunnel).

This test reproduces that killchain end-to-end on Windows and Linux:

1. **Stage 1 (T1105)** — downloads the pinned tailcat v0.7.0 binary from the
   official GitHub releases and executes it.
2. **Stage 2 (T1572 / T1021.004)** — launches `tailcat serve no-auth-ssh`: an
   unauthenticated SSH shell on the endpoint, reachable from the internet
   through DERP relays with no Tailscale account, no control plane, and no open
   inbound firewall port. A loopback client proves shell access.
3. **Stage 3 (T1005 / T1041)** — stages synthetic decoy user data and
   exfiltrates it over the encrypted DERP tunnel to a drop-box receiver.

**Priority recommendations:**

1. Where Tailscale is not a sanctioned tool, block and alert on egress to
   Tailscale DERP relay infrastructure and tailcat tooling (this kills the
   entire channel — no DERP, no C2).
2. Prevent unsigned/unapproved executables from running out of user-writable,
   non-standard paths (WDAC/AppLocker, ASR executable-prevalence rule).
3. Harden the npm supply chain (the delivery vehicle): `ignore-scripts`,
   lockfile-only installs, dependency auditing, private registry with a
   quarantine window.
4. Deploy the five detection-content formats shipped with this test so that
   even a successful tunnel is *seen*.

## Threat Overview

| Field | Value |
|-------|-------|
| **Test ID** | c37d6a01-3934-4e72-9cb1-3dae284b937b |
| **Test Name** | Kothamine Tailcat Encrypted C2 Channel and Data Exfiltration |
| **MITRE ATT&CK** | [T1105](https://attack.mitre.org/techniques/T1105/), [T1572](https://attack.mitre.org/techniques/T1572/), [T1021.004](https://attack.mitre.org/techniques/T1021/004/), [T1005](https://attack.mitre.org/techniques/T1005/), [T1041](https://attack.mitre.org/techniques/T1041/) |
| **Severity** | High |
| **Threat Actor** | Kothamine (unattributed) |
| **Platforms** | Windows, Linux |
| **Delivery Vector** | Malicious npm packages (supply chain) |
| **C2 Transport** | WireGuard (userspace) over Tailscale DERP relays; no account or control plane required |
| **Source** | Microsoft Threat Intelligence OSINT profile (2026-09-28); Malwarebytes write-up; [tailcat GitHub](https://github.com/tailscale/tailcat) |

### Why this evades conventional controls

- **No attacker infrastructure to block.** The endpoint reaches only Tailscale's
  DERP relays (`derp*.tailscale.com` and regional relay hostnames) and, at
  bootstrap, the DERP map endpoint (`tailcat.dev/derpmap.json` /
  `login.tailscale.com` ecosystem). These are legitimate SaaS destinations with
  clean reputations.
- **Encryption is end-to-end.** WireGuard keys are ephemeral per session; there
  is no TLS session to intercept and no certificate anomaly to flag.
- **No inbound port.** DERP relays NAT-traverse; host firewalls see outbound
  UDP/443 (or HTTPS fallback) only.
- **The shell needs no credential.** `tailcat serve no-auth-ssh` treats the
  ephemeral `tc…` address as the only credential — there is no authentication
  log, no failed-login signal, and no account to disable.
- **Tooling is legitimate and signed.** tailcat ships from the official
  tailscale GitHub org; hash- and signature-based allowlists built on "known
  good" publishers must treat it as a dual-use tool, not malware.

## MITRE ATT&CK Mapping

| Technique | Tactic | Applicable Mitigations |
|-----------|--------|------------------------|
| [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) | Command and Control | [M1031 — Network Intrusion Prevention](https://attack.mitre.org/mitigations/M1031/) |
| [T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/) | Command and Control | [M1031 — Network Intrusion Prevention](https://attack.mitre.org/mitigations/M1031/), [M1037 — Filter Network Traffic](https://attack.mitre.org/mitigations/M1037/) |
| [T1021.004 — Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/) | Lateral Movement | [M1035 — Limit Access to Resource Over Network](https://attack.mitre.org/mitigations/M1035/), [M1042 — Disable or Remove Feature or Program](https://attack.mitre.org/mitigations/M1042/), [M1030 — Network Segmentation](https://attack.mitre.org/mitigations/M1030/), [M1018 — User Account Management](https://attack.mitre.org/mitigations/M1018/), [M1032 — Multi-factor Authentication](https://attack.mitre.org/mitigations/M1032/) |
| [T1005 — Data from Local System](https://attack.mitre.org/techniques/T1005/) | Collection | No preventive mitigation in ATT&CK — detection and DLP-centric (M1057 as compensating control) |
| [T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Exfiltration | [M1031 — Network Intrusion Prevention](https://attack.mitre.org/mitigations/M1031/), [M1037 — Filter Network Traffic](https://attack.mitre.org/mitigations/M1037/), [M1057 — Data Loss Prevention](https://attack.mitre.org/mitigations/M1057/) |

Microsoft's recommended mitigations for Kothamine specifically (per the
2026-09-28 TI guidance): enable **cloud-delivered protection** in Microsoft
Defender, turn on **PUA protection in block mode**, enable the ASR rules
**"Block executable files from running unless they meet a prevalence, age, or
trusted list criterion"** and **"Block execution of potentially obfuscated
scripts"**, enforce **MFA everywhere**, audit **software supply-chain
dependencies**, and apply **least privilege**.

## Hardening Recommendations

### Quick Wins (Immediate — Low Impact)

1. **Defender feature switches (Windows).** Enable cloud-delivered protection
   (MAPS "Advanced"), PUA protection in **block** mode, real-time monitoring,
   and network protection. The Windows hardening script shipped with this test
   applies all four idempotently.
2. **ASR rules (Windows).** Enable in block mode:
   - *Block executable files from running unless they meet a prevalence, age,
     or trusted list criterion* (`01443614-cd74-433a-b99e-2ecdc07bfc25`) —
     directly counters a freshly-downloaded tailcat binary executing from a
     non-standard path.
   - *Block execution of potentially obfuscated scripts*
     (`5beb7efe-fd9a-4556-801d-275e5ffc04cc`) — counters npm install-script and
     loader stagers.
   Pilot in audit mode first on developer fleets; these rules can false-positive
   on legitimate newly-released tooling.
3. **Command-line and process auditing (both platforms).** Windows: enable
   process creation auditing (Event ID 4688) *with command line*. Linux: ship
   the auditd rules in the hardening script (execution of `tailcat`/`tailscaled`,
   `ssh`/`scp` children spawned by non-service parents, downloads landing in
   temp/user-writable paths).
4. **Alert on DERP-relay egress where Tailscale is unsanctioned.** At the
   proxy/DNS layer, alert (not necessarily block yet) on resolution of or
   connection to `*.tailscale.com` DERP relay hostnames, `tailcat.dev`, and the
   DERP map endpoint. Any hit on a fleet that has no sanctioned Tailscale
   deployment is a high-fidelity lead.
5. **npm developer hygiene (the delivery vector).** Set
   `ignore-scripts=true` in the global `/etc/npmrc` (Linux script does this) and
   user `.npmrc`; require `npm ci` against reviewed lockfiles in CI.

### Medium-Term (1–2 Weeks — Medium Impact)

1. **Application control for non-standard paths.** Deploy WDAC or AppLocker
   rules that deny execution of unsigned binaries from user-writable locations
   (`%TEMP%`, `%LOCALAPPDATA%`, `C:\ProgramData` subdirectories, user profile
   roots; `/tmp`, `/var/tmp`, `/dev/shm`, `$HOME` on Linux). tailcat is
   legitimate, signed-by-publisher tooling — the control that works is
   *where it runs from and who approved it*, not its hash.
2. **Egress policy on tunneling infrastructure.** If Tailscale is not
   sanctioned, block outbound to Tailscale DERP relay ranges/hostnames and
   `login.tailscale.com`/`tailcat.dev` at the perimeter, and treat the block
   events as detection signal (a host *attempting* the tunnel is already
   interesting). If Tailscale *is* sanctioned, restrict it to your tailnet's ACL
   policy and alert on DERP-map fetches from hosts without a managed tailscaled.
3. **npm supply-chain controls.** Route all installs through a private
   registry/proxy (e.g. Artifactory/Nexus/GitHub Packages) with a quarantine
   window for newly published package versions; run `npm audit`/Socket/OSV
   scanning in CI; pin and review lockfile changes in pull requests.
4. **Deploy the shipped detection content.** Import the five rule formats from
   this test directory into your stack (see *Detection Content Deployment*
   below): KQL for Defender XDR/Sentinel, Sigma for your SIEM, YARA for
   file-scanning, EQL/NDJSON for Elastic, and LimaCharlie D&R rules.
5. **SSH attack-surface hygiene.** Where inbound SSH is not required, disable
   or remove the OpenSSH server feature (Windows optional feature) and `sshd`
   (Linux). Note that tailcat's no-auth-ssh does **not** need the system sshd —
   it is its own server — so this step reduces parallel exposure, not the
   primary tunnel; the primary control is egress filtering + application
   control above.

### Strategic (1–3 Months — Requires Planning)

1. **Default-deny egress for endpoints.** Move endpoint VLANs from "allow all
   outbound" to an allowlisted egress model (proxy-mediated). tailcat/DERP
   survives because endpoints can reach arbitrary UDP/443 and HTTPS
   destinations; default-deny egress collapses the entire class of
   tunnel-over-legitimate-SaaS C2.
2. **Encrypted-tunnel analytics at the network layer.** WireGuard-over-DERP has
   recognizable shape (long-lived UDP/443 flows to Tailscale relay anycast
   ranges, DERP TLS fallback with relay hostnames). Feed Zeek/netflow to your
   SIEM and baseline which hosts ever speak to tunnel SaaS (Tailscale, ngrok,
   Cloudflare Tunnel, Teleport) — deviations are the durable detection when
   content inspection is impossible.
3. **MFA everywhere + least privilege.** Kothamine's operator commands run with
   the compromised user's privileges; phishing-resistant MFA and removing local
   admin limit both initial access (npm social engineering often follows
   credential theft) and what the RAT can stage.
4. **Developer-workstation isolation.** Treat engineering endpoints as a
   high-risk segment: separate egress policy, no direct access to production
   data stores, and mandatory private-registry mediation for all package
   ecosystems (npm, PyPI, Go modules).

## Hardening Scripts

> Only scripts for this test's target platforms (Windows and Linux) are
> included. Both are idempotent, require admin/root, and support rollback.
> They harden against the *technique class* (unsigned binaries in non-standard
> paths, tunneling-tool egress, unauthenticated remote shells, npm
> supply-chain compromise) — not against this test's artifacts.

| Platform | Script | Description |
|----------|--------|-------------|
| Windows | `c37d6a01-3934-4e72-9cb1-3dae284b937b_hardening.ps1` | Defender cloud/PUA/network protection, ASR rules, 4688 command-line auditing, AppLocker audit-mode baseline, unsanctioned-tunnel egress guidance. `-Undo` / `-WhatIf` supported. |
| Linux | `c37d6a01-3934-4e72-9cb1-3dae284b937b_hardening_linux.sh` | auditd execution/download monitoring, npm supply-chain hardening (`ignore-scripts`, lockfile enforcement), egress chain alerting on Tailscale/DERP destinations, noexec mounts guidance. `--undo` / `--check` supported. |

## Detection Content Deployment

The companion detection rules (generated by the sectest-detection-rules agent)
live alongside this document and target the same behaviors from the sensor side:

| File | Format | Deploy To |
|------|--------|-----------|
| `c37d6a01-3934-4e72-9cb1-3dae284b937b_detections.kql` | KQL | Microsoft Defender XDR Advanced Hunting / Microsoft Sentinel analytics rules |
| `c37d6a01-3934-4e72-9cb1-3dae284b937b_sigma_rules.yml` | Sigma | Convert with `sigma convert` for your SIEM (Splunk, Sentinel, Elastic, etc.) |
| `c37d6a01-3934-4e72-9cb1-3dae284b937b_rules.yar` | YARA | EDR file-scanning module, Velociraptor, or `yara -r` sweeps on suspected hosts |
| `c37d6a01-3934-4e72-9cb1-3dae284b937b_elastic_rules.ndjson` | Elastic Security (EQL) | Import via Kibana → Security → Rules → Import |
| `c37d6a01-3934-4e72-9cb1-3dae284b937b_dr_rules.yaml` | LimaCharlie D&R | `limacharlie org add` / paste into the D&R rule editor |

Deployment order of operations: (1) Sigma/KQL process-creation rules first —
they catch `tailcat serve`/`tailcat recv` command lines regardless of binary
name; (2) network rules for DERP egress; (3) YARA for the tailcat binary
itself on disk; (4) LimaCharlie D&R for real-time response actions on monitored
endpoints.

## Incident Response Playbook

### Detection Triggers

| Detection Name | Criteria | Confidence | Priority |
|----------------|----------|------------|----------|
| tailcat/Tailscale execution on unsanctioned host | Process creation where image or command line contains `tailcat`, `tailscaled`, or arguments `serve`, `no-auth-ssh`, `recv` (4688 / Sysmon 1 / auditd execve) | High | P1 |
| DERP-relay egress from unsanctioned host | DNS or TLS SNI for `derp*.tailscale.com`, `*.tailscale.com` DERP endpoints, `tailcat.dev`; long-lived UDP/443 flows to Tailscale relay ranges | High (if Tailscale unsanctioned) | P1 |
| Unsigned binary executing from user-writable path | Image load/execution from `%TEMP%`, `%LOCALAPPDATA%`, profile root, `C:\ProgramData\*`, `/tmp`, `/var/tmp`, `/dev/shm`, `$HOME` with no valid/expected signature | Medium | P2 |
| SSH client spawned by non-interactive parent | `ssh.exe`/`scp.exe` (or `ssh`/`scp`) with a parent that is not a shell/sshd/developer tool — indicates ProxyCommand-driven tunnel use | Medium | P2 |
| GitHub release download of tunneling tool | Download event for `github.com/tailscale/tailcat/releases/...` (or any dual-use tunneling tool) by a non-browser process | Medium | P2 |
| npm install script spawning network tooling | `node`/`npm` child process performing HTTP downloads or executing shell commands during install | Medium | P2 |
| Bulk file reads followed by tunnel process | Many file-open events on user documents immediately preceding a `tailcat`/scp transfer | Medium | P2 |

### Containment (First 15 Minutes)

- [ ] **Isolate the host** from the network (EDR network isolation or switch
      port shutdown). Do NOT reboot — the ephemeral tunnel address, WireGuard
      keys, and DERP session state are volatile and disappear on reboot.
- [ ] **Kill the tunnel processes.** Identify and suspend (do not immediately
      kill, if you plan memory capture first) processes matching:

  ```powershell
  Get-Process | Where-Object { $_.Name -match 'tailcat|tailscaled' } | Format-List Id, Path, CommandLine
  Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'serve|no-auth-ssh|recv' } | Select-Object ProcessId, CommandLine
  ```

  ```bash
  ps -eo pid,ppid,user,args | grep -Ei 'tailcat|tailscaled|no-auth-ssh' | grep -v grep
  ss -tunap | grep -E 'tailcat|3478|443'
  ```
- [ ] **Block the destination at the perimeter.** Add emergency egress blocks
      for `*.tailscale.com` DERP relays, `tailcat.dev`, and
      `login.tailscale.com` if not already policy.
- [ ] **Preserve volatile evidence** (see next section) before remediation.

### Evidence Collection

| Artifact | Location | Collection Command |
|----------|----------|-------------------|
| Process list + network connections | Windows (live) | `Get-NetTCPConnection -State Established \| Export-Csv C:\IR\net.csv`; `netstat -ano > C:\IR\netstat.txt` |
| Process list + sockets | Linux (live) | `ps auxww > /ir/ps.txt`; `ss -tunap > /ir/ss.txt` |
| Security event log | Windows | `wevtutil epl Security C:\IR\Security.evtx` |
| Sysmon log (if deployed) | Windows | `wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\IR\Sysmon.evtx` |
| Defender detections | Windows | `Get-MpThreatDetection \| Export-Clixml C:\IR\detections.xml`; `Get-MpComputerStatus > C:\IR\mpstatus.txt` |
| auditd logs | Linux | `cp /var/log/audit/audit.log* /ir/` ; `ausearch -k tailcat_exec > /ir/tailcat_hits.txt` (if the shipped rules were loaded) |
| auth/syslog | Linux | `cp /var/log/auth.log* /var/log/syslog* /ir/ 2>/dev/null` |
| Suspicious binaries | Both | Hash, then copy (do not delete yet): `Get-FileHash .\tailcat.exe -Algorithm SHA256` / `sha256sum ./tailcat` |
| npm provenance | Both | `npm ls -g --depth=0`; project `package-lock.json` git history; `~/.npm/_logs/*` |
| Prefetch / execution artifacts | Windows | `copy C:\Windows\Prefetch\TAILCAT*.pf C:\IR\` |
| Memory image (if P1) | Both | EDR-acquired image or `winpmem`/`avml` before killing tunnel processes |

### Eradication

- Terminate remaining tunnel tooling processes (after evidence capture).
- Remove dropped binaries and staging directories (search user-writable paths:
  `%TEMP%`, `%LOCALAPPDATA%`, profile roots, `/tmp`, `/var/tmp`, `$HOME`) —
  **only after** hashing and copying samples.
- Identify and remove the **delivery vector**: audit `package.json` /
  `package-lock.json` diffs on the host for recently added or typosquatted npm
  dependencies; check global npm installs; review CI build logs for unexpected
  install-time network activity.
- Remove any persistence the operator installed over the shell (scheduled
  tasks, Run keys, services on Windows; cron entries, systemd units, shell
  rc files, `~/.ssh/authorized_keys` additions on Linux).
- Rotate credentials reachable from the host — the no-auth-ssh shell gave the
  operator the user's full context: browser stores, SSH keys, cloud CLI tokens,
  `.npmrc` tokens, password managers if unlocked.

### Recovery

- [ ] Verify no `tailcat`/`tailscaled` binaries or processes remain (`Everything`/file search + running-process audit).
- [ ] Verify egress blocks for DERP infrastructure are in place and alerting.
- [ ] Confirm ASR/AppLocker/WDAC policies are enforcing (not just auditing) on the recovered host class.
- [ ] Reinstall or update the compromised npm dependency set from a clean lockfile via the private registry.
- [ ] Reimage if operator dwell time exceeded your threshold or credential theft is confirmed.
- [ ] Reconnect to network in a monitored VLAN first; watch for re-tunnel attempts.

### Post-Incident

1. **How was the attack detected?** Tunnel-process execution, DERP egress, or
   downstream data-loss signal? If none fired, treat as a detection-gap finding
   and backfill from the shipped rule set.
2. **What was detection-to-response time?** The no-auth-ssh shell is
   internet-reachable the moment DERP bootstrap completes (~seconds), so the
   meaningful SLA is egress-alert-to-isolation, not ticket triage.
3. **What would have prevented this?** Rank: (a) npm supply-chain controls
   (delivery), (b) application control on non-standard paths (execution),
   (c) DERP egress filtering (channel), (d) DLP on the staged data (impact).
4. **Is Tailscale sanctioned anywhere in the org?** If yes, verify the block
   scoping did not break legitimate tailnets and move sanctioned use behind a
   managed, ACL'd tailnet so unsanctioned DERP use stays a clean signal.

## References

- [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [T1021.004 — Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/)
- [T1005 — Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [M1031 — Network Intrusion Prevention](https://attack.mitre.org/mitigations/M1031/)
- [M1037 — Filter Network Traffic](https://attack.mitre.org/mitigations/M1037/)
- [M1042 — Disable or Remove Feature or Program](https://attack.mitre.org/mitigations/M1042/)
- [M1035 — Limit Access to Resource Over Network](https://attack.mitre.org/mitigations/M1035/)
- [M1030 — Network Segmentation](https://attack.mitre.org/mitigations/M1030/)
- [M1032 — Multi-factor Authentication](https://attack.mitre.org/mitigations/M1032/)
- [M1057 — Data Loss Prevention](https://attack.mitre.org/mitigations/M1057/)
- Microsoft Threat Intelligence — Kothamine / tailcat OSINT profile (2026-09-28) and Malwarebytes companion write-up
- [tailcat GitHub repository](https://github.com/tailscale/tailcat)
- [Microsoft: Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [CIS Benchmarks — Windows 11 / Ubuntu Linux (audit policy, firewall, package-management sections)](https://www.cisecurity.org/benchmark/microsoft_windows_11)

# Defense Guidance — UnDefend Defender Signature/Engine Update DoS

**Test UUID**: `6a2351ac-654a-4112-b378-e6919beef70d`
**MITRE ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools), T1083 (File and Directory Discovery)
**Threat Actor**: Nightmare-Eclipse (PoC author)
**Severity**: High

## Why This Matters

UnDefend demonstrates that a **standard-user process** (no admin, no driver,
no handle hijack) can indefinitely silence Microsoft Defender by racing
signature-update file replaces. The attack:

- Requires no privilege escalation.
- Leaves no obvious UI indicator (updates "succeed" from the user's perspective but actually fail silently).
- Keeps the AV running — so behavioral-monitoring tools that only check
  `WinDefend` service state won't notice.
- Can persist indefinitely: an attacker can re-launch UnDefend at boot via
  any user-context autorun (shell startup, user scheduled task, Run key)
  and keep Defender on stale signatures forever.

Defense requires layered controls because the attack touches only legitimate
APIs (no exploits, no unsigned code) and runs as any user.

## Layered Controls

### Layer 1 — Prevention

1. **Enable Defender Tamper Protection** (MDM or Intune).
   Tamper protection doesn't block the file-lock primitive directly but it
   closes related follow-on techniques (registry-based Defender disabling,
   policy override, exclusion planting). See `_hardening.ps1`.

2. **Enable all stable ASR rules** — in particular:
   - `Block abuse of exploited vulnerable signed drivers`
   - `Block untrusted and unsigned processes that run from USB`
   - `Block process creations originating from PSExec and WMI commands`
   These reduce the surface for dropping UnDefend-class payloads.

3. **Application control / WDAC or AppLocker** — restrict which user-context
   binaries may call `NotifyServiceStatusChangeW` on SCM. Not trivial, but
   enforcing a Microsoft-publisher-only policy for binaries that subscribe
   to service notifications eliminates UnDefend-class tools at run time.

4. **Restrict standard-user write access to autorun surfaces** — prevents
   the attacker from persistently re-launching UnDefend at boot. Specifically:
   - User Scheduled Tasks folder hardening
   - HKCU Run / RunOnce audit
   - Startup folder ACL monitoring

### Layer 2 — Detection

Deploy the rules in the four companion detection files. The four highest-value
behavioral signals, in order of fidelity:

1. **Non-Defender process opening a directory handle under
   `C:\ProgramData\Microsoft\Windows Defender\Definition Updates`** —
   see `_dr_rules.yaml` rule `undefend-open-definition-updates-directory`,
   `_sigma_rules.yml` rule `6a2351ac-sigma-002`.

2. **Non-Defender process subscribing to WinDefend service state via
   `NotifyServiceStatusChangeW`** — see `_dr_rules.yaml` rule
   `undefend-windefend-service-open-by-non-defender`,
   `_sigma_rules.yml` rule `6a2351ac-sigma-001`.

3. **Repeated Defender signature-update failure events on a host** —
   Defender operational log EventIDs 2001 / 2002 / 2004 firing 3+ times
   within 6 hours. See `_sigma_rules.yml` rule `6a2351ac-sigma-004`.

4. **Non-Microsoft process reading `ProductAppDataPath` /
   `SignatureLocation` registry values** — see `_dr_rules.yaml` rule
   `undefend-defender-registry-recon`.

### Layer 3 — Response

If any of the above rules fire:

1. **Quarantine the host** — isolate from network pending triage.
2. **Collect process tree** — the parent chain that launched the tamper
   process often reveals the initial-access vector (phishing attachment,
   malicious installer, lolbin via macro).
3. **Check Defender signature freshness** — `Get-MpComputerStatus` →
   `AntivirusSignatureLastUpdated`. If stale despite attempted updates,
   the host was likely DoS'd.
4. **Check for other autorun-backed UnDefend launch persistence** —
   user-context Run keys, startup folder, user scheduled tasks.
5. **Re-run Defender update** after removing the tamper tool:
   `Update-MpSignature -UpdateSource MicrosoftUpdateServer`.
6. **Reboot** — releases any remaining leaked file locks.

## Incident Response Playbook

```
1. Detect
   └─ D&R rule fires OR SOC triage pulls host with 3+ 2001/2002 events
2. Triage (within 30 min)
   ├─ Isolate host via MDE/LC network quarantine
   ├─ Pull running process list + their handles (handle.exe / Procmon)
   └─ Identify the process holding open handle on Definition Updates\*
3. Contain (within 2 hours)
   ├─ Terminate the tamper process (releases locks on handle close)
   ├─ Preserve process binary for analysis
   └─ Force Defender signature update; confirm success
4. Eradicate (within 8 hours)
   ├─ Identify launch persistence (user-context autoruns)
   ├─ Remove autorun entries
   ├─ Scan user profile for additional UnDefend variants
   └─ Hunt for lateral spread via the same user's credentials
5. Recover
   ├─ Reboot host to clear any leaked kernel objects
   ├─ Verify Defender health: Get-MpComputerStatus, no repeated failure events
   └─ Unquarantine host
6. Lessons Learned
   ├─ Confirm detection rules fired (or tune if missed)
   ├─ Verify preventive controls (ASR, App Control) coverage
   └─ Update IR runbook with any new IoCs found
```

## References

- Primary source: https://github.com/Nightmare-Eclipse/UnDefend
- MITRE ATT&CK T1562.001: https://attack.mitre.org/techniques/T1562/001/
- Microsoft Defender tamper protection: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection
- Attack Surface Reduction rules: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference

See `_hardening.ps1` for a preventive script, `_detections.kql` /
`_sigma_rules.yml` / `_elastic_rules.ndjson` / `_dr_rules.yaml` / `_rules.yar`
for detection coverage.

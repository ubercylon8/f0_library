# Defense Guidance — Nightmare-Eclipse RedSun Primitive Chain

**UUID**: `0d7e7571-45e2-426a-ac8e-bdb000439761`
**Threat**: RedSun Cloud Files rewrite privilege-escalation PoC (Nightmare-Eclipse, 2026)

## TL;DR

The RedSun PoC chains four observable primitives to trick Windows Defender's
Cloud Files rewrite pathway into overwriting `System32\TieringEngineService.exe`.
The privilege-escalation payoff requires ALL four primitives to succeed AND a
race against Defender's rewrite to be won. **Breaking ANY link in the chain
defeats the exploit.** The easiest links to break, in priority order, are:

1. **Block non-OneDrive Cloud Files sync-root registration** from untrusted
   processes. This is the hardest primitive for an attacker to reproduce
   with something else, and the most uniquely identifiable.
2. **Detect VSS device enumeration** (`\Device\HarddiskVolumeShadowCopy*`) from
   non-backup processes. Shadow-copy path enumeration from user-mode is rare.
3. **Alert on mount-point reparse points** set by non-privileged processes.
   Setting a reparse point that redirects into `C:\Windows\System32` is an
   immediate block-candidate.
4. **Detect the FILE_SUPERSEDE race pattern** — many rapid create/delete cycles
   against a single file from one process.

## Incident Response Playbook

### Triage (first 10 minutes)

1. Confirm the alert: which primitive triggered? (`SyncRootManager` registry
   write, VSS device enumeration, reparse-point set, or supersede loop.)
2. Extract the initiating process path and PID from the alert.
3. Pull the process's full ancestry via EDR process tree.
4. Check if the process is signed. Unsigned + touching CfApi.dll + imports
   `Nt*DirectoryObject` is near-certain RedSun-family behavior.

### Contain (10-30 minutes)

1. **Isolate the host** from the network (EDR network-containment feature).
2. Snapshot the host's memory (Defender for Endpoint → Collect investigation
   package, or manual `LiveKd.exe /o memory.dmp`).
3. Look for these artifacts on disk:
   - `%TEMP%\RS-{GUID}` working directory (the real PoC pattern)
   - Mount-point reparse points under user profile directories whose target is
     a `\??\` NT-path pointing into `System32` — run:
     ```cmd
     fsutil reparsepoint query C:\Users\<user>\AppData\*
     ```
   - Recently-modified `TieringEngineService.exe` in System32 — compare hash
     against a known-good Windows install of the same version.
4. Kill the initiating process and its children.

### Eradicate (30-90 minutes)

1. If `TieringEngineService.exe` was modified, restore from a known-good
   Windows image (Windows Update repair, in-place upgrade, or restore from
   backup). Do not attempt to replace the file while the service is running.
2. Delete any non-OneDrive / non-allowlisted sync-root registrations from
   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SyncRootManager`.
3. Delete any rogue reparse points found in step 3 above.
4. Check AutoRuns for persistence (scheduled tasks, Run keys) dropped by the
   same process tree.

### Recover (90 minutes - 4 hours)

1. Re-image the host if any system file was confirmed modified — eradication
   without re-image is unsafe for a SYSTEM-level compromise.
2. Reset credentials for any account that was logged in during the window.
3. Review Cloud Files provider registrations across the fleet; hunt for the
   same non-Microsoft provider name.
4. If the provider name used is identifiable (`SERIOUSLYMSFT`, or any other
   non-standard string), add it as a permanent IOC in the SIEM.

### Lessons Learned

- Was Cloud Files API feature (`OptionalFeatureName=ClientForNFS`? No, this is
  part of the Windows Explorer sync client) disabled anywhere it didn't need
  to be?
- Were object-access audits enabled? ETW kernel-file forwarding?
- Did the EDR have a detection for non-OneDrive `CfRegisterSyncRoot` before
  this incident? If not, enroll one.

## Hardening Recommendations (strategic)

### 1. Harden Cloud Files API usage

The Cloud Files API is an OPTIONAL Windows feature. If the environment does
not use third-party Cloud Files providers (i.e., you only use OneDrive or no
cloud sync), consider:

- Disabling the Cloud Files Mini-Filter (`cldflt`) on systems that don't need
  it. This breaks OneDrive, so only do this on server / lab systems without
  cloud sync.
- At minimum, monitor `SyncRootManager` registry key writes with an allowlist.

### 2. Enable object-access auditing for `\Device`

Most EDRs surface `NtOpenDirectoryObject` / `NtQueryDirectoryObject` via
kernel-file ETW. Ensure that provider is forwarded to the SIEM. Kernel-file
ETW is heavy — scope it to the critical forest of hosts first (domain
controllers, security jumpboxes, build servers, backup servers).

### 3. Alert on reparse-point creation by user processes

Configure a Windows Security audit policy:

```cmd
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

Then filter for event 4663 with access mask indicating reparse-point writes
from non-system processes.

### 4. Block the supersede-race pattern via AppLocker or WDAC

The RedSun PoC is a single unsigned binary. WDAC or AppLocker in Enforce mode
with a user-space allowlist kills this entire class of exploit — not just
RedSun — by refusing to launch the attacker's initial binary. This is the
single highest-value control.

### 5. Apply the Hardening Script

See `0d7e7571-45e2-426a-ac8e-bdb000439761_hardening.ps1` for concrete
commands (requires admin, idempotent, dry-run mode available).

## Detection Stack Recommendations

| Layer | What to Deploy |
|---|---|
| SIEM KQL | See `_detections.kql` — 6 queries covering each primitive + chain sentinel |
| Sigma | See `_sigma_rules.yml` — 5 rules, SIEM-agnostic |
| Elastic EQL | See `_elastic_rules.ndjson` — 5 rules, including a high-fidelity EICAR-in-sync-root sequence |
| LimaCharlie D&R | See `_dr_rules.yaml` — 4 rules (registry, FILE_READ, reparse-point, threat-name) |
| Static detection | See `_rules.yar` — 3 YARA rules matching the RedSun family PE surface |

## Known Limitations of This Defense Guidance

- **T1006 detection depends on ETW forwarding**. Many organizations don't
  forward kernel-file ETW to their SIEM. Without it, VSS-device enumeration
  is invisible at the SIEM layer.
- **FSCTL_REQUEST_BATCH_OPLOCK is high-volume**. The sigma/KQL rules use an
  allowlist of legitimate backup processes; tune it for your environment
  before deploying.
- **AV signatures for CfApi-family PoCs may lag**. The defense-in-depth for
  new variants is the behavioral detection (sync-root registration from
  unexpected process), not static signatures.

## References

- https://github.com/Nightmare-Eclipse/RedSun — original PoC source
- https://learn.microsoft.com/en-us/windows/win32/cfapi/cloud-files-api-portal
- https://attack.mitre.org/techniques/T1211/
- https://attack.mitre.org/techniques/T1006/
- https://attack.mitre.org/techniques/T1574/

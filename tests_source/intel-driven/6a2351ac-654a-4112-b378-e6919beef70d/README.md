# UnDefend - Defender Signature/Engine Update DoS via File-Lock Race

**Test UUID**: `6a2351ac-654a-4112-b378-e6919beef70d`
**Category**: intel-driven
**Subcategory**: defender-evasion
**Target**: windows-endpoint
**Severity**: high
**Complexity**: medium
**Threat Actor**: Nightmare-Eclipse
**Architecture**: multi-stage (3 stages)
**Techniques**: T1562.001 (Impair Defenses: Disable or Modify Tools), T1083 (File and Directory Discovery)
**Tactics**: defense-evasion, discovery

**Test Score**: **8.7/10**

## Summary

Simulates the [UnDefend PoC](https://github.com/Nightmare-Eclipse/UnDefend) from
Nightmare-Eclipse: a standard-user (no-admin) denial-of-service technique against
Microsoft Defender that blocks signature and engine updates by holding exclusive
file locks at the exact moment Defender tries to apply them.

The real UnDefend targets three primitives:

1. **Passive signature lock** — subscribes to `ReadDirectoryChangesW` on Defender's
   `Definition Updates` directory (resolved from registry `ProductAppDataPath`).
   On any `FILE_ACTION_MODIFIED`, opens the modified file with `NtCreateFile`
   (`GENERIC_READ | SYNCHRONIZE`) and calls `LockFile` for an exclusive lock —
   Defender's signature update fails silently, AV keeps stale DB.
2. **Aggressive engine lock** — subscribes to `NotifyServiceStatusChangeW` on
   `WinDefend` with `SERVICE_NOTIFY_STOPPED`; when the service stops during a
   platform update, resolves `mpavbase.vdm` via registry `SignatureLocation` and
   `LockFileEx` it with `LOCKFILE_EXCLUSIVE_LOCK`.
3. **Preemptive backup lock** — locks `Definition Updates\Backup\mpavbase.lkg`
   and `mpavbase.vdm` at startup before monitoring begins.

This F0RT1KA simulation reproduces the **detectable API primitives** — registry
recon, directory-change subscription, service-stop subscription, and the
`NtCreateFile + LockFile / LockFileEx` sequence — but **never takes a real lock
on a real Defender file**. The exclusive-lock primitive is exercised against a
benign sandbox file under `ARTIFACT_DIR` that the test itself creates and
releases within the same function call.

## Stages

| # | Stage | Technique | What Runs |
|---|-------|-----------|-----------|
| 1 | Defender Update-Path Discovery | T1083 | HKLM registry reads (`ProductAppDataPath`, `SignatureLocation`) + `ReadDirectoryChangesW` subscription on the real Definition Updates directory for 2s |
| 2 | UnDefend File-Lock Primitive (Benign Target) | T1562.001 | Creates `ARTIFACT_DIR\UnDefendSim\sig-sample.yaml`; calls `CreateFile` (GENERIC_READ&#124;SYNCHRONIZE) + `LockFile` + `LockFileEx` (LOCKFILE_EXCLUSIVE_LOCK); releases and deletes |
| 3 | WinDefend Service-Stop Notification Subscription | T1562.001 | `OpenSCManager` + `OpenService("WinDefend")` + `QueryServiceStatus` + `NotifyServiceStatusChangeW(SERVICE_NOTIFY_STOPPED)`; subscription torn down at return (no `SleepEx`) |

## Safety Boundary

The real UnDefend persists locks across process lifetime and can leave Defender
crippled between runs. This simulation:

- **Never** opens any file under `C:\Windows\System32\MRT`, `C:\ProgramData\Microsoft\Windows Defender\`, or any real Defender path with write/lock intent.
- Takes the exclusive-lock primitive on a file it creates and owns in `ARTIFACT_DIR`.
- Releases every lock via `UnlockFile` / `UnlockFileEx` inside the same function that acquired it.
- Registers the `WinDefend` service-stop subscription without an alertable wait, guaranteeing the callback never fires.

## Exit Codes

- **101** — All three primitives ran without EDR intervention (vulnerable)
- **126** — EDR blocked at least one primitive (protected)
- **999** — Prerequisites missing (Defender not installed, registry unreadable, `WinDefend` not running)

## Build

```bash
./build_all.sh
# or
./utils/gobuild build-sign tests_source/intel-driven/6a2351ac-654a-4112-b378-e6919beef70d/ --org sb
```

## References

See `6a2351ac-654a-4112-b378-e6919beef70d_references.md` for source provenance.

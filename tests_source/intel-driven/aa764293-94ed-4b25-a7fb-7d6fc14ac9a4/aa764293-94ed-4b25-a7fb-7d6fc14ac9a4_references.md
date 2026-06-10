# References — RoguePlanet Windows Defender Remediation TOCTOU LPE

**UUID**: `aa764293-94ed-4b25-a7fb-7d6fc14ac9a4`

## Primary source

| Field | Value |
|-------|-------|
| **Title** | RoguePlanet — Technical Analysis & Build Guide |
| **Author** | Internal F0RT1KA research analysis of the RoguePlanet PoC (PoC attributed to "Nightmare-Eclipse") |
| **Date** | 2026 (local research artifact) |
| **URL** | N/A — local research artifact (`/home/jimx/F0RT1KA/RoguePlanet/ROGUEPLANET_ANALYSIS.md`) |
| **Type** | research-paper (internal technical analysis) + tool-release (PoC) |

The analysis document is the authoritative behavior spec for this test. Key sections
used:

- **§0 TL;DR** — exploit class, result, reliability, constraints.
- **§1** — security audit (no C2/exfil/persistence) + intrinsic side effects.
- **§2–§3** — vulnerability summary and primitive glossary (EICAR-as-wermgr, mounted
  ISO, `:WDFOO` ADS, NTFS junction, oplock, VSS, Poseidon threads, WER `QueueReporting`
  task, named pipe, self-copy payload).
- **§4** — execution flow, incl. §4a SYSTEM re-entry path / `IsRunningAsLocalSystem`
  branch (load-bearing for the execution-context requirement).
- **§7** — observable signal set (basis for the detection rules).
- **§10** — self-restoring `wermgr.exe` modification and manual-restore guidance.

## Embedded payload

| Field | Value |
|-------|-------|
| **File** | `RoguePlanet.exe` (PE32+ x64 console, ~1.07 MB) |
| **Source-of-truth SHA256 (unsigned)** | `08295dfde704bccce015af683ca95312d45564f7321bd64cc63c034b64e08080` |
| **Provenance** | Prebuilt PoC supplied for authorized defensive research; NOT recompiled from `RoguePlanet.cpp` (5.7 MB / 79k lines, requires MSVC + Windows SDK). |
| **Embedding** | Signed with F0RT1KA cert, gzip-compressed, embedded via `//go:embed`, decompressed in memory at runtime. |

## MITRE ATT&CK

- **T1068** — Exploitation for Privilege Escalation —
  https://attack.mitre.org/techniques/T1068/
- **T1036.005** — Masquerading: Match Legitimate Name or Location —
  https://attack.mitre.org/techniques/T1036/005/
- **T1053.005** — Scheduled Task/Job: Scheduled Task —
  https://attack.mitre.org/techniques/T1053/005/

## Background concepts (supporting references)

| Title | URL | Type |
|-------|-----|------|
| Privileged file operation abuse / junction + oplock LPE primitive (general class) | https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html | research-paper |
| NTFS reparse points / mount points (junctions) | https://learn.microsoft.com/windows/win32/fileio/reparse-points | documentation |
| Opportunistic locks (oplocks) | https://learn.microsoft.com/windows/win32/fileio/opportunistic-locks | documentation |
| EICAR standard anti-malware test file | https://www.eicar.org/download-anti-malware-testfile/ | reference |
| Windows Error Reporting / `wermgr.exe` | https://learn.microsoft.com/windows/win32/wer/windows-error-reporting | documentation |
| `WTSQueryUserToken` (SYSTEM→user session launch) | https://learn.microsoft.com/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken | documentation |
| `CreateProcessAsUser` | https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw | documentation |

## Notes

- No public CVE/SOURCE_URL is asserted for this PoC; `SOURCE_URL` is `N/A` in the
  metadata header by design (local research artifact).
- The exploit performs **no** network/C2/exfil and creates **no** new persistence
  (audited in analysis §1); the WER `QueueReporting` task it triggers is a
  **built-in** task, not one it creates.

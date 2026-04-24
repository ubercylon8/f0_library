# References — BlueHammer Early-Stage Behavioral Pattern

## Primary source

| Field | Value |
|-------|-------|
| Title | BlueHammer — Windows Defender TOCTOU VSS SAM-leak PoC |
| Author | Nightmare-Eclipse |
| URL | <https://github.com/Nightmare-Eclipse/BlueHammer> |
| Type | tool-release |
| Date | 2026 |

## Local working copies (build-machine path references)

| File | Purpose |
|------|---------|
| `BlueHammer/EXPLOIT_ANALYSIS.md` | Authoritative phase walkthrough (read first when reviewing this test) |
| `BlueHammer/FunnyApp.cpp` | Original C++ source — this test references `wmain`, `FreezeVSS`, `ShadowCopyFinderThread` only. Later phases (`DoSpawnShellAsAllUsers`, `LaunchConsoleInSessionId`, SAM parsing) are intentionally NOT examined or reimplemented. |

## Microsoft API documentation referenced by this test

| API | Used by | Docs |
|-----|---------|------|
| `CfRegisterSyncRoot` | Stage 1 | <https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfregistersyncroot> |
| `CfConnectSyncRoot` + `CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS` | Stage 1 | <https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfconnectsyncroot> |
| `FSCTL_REQUEST_BATCH_OPLOCK` | Stage 2 | <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_batch_oplock> |
| `NtOpenDirectoryObject` | Stage 3 | <https://learn.microsoft.com/en-us/windows/win32/devnotes/ntopendirectoryobject> |
| `CreateTransaction` / `CreateFileTransactedW` | Stage 3 | <https://learn.microsoft.com/en-us/windows/win32/api/ktmw32/nf-ktmw32-createtransaction> / <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiletransactedw> |

## MITRE ATT&CK references

- **T1211 — Exploitation for Defense Evasion**: <https://attack.mitre.org/techniques/T1211/>
- **T1562.001 — Impair Defenses: Disable or Modify Tools**: <https://attack.mitre.org/techniques/T1562/001/>

## Background: Cloud Files API oplock-stall technique

The technique of using `CfRegisterSyncRoot` + `FSCTL_REQUEST_BATCH_OPLOCK` as an AV scanner-stall primitive is documented publicly; selected references (not used as a source for implementation, included here for research context):

- James Forshaw — "Windows Exploitation Tricks: Arbitrary Directory Creation to Arbitrary File Read" (Google Project Zero), <https://googleprojectzero.blogspot.com/>
- Microsoft Cloud Files API security notes — <https://learn.microsoft.com/en-us/windows/win32/cfapi/>

## Reference material NOT used

Per scoping, the following were intentionally NOT examined during this test's construction:
- `BlueHammer/AGENTS.md`
- `BlueHammer/windefend_*.c`, `.h`, `.idl` (COM stubs, irrelevant to behavioral simulation)

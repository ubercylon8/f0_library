---
name: sectest-deploy
description: Deploy and execute F0RT1KA security test on target endpoint. Auto-detects platform from test source, deploys via SSH, executes with output capture, interprets exit codes, retrieves logs.
---

# Security Test Deployment

This skill handles Phase 3b of security test creation: deploying a compiled F0RT1KA test binary to a target endpoint via SSH, executing it, capturing output, and interpreting results. It runs AFTER Phase 3 (sectest-validation) or can be invoked standalone to re-deploy an already-built test.

## Step 1: Platform Detection

Determine the target platform by inspecting the test source directory.

### Detection Priority

1. **Logger file presence** — Check for platform-specific logger files in the test directory
2. **Build tag** — Scan `<uuid>.go` for `//go:build windows|linux|darwin`
3. **Metadata header** — Look for `TARGET:` field in the Go file comment block
4. **Override** — Accept `--target <windows|linux|darwin>` argument to force a platform

### Detection Commands

```bash
# Check for platform-specific logger files
ls <test_dir>/test_logger_windows.go 2>/dev/null && echo "windows"
ls <test_dir>/test_logger_linux.go   2>/dev/null && echo "linux"
ls <test_dir>/test_logger_darwin.go  2>/dev/null && echo "darwin"

# Fallback: check build tag in main Go file
grep -m1 '//go:build' <test_dir>/<uuid>.go

# Fallback: check metadata header TARGET field
grep 'TARGET:' <test_dir>/<uuid>.go
```

### Platform Configuration Table

| Platform | SSH Host | Deploy Path | Binary Extension | GOOS/GOARCH | Sign Method | Pre-exec |
|----------|----------|-------------|-----------------|-------------|-------------|----------|
| Windows | `win` | `c:\F0\` | `.exe` | `windows/amd64` | `utils/codesign` (dual) | none |
| Linux | `debian` | `/opt/f0/` | none | `linux/amd64` | skip | `chmod +x` |
| macOS | `mac` | `/opt/f0/` | none | `darwin/arm64` | `codesign -s -` | `xattr -cr` |

**Note:** Log files are written to `c:\F0` (Windows) or `/tmp/F0` (Linux/macOS), which differs from the deploy path on Linux/macOS.

## Step 2: Verify Binary Exists

Before attempting deployment, confirm the compiled binary is present locally.

```bash
# Windows binary
ls -lh build/<uuid>/<uuid>.exe

# Linux/macOS binary
ls -lh build/<uuid>/<uuid>
```

If the binary is missing, do NOT proceed. Report back to the orchestrator:

```
DEPLOY BLOCKED: Binary not found at build/<uuid>/<uuid>[.exe]
ACTION REQUIRED: Run sectest-build-config to rebuild the test binary.
```

The orchestrator must invoke `sectest-build-config` to compile and sign before retrying deployment.

## Step 3: SSH Connectivity Check

Verify the target host is reachable before attempting file transfer.

```bash
# Windows
ssh -o ConnectTimeout=10 win echo "ok"

# Linux
ssh -o ConnectTimeout=10 debian echo "ok"

# macOS
ssh -o ConnectTimeout=10 mac echo "ok"
```

If the connection fails:

```
DEPLOY BLOCKED: SSH host <win|debian|mac> is unreachable.
ACTION REQUIRED: Verify VPN/network connection and that the target VM is running.
```

Stop and report. Do not attempt SCP or execution.

## Step 4: Clean Remote Directory

Remove any previous test artifacts and create a fresh working directory on the remote host.

```bash
# Windows
ssh win 'rmdir /s /q c:\F0 2>nul & mkdir c:\F0'

# Linux
ssh debian 'sudo rm -rf /opt/f0 && sudo mkdir -p /opt/f0 && sudo chmod 777 /opt/f0'

# macOS
ssh mac 'sudo rm -rf /opt/f0 && sudo mkdir -p /opt/f0 && sudo chmod 777 /opt/f0'
```

This ensures no leftover logs, stale binaries, or quarantine states from a prior run interfere with results.

## Step 5: Deploy Binary

Transfer the compiled binary to the remote host using SCP.

```bash
# Windows
scp build/<uuid>/<uuid>.exe win:'c:\F0\'

# Linux
scp build/<uuid>/<uuid> debian:/opt/f0/
ssh debian 'chmod +x /opt/f0/<uuid>'

# macOS
scp build/<uuid>/<uuid> mac:/opt/f0/
ssh mac 'chmod +x /opt/f0/<uuid>'
```

Verify the transfer succeeded by checking file size on the remote side:

```bash
# Windows
ssh win 'dir c:\F0\<uuid>.exe'

# Linux/macOS
ssh <host> 'ls -lh /opt/f0/<uuid>'
```

If transfer fails or file size is 0, stop and report the SCP error.

## Step 6: Execute with Output Capture

Run the test binary on the remote host. Capture stdout live to the console and record the exit code.

```bash
# Windows — capture output; exit code appended inline
ssh win 'c:\F0\<uuid>.exe & echo EXIT_CODE: %ERRORLEVEL%'

# Linux — run and echo exit code
ssh debian '/opt/f0/<uuid>; echo EXIT_CODE: $?'

# macOS — remove Gatekeeper quarantine flag first, then run
ssh mac 'xattr -cr /opt/f0/<uuid> 2>/dev/null; /opt/f0/<uuid>; echo EXIT_CODE: $?'
```

Parse the exit code from the last `EXIT_CODE:` line in the output. If the SSH command itself times out or is killed, treat the exit code as `102` (timeout).

**Note:** On Windows, SSH inherits cmd.exe conventions. Use `& echo EXIT_CODE: %ERRORLEVEL%` (not `&&`) to ensure it echoes even on non-zero exits.

## Step 7: Retrieve Output Logs

Copy remote log files to a local staging directory for review and archival.

```bash
# Create local staging directory
mkdir -p staging/<uuid>/

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Windows — retrieve JSON log, output files from c:\F0\
scp 'win:c:\F0\*.json'        staging/<uuid>/ 2>/dev/null
scp 'win:c:\F0\*_output.txt'  staging/<uuid>/ 2>/dev/null

# Linux — retrieve from both deploy path and log path
scp 'debian:/opt/f0/*.json'   staging/<uuid>/ 2>/dev/null
scp 'debian:/tmp/F0/*.json'   staging/<uuid>/ 2>/dev/null
scp 'debian:/tmp/F0/*.txt'    staging/<uuid>/ 2>/dev/null

# macOS — retrieve from both deploy path and log path
scp 'mac:/opt/f0/*.json'      staging/<uuid>/ 2>/dev/null
scp 'mac:/tmp/F0/*.json'      staging/<uuid>/ 2>/dev/null
scp 'mac:/tmp/F0/*.txt'       staging/<uuid>/ 2>/dev/null
```

Save the combined console output captured in Step 6 to:

```
staging/<uuid>/<uuid>_<timestamp>_deploy.log
```

If no JSON log was retrieved (e.g., EDR quarantined before the logger could write), note this in the deployment report — it indicates the test was stopped very early.

## Step 8: Interpret Exit Code

Map the exit code to a F0RT1KA result classification.

| Exit Code | Classification | Meaning |
|-----------|---------------|---------|
| `101` | UNPROTECTED | Attack succeeded — endpoint is vulnerable, no protection fired |
| `105` | FILE QUARANTINED ON EXTRACTION | Binary quarantined before it could run |
| `126` | EXECUTION PREVENTED | EDR/AV blocked execution at runtime |
| `127` | FILE QUARANTINED ON EXECUTION | Binary quarantined during or immediately after launch |
| `102` | TIMEOUT EXCEEDED | Test exceeded its time limit |
| `999` | UNEXPECTED TEST ERROR | Prerequisites not met (missing user, path, dependency) |
| `0` | TEST COMPLETED | Test ran to completion without EDR intervention |

### Interpretation Notes

- **Exit 999**: Flag for source investigation. The test likely has a prerequisite not present on the target (e.g., a required user account, registry key, or tool). Review the output log for the specific error.
- **Exit 126 on an unprotected/test system**: May be a false positive. The exit code logic in `determineExitCode()` could be misclassifying a non-EDR error as "blocked". Review logs carefully and check for `fmt.Errorf()` wrappers containing blame keywords (`access denied`, `blocked`, `prevented`).
- **Exit 0**: Test ran but no protection fired — same practical meaning as 101 on a protected system (unprotected), but the test completed its cleanup phase normally.
- **Exit 105 or 127**: Check whether the AV/EDR quarantined the binary or one of its embedded stage binaries. Useful for multi-stage tests to identify which stage triggered detection.

## Step 9: Clean Remote Artifacts

After logs have been retrieved, remove all test artifacts from the remote host.

```bash
# Windows
ssh win 'rmdir /s /q c:\F0 2>nul'

# Linux
ssh debian 'sudo rm -rf /opt/f0 /tmp/F0'

# macOS
ssh mac 'sudo rm -rf /opt/f0 /tmp/F0'
```

Verify cleanup:

```bash
# Windows
ssh win 'dir c:\F0 2>nul && echo "WARNING: c:\F0 still exists" || echo "Cleaned"'

# Linux/macOS
ssh <host> 'ls /opt/f0 /tmp/F0 2>/dev/null && echo "WARNING: directories still exist" || echo "Cleaned"'
```

If cleanup fails (e.g., EDR locks the binary), note it in the deployment report but do not block completion.

## Step 10: Report Result

Output a structured deployment result block summarizing the full run.

```
DEPLOY RESULT:
  Test UUID:   <uuid>
  Platform:    <windows|linux|darwin>
  Host:        <win|debian|mac>
  Exit Code:   <code>
  Result:      <UNPROTECTED|FILE_QUARANTINED_EXTRACTION|EXECUTION_PREVENTED|FILE_QUARANTINED_EXECUTION|TIMEOUT|ERROR|COMPLETED>
  Output Log:  staging/<uuid>/<uuid>_<timestamp>_deploy.log
  JSON Log:    staging/<uuid>/<uuid>_results.json  (if retrieved)
```

### Flags and Recommendations

| Condition | Flag | Recommended Action |
|-----------|------|-------------------|
| Exit 999 | SOURCE_INVESTIGATION_NEEDED | Check prerequisite setup in test source |
| Exit 126 on test/unprotected system | POSSIBLE_FALSE_POSITIVE | Review `determineExitCode()` for blame keywords in error messages |
| No JSON log retrieved | EARLY_TERMINATION | EDR likely quarantined binary before logger initialized |
| Exit 105 or 127 on multi-stage | STAGE_DETECTION | Identify which embedded stage triggered quarantine |
| Cleanup failed | RESIDUAL_ARTIFACTS | Manually remove via RDP/console access |

After reporting, pass the structured result back to the calling orchestrator (or display to the user if invoked standalone) so the next phase can proceed or the source can be fixed and redeployed.

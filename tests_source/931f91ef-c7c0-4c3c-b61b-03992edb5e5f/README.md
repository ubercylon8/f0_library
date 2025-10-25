# LSASS Memory Dump via MiniDumpWriteDump

## Overview
This test simulates credential theft by attempting to dump LSASS (Local Security Authority Subsystem Service) process memory using the Windows MiniDumpWriteDump API. This technique is one of the most common methods attackers use to extract credentials from Windows systems for lateral movement.

**Test Score**: **7.5/10** - Strong real-world simulation with clear detection opportunities

**Score Breakdown**:
- Real-World Accuracy: 3.0/3.0 - Uses actual Windows LSASS dumping technique via legitimate API
- Technical Sophistication: 2.0/3.0 - Windows API calls with privilege escalation
- Safety Mechanisms: 1.0/2.0 - Automatic cleanup, no persistent changes
- Detection Opportunities: 1.0/1.0 - Multiple clear detection points across phases
- Logging & Observability: 0.5/1.0 - Basic structured logging

## MITRE ATT&CK Mapping
- **T1003.001** - OS Credential Dumping: LSASS Memory
- **T1055** - Process Injection (handle acquisition to sensitive process)

## What This Test Does

### Attack Phases

**Phase 1: Prerequisites Check**
- Verifies test is running with Administrator privileges
- Confirms execution context

**Phase 2: Enable SeDebugPrivilege**
- Attempts to enable SeDebugPrivilege (required for LSASS access)
- This privilege allows access to sensitive system processes

**Phase 3: Locate LSASS Process**
- Enumerates running processes to find lsass.exe
- Obtains the Process ID (PID) of LSASS

**Phase 4: LSASS Memory Dump Attempt** (CRITICAL)
- Opens handle to lsass.exe process with PROCESS_VM_READ permissions
- Calls MiniDumpWriteDump API to dump process memory
- Writes dump file to C:\F0\lsass.dmp

**Phase 5: Cleanup**
- Removes dump file if created
- No persistent artifacts left on system

## Detection Opportunities

EDR solutions should detect and block:

1. **SeDebugPrivilege Elevation** - Non-system process requesting debug privileges
2. **LSASS Process Enumeration** - Scanning for lsass.exe PID
3. **OpenProcess to LSASS** - Handle acquisition to sensitive process with PROCESS_VM_READ
4. **MiniDumpWriteDump API Call** - API call targeting LSASS process
5. **Suspicious File Creation** - .dmp file creation in non-standard location
6. **LSASS Memory Access** - Any memory read operation against LSASS

## Expected Results

### On Protected System (Exit Code 126)
```
✅ RESULT: PROTECTED
System successfully prevented LSASS memory dump

Protection Details:
  • OpenProcess denied - no handle obtained
  OR
  • MiniDumpWriteDump blocked by EDR

Security Status: ENDPOINT IS SECURE
```

### On Unprotected System (Exit Code 101)
```
❌ RESULT: VULNERABLE
CRITICAL: System failed to prevent LSASS memory dump

Attack Chain:
  ✓ SeDebugPrivilege enabled
  ✓ LSASS PID Discovery: Success
  ✓ OpenProcess: Success (handle obtained)
  ✓ MiniDumpWriteDump: Success (memory dumped)

Security Impact:
  • Credentials in memory could be extracted
  • Domain admin passwords potentially compromised
  • Lateral movement risk elevated

IMMEDIATE ACTION REQUIRED
```

## Exit Code Logic

The test uses proper result evaluation:

```go
if dumpSucceeded {
    // Memory dump created successfully
    exitCode = 101 (Unprotected)
} else if !handleOpened {
    // OpenProcess denied - strongest protection
    exitCode = 126 (ExecutionPrevented)
} else {
    // Handle obtained but dump blocked
    exitCode = 126 (ExecutionPrevented)
}
```

**Critical Decision Points:**
- If OpenProcess fails → **126** (Protected at earliest stage)
- If OpenProcess succeeds but MiniDumpWriteDump fails → **126** (Protected at API level)
- If both succeed and dump file created → **101** (Vulnerable)

## Real-World Context

### Why This Matters

LSASS memory dumping is a **critical post-exploitation technique** used in virtually every major breach:

- **Credential Theft**: Extract plaintext passwords, NTLM hashes, Kerberos tickets
- **Lateral Movement**: Stolen credentials enable access to other systems
- **Privilege Escalation**: Domain admin credentials often cached in LSASS
- **Persistence**: Credentials enable long-term unauthorized access

### Attack Tools Using This Technique

- **Mimikatz** - Most famous credential dumping tool
- **ProcDump** - Microsoft's legitimate debugging tool (abused)
- **Dumpert** - Direct syscall version
- **Nanodump** - Evasive LSASS dumping technique
- **Custom malware** - Nearly all APTs include LSASS dumping

### Defensive Mitigations

If this test shows your system is vulnerable (Exit 101):

1. **Enable Credential Guard** - Hardware-based credential isolation (most effective)
2. **Configure EDR LSASS Protection** - Enable specific LSASS process protection
3. **Enable Attack Surface Reduction (ASR)** - Block credential theft from LSASS
4. **Deploy Protected Process Light (PPL)** - Windows LSASS protection mechanism
5. **Restrict SeDebugPrivilege** - Limit which accounts have debug privileges
6. **Monitor LSASS Access** - Alert on any LSASS process access attempts

## Technical Details

### Windows API Calls Used

```go
// Privilege elevation
LookupPrivilegeValue(SE_DEBUG_NAME)
AdjustTokenPrivileges(SE_PRIVILEGE_ENABLED)

// Process enumeration
CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)
Process32First() / Process32Next()

// LSASS access
OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, lsassPID)

// Memory dump
MiniDumpWriteDump(handle, lsassPID, dumpFile, MiniDumpWithFullMemory)
```

### Files Created

| File | Location | Purpose | Cleanup |
|------|----------|---------|---------|
| lsass.dmp | C:\F0\ | Memory dump (if successful) | Auto-removed |
| test_execution_log.json | C:\F0\ | Structured test log | Persistent |
| test_execution_log.txt | C:\F0\ | Human-readable log | Persistent |

### Build Information

- **Language**: Go 1.21+
- **Platform**: Windows (amd64)
- **Dependencies**: golang.org/x/sys/windows
- **Binary Size**: ~3-4 MB (single binary)

## Building and Running

### Build
```bash
# Using F0RT1KA build utility
./utils/gobuild build tests_source/931f91ef-c7c0-4c3c-b61b-03992edb5e5f/

# Or manually
cd tests_source/931f91ef-c7c0-4c3c-b61b-03992edb5e5f/
GOOS=windows GOARCH=amd64 go build -o ../../build/931f91ef-c7c0-4c3c-b61b-03992edb5e5f/931f91ef-c7c0-4c3c-b61b-03992edb5e5f.exe
```

### Sign (Dual Signing Recommended)
```bash
# Dual sign with organization cert + F0RT1KA
/build-sign-test 931f91ef-c7c0-4c3c-b61b-03992edb5e5f sb

# Or F0RT1KA-only
/build-sign-test 931f91ef-c7c0-4c3c-b61b-03992edb5e5f
```

### Execute
```powershell
# Run as Administrator (required)
.\931f91ef-c7c0-4c3c-b61b-03992edb5e5f.exe

# Check exit code
echo $LASTEXITCODE
# 126 = Protected
# 101 = Vulnerable
# 999 = Test error (not admin, etc.)
```

## Logs and Analysis

### JSON Log
Structured machine-readable format at `C:\F0\test_execution_log.json`:
```json
{
  "testId": "931f91ef-c7c0-4c3c-b61b-03992edb5e5f",
  "testName": "LSASS Memory Dump via MiniDumpWriteDump",
  "exitCode": 126,
  "exitReason": "System protected - OpenProcess denied to LSASS",
  "phases": [...],
  "systemInfo": {...}
}
```

### Text Log
Human-readable format at `C:\F0\test_execution_log.txt`:
- Test execution timeline
- System information
- Phase-by-phase results
- Detailed message log with timestamps

## Comparison to Other Tests

| Test | Complexity | Detection Difficulty | Real-World Usage |
|------|------------|---------------------|------------------|
| LSASS Dump (this) | Low | Low | Very High |
| MDE Auth Bypass | High | High | Medium |
| Process Injection | Medium | Medium | High |

This test provides a **fundamental security capability check** - if EDR cannot prevent LSASS dumping, the system is at high risk of credential theft.

## Version History

- **v1.0** (2025-01-25) - Initial implementation
  - Single-phase LSASS dump attempt
  - Comprehensive logging
  - Clear exit code evaluation

## References

- [MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [Microsoft: Protect LSASS](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Microsoft: Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)
- [ASR Rule: Block credential theft from LSASS](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)

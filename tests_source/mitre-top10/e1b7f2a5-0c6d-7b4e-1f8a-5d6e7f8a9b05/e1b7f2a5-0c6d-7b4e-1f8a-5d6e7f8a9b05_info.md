# System Recovery Inhibition (Safe Mode)

## Test Information

**Test ID**: e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05
**Test Name**: System Recovery Inhibition (Safe Mode)
**Category**: Impact / Ransomware Precursor
**Severity**: Critical
**MITRE ATT&CK**: T1490

## Description

This test evaluates endpoint detection capabilities against T1490 (Inhibit System Recovery) - a critical technique used by ransomware to prevent victims from recovering their systems without paying the ransom. The test uses a SAFE MODE implementation that performs READ-ONLY checks only, making it completely safe to run on production systems.

T1490 is one of the most impactful ransomware techniques because it:
- Eliminates recovery options before encryption begins
- Increases pressure on victims to pay ransom
- Prevents rollback to pre-infection state
- Is used by virtually all modern ransomware families

## Test Score: 8.0/10

### Score Breakdown

| Criterion | Score | Justification |
|-----------|-------|---------------|
| **Real-World Accuracy** | **2.5/3.0** | Tests actual recovery tools (vssadmin, bcdedit, wbadmin) used by ransomware. Uses same executables but read-only queries instead of destructive commands. Closely models reconnaissance phase of T1490. |
| **Technical Sophistication** | **1.5/3.0** | Intentionally limited for safety. Uses standard command-line tools with read-only flags. No advanced techniques like direct API calls or registry manipulation. |
| **Safety Mechanisms** | **2.0/2.0** | Maximum score - completely safe implementation. All operations are read-only. Never executes destructive commands. Creates only marker files in c:\F0. Can run repeatedly without system impact. |
| **Detection Opportunities** | **1.0/1.0** | Provides 6+ distinct detection points: 3 tool accessibility checks, 3 read-only queries, process creation events, command line logging. Comprehensive documentation of what to detect. |
| **Logging & Observability** | **1.0/1.0** | Full Schema v2.0 logging implementation. JSON and text output. Phase tracking. Process execution logging. Comprehensive report generation with query outputs. |

**Key Strengths**:
- Maximum safety score - no risk of system damage
- Tests critical ransomware technique (T1490)
- Multiple detection opportunity points
- Comprehensive documentation of ransomware commands
- Repeatable testing without side effects
- Full Schema v2.0 compliance

**Improvement Opportunities**:
- Could add WMI-based shadow copy enumeration (still read-only)
- Could test PowerShell-based recovery tool access
- Could add registry-based BCD store read checks

## Technical Details

### Attack Flow

1. **Phase 1: Initialization**
   - Initialize dropper and logging framework
   - Create target directory c:\F0
   - Check administrator privileges
   - Create start marker file

2. **Phase 2: vssadmin Check**
   - Verify C:\Windows\System32\vssadmin.exe exists
   - Execute read-only query: `vssadmin list shadows`
   - Capture output and detect any EDR blocking
   - Log process execution details

3. **Phase 3: bcdedit Check**
   - Verify C:\Windows\System32\bcdedit.exe exists
   - Execute read-only query: `bcdedit /enum`
   - Capture boot configuration output
   - Log process execution details

4. **Phase 4: wbadmin Check**
   - Verify C:\Windows\System32\wbadmin.exe exists
   - Execute read-only query: `wbadmin get versions`
   - Capture backup version information
   - Log process execution details

5. **Phase 5: Destructive Command Documentation**
   - Log commands ransomware WOULD execute (NOT executed)
   - Document impact of each command
   - Provide detection signatures

6. **Phase 6: Final Assessment**
   - Generate comprehensive report
   - Determine protection status
   - Create completion marker

### Key Indicators

Defenders should monitor for:

- **Process Creation**:
  - vssadmin.exe execution
  - bcdedit.exe execution
  - wbadmin.exe execution
  - wmic.exe with shadowcopy arguments

- **Command Line Arguments**:
  - `delete shadows` or `resize shadowstorage`
  - `recoveryenabled No` or `bootstatuspolicy`
  - `delete systemstatebackup` or `delete catalog`
  - `shadowcopy delete`

- **Event Logs**:
  - VSS Event ID 8193, 8194 (shadow copy events)
  - System Event ID 7036 (VSS service changes)

## Detection Opportunities

1. **Tool Access Detection**
   - Monitor for any process accessing recovery tool executables
   - Alert on non-standard parent processes for these tools
   - Track frequency and patterns of access

2. **Command Line Monitoring**
   - Flag any vssadmin/bcdedit/wbadmin command execution
   - Specifically alert on destructive arguments
   - Correlate with other ransomware indicators

3. **Behavioral Analysis**
   - Multiple recovery tool access in short timeframe
   - Access from unusual process trees
   - Access outside normal administrative windows

4. **File System Monitoring**
   - Shadow copy volume access patterns
   - BCD store file access
   - Backup catalog file access

5. **Registry Monitoring**
   - HKLM\BCD00000000 access patterns
   - Volume Shadow Copy Service registry keys
   - Backup service configuration changes

## Expected Results

### Unprotected System (Code 101)

When the test returns exit code 101:
- All three recovery tools are accessible
- Read-only queries executed successfully
- No EDR/AV intervention detected
- System is vulnerable to T1490 attacks
- Report shows all tools queryable

Implications:
- Ransomware could delete shadow copies
- Boot recovery could be disabled
- Backup catalogs could be destroyed
- No behavioral protection against T1490

### Protected System (Code 126)

When the test returns exit code 126:
- EDR blocked one or more read-only queries
- Tool access or query execution prevented
- Active protection against T1490 detected
- Report shows which queries were blocked

Protection mechanisms that may trigger this:
- Behavioral monitoring of recovery tool access
- Command line argument scanning
- Process creation blocking for sensitive tools
- Application whitelisting policies

### Prerequisites Not Met (Code 999)

When the test returns exit code 999:
- Administrator privileges not available
- Cannot accurately assess recovery tool access
- Re-run with elevated privileges required

## References

- [MITRE ATT&CK T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [Ransomware Shadow Copy Deletion Analysis](https://www.microsoft.com/en-us/security/blog/)
- [Volume Shadow Copy Service Documentation](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [BCDEdit Command Reference](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdedit-command-line-options)
- [WBAdmin Command Reference](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin)

## Ransomware Families Using T1490

This technique is used by virtually all modern ransomware including:
- LockBit
- Conti
- REvil/Sodinokibi
- Ryuk
- BlackCat/ALPHV
- Hive
- Royal
- Play
- BlackBasta

## Enhancement Notes

Version 1.0.0 (2026-01-11):
- Initial safe mode implementation
- Read-only checks for vssadmin, bcdedit, wbadmin
- Comprehensive documentation of destructive commands
- Full Schema v2.0 logging compliance
- Multi-organization support via org_resolver

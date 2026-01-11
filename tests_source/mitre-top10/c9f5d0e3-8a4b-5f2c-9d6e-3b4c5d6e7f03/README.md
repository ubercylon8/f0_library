# RDP Lateral Movement Simulation

**Test Score**: **8.0/10**

## Overview

This test evaluates EDR/AV detection capabilities against Remote Desktop Protocol (RDP) lateral movement techniques. RDP is one of the most commonly abused remote access methods by threat actors for lateral movement within compromised networks. This test simulates both reconnaissance (service/session enumeration) and credential manipulation patterns.

## MITRE ATT&CK Mapping

- **Tactic**: Lateral Movement, Credential Access
- **Technique**: T1021.001 - Remote Services: Remote Desktop Protocol
- **Sub-technique**: T1555.004 - Credentials from Password Stores: Windows Credential Manager

## Test Patterns

1. **RDP Service Status**: `sc query TermService` - Check if RDP service is running
2. **Registry Configuration**: `reg query` - RDP configuration enumeration
3. **Session Enumeration**: `qwinsta` - List active RDP sessions
4. **Cmdkey Manipulation**: `cmdkey /add` + `cmdkey /delete` - Credential Manager simulation
5. **SharpRDP Execution**: Optional headless RDP tool execution (PLACEHOLDER)

## Test Execution

This test simulates RDP lateral movement patterns to evaluate defensive capabilities:

- Uses native Windows commands (sc, reg, qwinsta, cmdkey)
- Creates and immediately removes test credentials (safe operation)
- Optionally executes SharpRDP if the binary is embedded
- All operations are local-only (no actual lateral movement)

## Expected Outcomes

- **Protected (105)**: SharpRDP.exe quarantined on extraction
- **Protected (126)**: EDR blocks cmdkey manipulation or SharpRDP execution
- **Unprotected (101)**: RDP patterns executed without detection
- **Error (999)**: RDP service not running

## Build Instructions

```bash
# Build single self-contained binary
./utils/gobuild build tests_source/mitre-top10/c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03/

# Sign the binary
./utils/codesign sign build/c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03/c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03.exe
```

## SharpRDP Integration (Optional)

To enable SharpRDP testing:

1. Obtain SharpRDP.exe from [0xthirteen/SharpRDP](https://github.com/0xthirteen/SharpRDP)
2. Place it in `tools/SharpRDP.exe`
3. Rebuild the test binary (SharpRDP will be embedded)

See `tools/README.md` for detailed instructions.

**Note**: SharpRDP execution is local-only (computername=localhost) for safe detection testing.

## Detection Opportunities

1. **Service Query**: sc.exe querying TermService
2. **Registry Access**: reg.exe accessing Terminal Server registry keys
3. **Session Enumeration**: qwinsta.exe execution
4. **Credential Manipulation**: cmdkey.exe /add and /delete operations
5. **Tool Execution**: SharpRDP.exe binary (if present)
6. **Process Chain**: Parent-child relationships from test binary

## Safety Considerations

- All operations are local (no remote RDP connections)
- Test credentials are created and immediately deleted
- No actual lateral movement occurs
- No persistent changes to system state
- SharpRDP uses localhost target for safe testing

## References

- [MITRE ATT&CK T1021.001](https://attack.mitre.org/techniques/T1021/001/)
- [MITRE ATT&CK T1555.004](https://attack.mitre.org/techniques/T1555/004/)
- [SharpRDP GitHub](https://github.com/0xthirteen/SharpRDP)

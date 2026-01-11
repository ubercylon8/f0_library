# Local Account Enumeration

**Test Score**: **8.5/10**

## Overview

This test simulates local account enumeration techniques commonly used by adversaries during initial reconnaissance and credential access phases. It combines native Windows commands with optional Rubeus Kerberos operations to evaluate EDR detection capabilities against account discovery and Kerberoasting attacks.

## MITRE ATT&CK Mapping

- **Tactic**: Defense Evasion, Persistence, Privilege Escalation, Initial Access, Discovery, Credential Access
- **Technique**: T1078.003 - Valid Accounts: Local Accounts
- **Technique**: T1087.001 - Account Discovery: Local Account
- **Technique**: T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

## Test Execution

Simulates the following attack patterns to evaluate defensive capabilities:

### Native Windows Commands (Always Executed)

1. **net user** - Enumerates all local user accounts
2. **net localgroup administrators** - Enumerates members of the local administrators group
3. **whoami /all** - Retrieves current user context including privileges and group memberships
4. **wmic useraccount list brief** - Enumerates user accounts via WMI

### Rubeus Operations (Optional - Requires Tool Placement)

5. **Rubeus kerberoast** - Requests service tickets for SPNs (Kerberoasting)
6. **Rubeus asreproast** - Targets accounts without pre-authentication (AS-REP Roasting)

## Tool Requirements

### Rubeus (Optional)

Rubeus is a C# toolset for raw Kerberos interaction and abuse. To enable Rubeus testing:

1. Obtain Rubeus.exe (see `tools/README.md` for instructions)
2. Place it in `c:\F0\tools\Rubeus.exe` on the target system
3. The test will automatically detect and use Rubeus

**Note**: The test runs successfully without Rubeus - native enumeration patterns are always tested.

## Expected Outcomes

| Exit Code | Outcome | Description |
|-----------|---------|-------------|
| 101 | UNPROTECTED | All enumeration patterns executed successfully without detection |
| 105 | PROTECTED | Rubeus.exe was quarantined on extraction |
| 126 | PROTECTED | EDR blocked one or more enumeration commands |
| 999 | ERROR | Test encountered an error or insufficient privileges |

## Detection Opportunities

1. **net.exe execution** with 'user' or 'localgroup' arguments
2. **whoami.exe execution** with '/all' argument
3. **wmic.exe execution** with 'useraccount' query
4. **Rubeus.exe file signature** detection on extraction
5. **Rubeus.exe process creation** event
6. **Kerberos TGS-REQ** requests for service tickets (Kerberoasting)
7. **AS-REQ** requests without pre-authentication (AS-REP Roasting)
8. **Process command line** patterns indicating enumeration

## Build Instructions

```bash
# Build the test binary
cd tests_source/mitre-top10/b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02/
GOOS=windows GOARCH=amd64 go build -o b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02.exe .

# Or use the gobuild utility
../../utils/gobuild build tests_source/mitre-top10/b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02/

# Sign the binary
../../utils/codesign sign build/b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02/b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02.exe
```

## Deployment

```powershell
# Copy test binary to target
copy b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02.exe c:\F0\

# (Optional) Set up Rubeus for Kerberos testing
mkdir c:\F0\tools
copy Rubeus.exe c:\F0\tools\

# Execute test
c:\F0\b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02.exe
```

## Safety Considerations

- All native commands are **read-only enumeration** - no system modifications
- No password guessing or brute force attacks
- Rubeus operations are **read-only Kerberos queries** - no credential extraction or cracking
- All test artifacts are cleaned up after execution

## References

- [MITRE ATT&CK T1078.003](https://attack.mitre.org/techniques/T1078/003/)
- [MITRE ATT&CK T1087.001](https://attack.mitre.org/techniques/T1087/001/)
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Rubeus - GhostPack](https://github.com/GhostPack/Rubeus)

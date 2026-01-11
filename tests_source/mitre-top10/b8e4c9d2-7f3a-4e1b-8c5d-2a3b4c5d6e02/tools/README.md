# Rubeus Tool Setup

This directory is a placeholder for Rubeus, a C# toolset for raw Kerberos interaction and abuse, used for security testing.

## About Rubeus

[Rubeus](https://github.com/GhostPack/Rubeus) is a C# implementation of Kerberos abuse tooling developed by the GhostPack team. It is commonly used by:

- Red team operators for Kerberos-based attacks
- Penetration testers for Active Directory assessment
- Security researchers studying Kerberos abuse techniques

### Key Features

- **Kerberoasting**: Request TGS tickets for offline cracking
- **AS-REP Roasting**: Target accounts without pre-authentication
- **Ticket Operations**: Dump, renew, and forge Kerberos tickets
- **Delegation Abuse**: Constrained and unconstrained delegation attacks
- **Pass-the-Ticket**: Use captured tickets for authentication

## Prerequisites

1. **.NET Framework 4.0+** must be available on the target system
2. Domain-joined Windows system for full Kerberos functionality
3. Valid domain credentials for most operations
4. Network access to domain controller (TCP 88)

## Obtaining Rubeus

### Option 1: Build from Source (Recommended)

```powershell
# Clone the repository
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus

# Open in Visual Studio and build Release version
# Or use MSBuild
msbuild Rubeus.sln /p:Configuration=Release

# Copy the built binary
copy Rubeus\bin\Release\Rubeus.exe c:\F0\tools\
```

### Option 2: Download Pre-built Binary

Pre-built binaries may be available from:
- GitHub Releases (check GhostPack repository)
- Security tool repositories
- Red team tool collections

**WARNING**: Always verify the integrity and source of pre-built binaries. Malicious actors may distribute backdoored versions of security tools.

### Option 3: Use SharpCollection

The [SharpCollection](https://github.com/Flangvik/SharpCollection) repository maintains regularly updated builds of common C# offensive tools including Rubeus.

## Installation for F0RT1KA Testing

Rubeus is loaded at **runtime** from the target system, not embedded at build time.

1. Obtain Rubeus.exe using one of the methods above
2. Create the tools directory on the target system:

```powershell
mkdir c:\F0\tools
```

3. Place Rubeus.exe in the tools directory:

```
c:\F0\
+-- tools\
    +-- Rubeus.exe   <- Place binary here BEFORE running the test
```

4. Run the F0RT1KA test - it will automatically detect and use Rubeus:

```powershell
c:\F0\b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02.exe
```

**Note**: The test binary does NOT embed Rubeus. This design choice allows:
- Testing without requiring users to build/obtain Rubeus
- Flexibility to test different versions of Rubeus
- Smaller test binary size when Rubeus is not needed
- Testing in environments where Rubeus cannot be obtained

## How the Test Uses Rubeus

The F0RT1KA test executes Rubeus in a **safe, read-only mode**:

### Kerberoasting (T1558.003)
```
Rubeus kerberoast /outfile:hashes.txt /opsec
```

This approach:
- Requests service tickets for SPN-enabled accounts
- Uses /opsec flag for stealthier operation
- Outputs hashes to file (for detection testing only)
- Does NOT perform actual credential cracking

### AS-REP Roasting (T1558.003)
```
Rubeus asreproast /format:hashcat
```

This approach:
- Targets accounts without Kerberos pre-authentication
- Outputs in hashcat format (for detection testing only)
- Does NOT perform actual credential cracking

### Detection Opportunities

When Rubeus executes, security teams should monitor for:

1. **Binary Detection**: Rubeus.exe file signature
2. **Process Execution**: Rubeus.exe process creation
3. **Kerberos Traffic**: TGS-REQ requests for multiple SPNs
4. **AS-REQ Patterns**: Requests without pre-authentication data
5. **Event Logs**: Kerberos service ticket requests (Event ID 4769)
6. **Encryption Types**: RC4 encryption type requests (downgrade)
7. **Command Line**: Rubeus-specific arguments

## Usage Reference (Manual Testing)

For manual security testing (outside F0RT1KA):

### Kerberoasting
```powershell
# Request TGS for all SPNs
Rubeus.exe kerberoast

# Target specific SPN
Rubeus.exe kerberoast /spn:MSSQLSvc/sqlserver.domain.com:1433

# Output to file with opsec mode
Rubeus.exe kerberoast /outfile:hashes.txt /opsec

# Target specific user
Rubeus.exe kerberoast /user:serviceaccount
```

### AS-REP Roasting
```powershell
# Find AS-REP roastable accounts
Rubeus.exe asreproast

# Output in hashcat format
Rubeus.exe asreproast /format:hashcat

# Target specific user
Rubeus.exe asreproast /user:nopreauth
```

### Other Operations (Not Used by This Test)
```powershell
# Dump current TGT
Rubeus.exe dump

# Request TGT
Rubeus.exe asktgt /user:username /password:password

# S4U (delegation abuse)
Rubeus.exe s4u /user:machine$ /impersonateuser:admin /msdsspn:cifs/target
```

## Safety Considerations

- **Only use against authorized test systems**
- **Ensure proper authorization before testing**
- **Document all test activities**
- **Coordinate with SOC/security teams before testing**
- **Be aware of audit and logging implications**
- **Never use against production systems without approval**
- **Kerberos attacks leave traces in Event Logs**
- **Domain controller logging will record ticket requests**

## File Structure

On the target Windows system:

```
c:\F0\
+-- b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02.exe  <- Test binary
+-- tools\
    +-- Rubeus.exe                              <- Rubeus (user-provided)
```

## Verification

To verify Rubeus is detected by the test:

```powershell
# Run the test - it will report Rubeus status
c:\F0\b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02.exe

# Look for output:
# "Rubeus binary found - loading..."
# OR
# "Rubeus not available - see tools/README.md..."
```

## Domain Environment Requirements

For full Kerberoasting testing, the target system should be:

1. **Domain-joined** Windows workstation or server
2. Connected to **domain controller** (TCP 88)
3. Running with valid **domain user credentials**
4. Domain should have **SPN-enabled service accounts** for Kerberoasting
5. Domain should have accounts with **pre-auth disabled** for AS-REP roasting

**Note**: In non-domain environments, Rubeus will still execute (for detection testing) but Kerberos operations will fail with expected errors.

## Rubeus Command Reference

| Operation | Command | Description |
|-----------|---------|-------------|
| Kerberoast | `kerberoast` | Request TGS tickets for SPNs |
| AS-REP Roast | `asreproast` | Target no-preauth accounts |
| Dump | `dump` | Dump current Kerberos tickets |
| Triage | `triage` | Display ticket information |
| Ask TGT | `asktgt` | Request TGT with credentials |
| Ask TGS | `asktgs` | Request TGS for SPN |
| S4U | `s4u` | Perform S4U2Self/S4U2Proxy |
| PTT | `ptt` | Pass-the-ticket |
| Harvest | `harvest` | Monitor for tickets |

## References

- [Rubeus GitHub Repository](https://github.com/GhostPack/Rubeus)
- [Rubeus Documentation](https://github.com/GhostPack/Rubeus/wiki)
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Kerberoasting Deep Dive](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
- [AS-REP Roasting](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
- [Kerberoasting Detection](https://adsecurity.org/?p=2293)

## Legal Notice

Rubeus and this test are provided for **authorized security testing purposes only**. Ensure you have proper written authorization before testing Kerberos attacks against any system. Unauthorized access to computer systems is illegal and may result in criminal prosecution. Kerberoasting and AS-REP roasting are sensitive operations that may trigger security alerts.

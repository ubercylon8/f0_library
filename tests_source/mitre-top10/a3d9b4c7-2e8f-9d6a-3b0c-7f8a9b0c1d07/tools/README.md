# Seatbelt Tool Setup

This directory is a placeholder for Seatbelt, a comprehensive host security enumeration tool used for security testing.

## About Seatbelt

[Seatbelt](https://github.com/GhostPack/Seatbelt) is a C# project by GhostPack that performs numerous security-oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives. It is commonly used by:

- Red team operators for comprehensive host reconnaissance
- Penetration testers for security posture assessment
- Security researchers studying enumeration techniques
- Ransomware operators for pre-encryption reconnaissance (malicious use)

### Key Features

- **60+ Security Checks**: Comprehensive host enumeration
- **Grouped Execution**: Run all checks or specific groups
- **Credential Discovery**: Find stored credentials and vault entries
- **Security Assessment**: Check AppLocker, Defender, firewall configurations
- **Browser Enumeration**: Extract browser history and saved credentials
- **Network Discovery**: DNS cache, shares, ARP table enumeration

### Check Groups

| Group | Description |
|-------|-------------|
| `all` | Run all checks (comprehensive) |
| `user` | Current user and session info |
| `system` | OS, processes, services info |
| `misc` | Miscellaneous security checks |
| `credential` | Credential-related checks |
| `browser` | Browser history and credentials |

## Prerequisites

1. **.NET Framework 4.0+** must be available on the target system
2. Some checks require **Administrator privileges**
3. Some checks may require **specific Windows versions**

## Obtaining Seatbelt

### Option 1: Build from Source (Recommended)

Building from source ensures you have a clean, unmodified binary.

```powershell
# Clone the repository
git clone https://github.com/GhostPack/Seatbelt.git
cd Seatbelt

# Open Seatbelt.sln in Visual Studio
# Build Release configuration (Any CPU)

# Or use MSBuild from Developer Command Prompt
msbuild /p:Configuration=Release Seatbelt.sln

# Binary will be at:
# Seatbelt\bin\Release\Seatbelt.exe
```

### Option 2: Download Pre-built Binary

Pre-built binaries may be available from:
- GitHub Releases (if provided by GhostPack)
- Security tool repositories
- Red team tool collections

**WARNING**: Always verify the integrity and source of pre-built binaries. Malicious actors may distribute backdoored versions of security tools. Build from source when possible.

### Option 3: Use Existing Collection

If you have an existing red team toolkit or GhostPack collection, locate Seatbelt.exe and copy it to this directory.

## Installation for F0RT1KA Testing

Seatbelt is loaded at **runtime** from the target system, not embedded at build time. This design allows:
- Testing without requiring users to build/obtain Seatbelt
- Flexibility to test different versions of Seatbelt
- Smaller test binary size when Seatbelt is not needed
- Separation of offensive tools from test framework

### Installation Steps

1. Obtain Seatbelt.exe using one of the methods above

2. Create the tools directory on the target system:

```powershell
mkdir c:\F0\tools
```

3. Place Seatbelt.exe in the tools directory:

```
c:\F0\
|-- a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07.exe  <- Test binary
|-- tools\
    |-- Seatbelt.exe                            <- Place binary here BEFORE running the test
```

4. Run the F0RT1KA test - it will automatically detect and use Seatbelt:

```powershell
c:\F0\a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07.exe
```

## How the Test Uses Seatbelt

The F0RT1KA test executes Seatbelt in two modes:

### Mode 1: Comprehensive Enumeration

```
Seatbelt.exe -group=all
```

This runs all 60+ security checks, including:
- CurrentUser, LocalGroups, DomainInfo
- OSInfo, Processes, Services, InstalledProducts
- EnvironmentVariables, NTLMSettings
- WindowsDefenderSettings, AppLockerSettings
- FirewallRules, NetworkShares
- And many more...

### Mode 2: Credential Enumeration

```
Seatbelt.exe WindowsCredentialFiles WindowsVault InterestingFiles
```

Targeted checks for:
- **WindowsCredentialFiles**: Windows Credential Manager files
- **WindowsVault**: Windows Vault stored credentials
- **InterestingFiles**: Files with potentially sensitive content

## Detection Opportunities

When Seatbelt executes, security teams should monitor for:

1. **Binary Detection**: Seatbelt.exe file signature/hash
2. **Process Execution**: Seatbelt.exe process creation
3. **Arguments**: -group=all, WindowsCredentialFiles, etc.
4. **Behavioral Patterns**: Rapid enumeration of multiple system areas
5. **Registry Access**: Queries to security-related registry keys
6. **File Access**: Access to credential storage locations
7. **WMI Queries**: System information gathering

### Common Seatbelt Hashes (Reference)

**Note**: Hashes vary by build. These are examples from known versions:

| Version | SHA256 |
|---------|--------|
| Build from source | (Calculate after building) |

Always verify binaries match expected hashes.

## Usage Reference (Manual Testing)

For manual security testing (outside F0RT1KA):

```powershell
# Run all checks
Seatbelt.exe -group=all

# Run specific check groups
Seatbelt.exe -group=user
Seatbelt.exe -group=system
Seatbelt.exe -group=credential

# Run specific checks
Seatbelt.exe WindowsCredentialFiles WindowsVault
Seatbelt.exe OSInfo Processes Services
Seatbelt.exe AppLockerSettings WindowsDefenderSettings

# Output to file
Seatbelt.exe -group=all > seatbelt_output.txt

# Run with elevated privileges (recommended)
runas /user:Administrator "Seatbelt.exe -group=all"
```

## Safety Considerations

- **Only use against authorized test systems**
- **Ensure proper authorization before testing**
- **Document all test activities**
- **Coordinate with SOC/security teams before testing**
- **Be aware of audit and logging implications**
- **Never use against production systems without explicit approval**
- **Some checks may cause alerts or trigger incident response**

## File Structure

On the target Windows system:

```
c:\F0\
|-- a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07.exe     <- F0RT1KA test binary
|-- tools\
    |-- Seatbelt.exe                              <- Seatbelt (user-provided)
```

After test execution (if Seatbelt is available):

```
c:\F0\
|-- a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07.exe
|-- Seatbelt.exe                                   <- Copied from tools for execution
|-- seatbelt_groupall_output.txt                   <- Output from -group=all
|-- seatbelt_credentials_output.txt                <- Output from credential checks
|-- tools\
    |-- Seatbelt.exe
```

## Verification

To verify Seatbelt is detected by the test:

```powershell
# Run the test - it will report Seatbelt status
c:\F0\a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07.exe

# Look for output:
# "Seatbelt binary found - extracting..."
# OR
# "Seatbelt not available - see tools/README.md for instructions"
```

## Test Without Seatbelt

The test will still run valuable enumeration tests without Seatbelt:

- Recursive file enumeration (dir /s /b)
- Extension-based filtering
- Target list generation

Seatbelt phases will be marked as "skipped" in the results.

## References

- [GhostPack Seatbelt Repository](https://github.com/GhostPack/Seatbelt)
- [Seatbelt Wiki](https://github.com/GhostPack/Seatbelt/wiki)
- [MITRE ATT&CK T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [MITRE ATT&CK T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [GhostPack Tools Overview](https://specterops.io/tools/)

## Legal Notice

Seatbelt and this test are provided for **authorized security testing purposes only**. Ensure you have proper written authorization before testing enumeration techniques against any system. Unauthorized access to computer systems and unauthorized collection of system information is illegal and may result in criminal prosecution.

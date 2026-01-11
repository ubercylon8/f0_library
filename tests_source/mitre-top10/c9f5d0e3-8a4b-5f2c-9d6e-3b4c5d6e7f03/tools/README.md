# SharpRDP Tool Setup

This directory is a placeholder for SharpRDP, a headless RDP command execution tool used for security testing.

## About SharpRDP

[SharpRDP](https://github.com/0xthirteen/SharpRDP) is a C# application that enables command execution over RDP without spawning a full graphical session. It is commonly used by:

- Red team operators for stealthy lateral movement
- Penetration testers for RDP-based attack simulation
- Security researchers studying RDP abuse techniques

### Key Features

- Headless RDP command execution
- No interactive GUI session required
- Supports command execution via RDP protocol
- Works with credentials or current session context

## Prerequisites

1. **.NET Framework 4.0+** must be available on the target system
2. Valid credentials for RDP authentication (for remote targets)
3. RDP service must be running on the target

## Obtaining SharpRDP

### Option 1: Build from Source (Recommended)

```powershell
# Clone the repository
git clone https://github.com/0xthirteen/SharpRDP.git
cd SharpRDP

# Open in Visual Studio and build Release version
# Or use MSBuild
msbuild /p:Configuration=Release

# Copy the built binary
copy bin\Release\SharpRDP.exe c:\F0\tools\
```

### Option 2: Download Pre-built Binary

Pre-built binaries may be available from:
- GitHub Releases (if provided by author)
- Security tool repositories
- Red team tool collections

**WARNING**: Always verify the integrity and source of pre-built binaries. Malicious actors may distribute backdoored versions of security tools.

## Installation for F0RT1KA Testing

SharpRDP is loaded at **runtime** from the target system, not embedded at build time.

1. Obtain SharpRDP.exe using one of the methods above
2. Create the tools directory on the target system:

```powershell
mkdir c:\F0\tools
```

3. Place SharpRDP.exe in the tools directory:

```
c:\F0\
└── tools\
    └── SharpRDP.exe   <- Place binary here BEFORE running the test
```

4. Run the F0RT1KA test - it will automatically detect and use SharpRDP:

```powershell
c:\F0\c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03.exe
```

**Note**: The test binary does NOT embed SharpRDP. This design choice allows:
- Testing without requiring users to build/obtain SharpRDP
- Flexibility to test different versions of SharpRDP
- Smaller test binary size when SharpRDP is not needed

## How the Test Uses SharpRDP

The F0RT1KA test executes SharpRDP in a **safe, local-only mode**:

```
SharpRDP computername=localhost command=whoami
```

This approach:
- Does NOT perform actual lateral movement
- Tests EDR detection of SharpRDP binary
- Tests EDR detection of SharpRDP execution patterns
- Uses localhost as the target for safety

### Detection Opportunities

When SharpRDP executes, security teams should monitor for:

1. **Binary Detection**: SharpRDP.exe file signature
2. **Process Execution**: SharpRDP.exe process creation
3. **RDP API Calls**: Windows Terminal Services API usage
4. **Network Traffic**: RDP protocol activity (even to localhost)
5. **Credential Usage**: Authentication events with RDP context
6. **Process Chain**: Unusual parent process spawning SharpRDP

## Usage Reference (Manual Testing)

For manual security testing (outside F0RT1KA):

```powershell
# Execute command on remote host (requires valid credentials)
SharpRDP.exe computername=TARGET command="whoami" username=DOMAIN\user password=P@ssw0rd

# Execute with restricted admin
SharpRDP.exe computername=TARGET command="hostname" username=DOMAIN\user password=P@ssw0rd restricted=true

# Execute with alternate shell
SharpRDP.exe computername=TARGET command="net user" username=DOMAIN\user password=P@ssw0rd exec=powershell
```

## Safety Considerations

- **Only use against authorized test systems**
- **Ensure proper authorization before testing**
- **Document all test activities**
- **Coordinate with SOC/security teams before testing**
- **Be aware of audit and logging implications**
- **Never use against production systems without approval**

## File Structure

On the target Windows system:

```
c:\F0\
├── c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03.exe  <- Test binary
└── tools\
    └── SharpRDP.exe                            <- SharpRDP (user-provided)
```

## Verification

To verify SharpRDP is detected by the test:

```powershell
# Run the test - it will report SharpRDP status
c:\F0\c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03.exe

# Look for output:
# "SharpRDP binary found - loading..."
# OR
# "SharpRDP not available - see tools/README.md..."
```

## References

- [SharpRDP GitHub Repository](https://github.com/0xthirteen/SharpRDP)
- [MITRE ATT&CK T1021.001](https://attack.mitre.org/techniques/T1021/001/)
- [RDP Abuse Detection Strategies](https://www.elastic.co/guide/en/security/current/rdp-enabled-via-registry.html)

## Legal Notice

SharpRDP and this test are provided for **authorized security testing purposes only**. Ensure you have proper written authorization before testing RDP lateral movement techniques against any system. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

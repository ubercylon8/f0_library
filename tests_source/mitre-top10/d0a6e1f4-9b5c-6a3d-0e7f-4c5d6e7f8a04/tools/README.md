# wmiexec-Pro Tool Setup

This directory is a placeholder for the wmiexec-Pro tool, which enables advanced WMI-based execution testing.

## About wmiexec-Pro

[wmiexec-Pro](https://github.com/XiaoliChan/wmiexec-Pro) is an enhanced version of the classic Impacket wmiexec tool that provides:

- Stealthier WMI execution patterns
- Semi-interactive shell support
- Improved output handling
- OPSEC-aware operation modes

## Prerequisites

1. **Python 3.x** must be installed on the target Windows system
2. Required Python packages (will be installed with wmiexec-Pro)

## Installation Instructions

### Option 1: Direct Download

```powershell
# Download wmiexec-Pro from GitHub
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/XiaoliChan/wmiexec-Pro/master/wmiexec-Pro.py" -OutFile "c:\F0\tools\wmiexec-Pro.py"

# Install dependencies
pip install impacket
```

### Option 2: Clone Repository

```powershell
# Clone the repository
cd c:\F0\tools
git clone https://github.com/XiaoliChan/wmiexec-Pro.git

# Install dependencies
cd wmiexec-Pro
pip install -r requirements.txt
```

## Usage Notes

**IMPORTANT**: This test does NOT automatically execute wmiexec-Pro for remote WMI operations. The tool is provided as a placeholder for manual security testing.

### Typical Usage (Manual Testing)

```powershell
# Basic usage (requires target credentials)
python c:\F0\tools\wmiexec-Pro.py DOMAIN/username:password@target_ip

# With hash authentication
python c:\F0\tools\wmiexec-Pro.py DOMAIN/username@target_ip -hashes :NT_HASH

# Execute single command
python c:\F0\tools\wmiexec-Pro.py DOMAIN/username:password@target_ip "whoami"
```

### Detection Opportunities

When wmiexec-Pro is executed, security teams should monitor for:

1. **DCE/RPC Traffic**: Port 135 connections to remote hosts
2. **WMI Provider Activity**: wmiprvse.exe spawning processes on remote systems
3. **DCOM Activation**: Service Control Manager activity
4. **Authentication Events**: 4624/4625 logon events with WMI/DCOM correlation
5. **Process Creation**: Unusual parent-child relationships from WMI

### Safety Considerations

- Only use against authorized test systems
- Ensure proper network segmentation during testing
- Document all test activities
- Be aware of audit/logging implications
- Coordinate with SOC before testing

## File Placement

Place the wmiexec-Pro tool in this directory:

```
c:\F0\tools\
├── wmiexec-Pro.py      <- Main tool (required)
├── README.md           <- This file
└── [dependencies]      <- Any additional files
```

The F0RT1KA test will automatically detect if the tool is present and log its availability.

## References

- [wmiexec-Pro GitHub Repository](https://github.com/XiaoliChan/wmiexec-Pro)
- [Impacket Project](https://github.com/fortra/impacket)
- [MITRE ATT&CK T1047](https://attack.mitre.org/techniques/T1047/)

## Legal Notice

This tool is provided for authorized security testing purposes only. Ensure you have proper authorization before testing WMI execution against any system. Unauthorized access to computer systems is illegal.

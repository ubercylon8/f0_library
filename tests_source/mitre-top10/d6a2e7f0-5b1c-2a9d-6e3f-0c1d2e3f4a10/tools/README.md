# NetExec Tools Directory

This directory is for placing NetExec (nxc.exe) for advanced service enumeration testing.

## About NetExec

NetExec (formerly CrackMapExec) is a network service enumeration and exploitation tool commonly used in red team engagements and penetration testing. This test uses it to evaluate EDR detection of SMB-based service enumeration.

## How to Add NetExec

1. **Download NetExec** from the official repository:
   - GitHub: https://github.com/Pennyw0rth/NetExec
   - Releases: https://github.com/Pennyw0rth/NetExec/releases

2. **Extract nxc.exe** and place it in this directory:
   ```
   c:\F0\tools\nxc.exe
   ```

3. **Re-run the test** - it will automatically detect and use NetExec

## Test Behavior

### If nxc.exe IS Present:
- Test executes: `nxc smb 127.0.0.1 -u test -p test --services`
- This performs **local-only** SMB service enumeration against localhost
- Authentication will fail (expected) but tool execution is tested
- EDR should detect/block the enumeration attempt

### If nxc.exe IS NOT Present:
- Test skips the NetExec phase
- Other service query tests still run
- Log indicates NetExec was not available

## Why Test NetExec?

NetExec is commonly used by attackers to:
- Enumerate services across network hosts via SMB
- Identify running security services (potential targets)
- Map service configurations before lateral movement

Detecting NetExec execution is important because:
- T1489 (Service Stop) often follows service enumeration
- SMB-based enumeration is a common lateral movement precursor
- Red teams frequently use NetExec in assessments

## Safety Notes

- Test only runs against **localhost (127.0.0.1)**
- Uses **dummy credentials** that will fail authentication
- No actual service control is performed
- Network traffic stays local

## Expected Detection Opportunities

1. **Process creation**: nxc.exe execution
2. **Network activity**: SMB connection to 127.0.0.1:445
3. **Command line**: Contains `--services` flag
4. **Tool signature**: NetExec binary hash/signature

## File Placement

```
c:\F0\
  ├── d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10.exe  # Main test binary
  └── tools\
      ├── nxc.exe                                 # Place NetExec here
      ├── nxc_output.txt                          # Output captured during test
      └── README.md                               # This file
```

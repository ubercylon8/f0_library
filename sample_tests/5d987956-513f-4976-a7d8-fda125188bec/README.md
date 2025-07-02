# Remote Services: RDP

This VST attempts to utilize a platform-native tool to simulate initiating a connection to a remote host over RDP. Remote interactive graphical user sessions are prevalent, and commonly utilized both by everyday users and administrators, as well as threat actors and malware, for many different reasons. Microsoft's version of this feature is named Remote Desktop Protocol.

## How

> Safety: this test does not modify the local host in a harmful manner.

Steps:

1. Attempt to initiate an RDP connection to the local host by invoking the Windows-native Microsoft Terminal Services Client (mstsc) program. If this step encounters an error, exit `PROTECTED`
2. If mstsc exists after a 5-second sleep, the Powershell scriptlet attempts to kill the process.
3. If no error is encountered, exit `UNPROTECTED`

Example Output:
```bash
 [2024-07-29T09:00:41][5d987956-513f-4976-a7d8-fda125188bec] Starting test at: 2024-07-29T09:00:41
 [2024-07-29T09:00:41][5d987956-513f-4976-a7d8-fda125188bec] Attempting to issue RDP connection command
 [2024-07-29T09:00:46][5d987956-513f-4976-a7d8-fda125188bec] Successfully issued RDP command, exiting test
 [2024-07-29T09:00:46][5d987956-513f-4976-a7d8-fda125188bec] Completed with code: 101
 [2024-07-29T09:00:46][5d987956-513f-4976-a7d8-fda125188bec] Exit called from line: 33
 [2024-07-29T09:00:46][5d987956-513f-4976-a7d8-fda125188bec] Ending test at: 2024-07-29T09:00:46; ;
```

## Resolution

If this test succeeds:

* Ensure that the host is supposed to be configured to listen for incoming RDP connections.
* Administrators should attempt to secure their networks and users via best practices using a defense-in-depth approach.

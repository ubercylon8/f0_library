# Malicious Office Document

This VST attempts to achieve code execution by dropping and executing a Microsoft Office Word document that has been embedded with a macro. This is a famous and often-used malicious code execution proxy that is regularly deployed in spear-phishing campaigns to establish initial access to one or more victim machines. The macro in the test's document is written to launch PowerShell, and, ultimately, write a text file to the testing directory to prove successful code execution.

## How

> Safety: the macro only writes a text file to the testing directory on the host.

Steps:

1. Assess whether Word is installed on the victim machine and ascertain its version. If not installed, exit `NOTRELEVANT`
2. Modify the current user's registry to allow for automatic macro execution on the host
3. Extract the malicious macro-embedded Word document to the testing directory
4. Open the document to invoke the embedded macro
5. Check for the existence of the IoC text file in the testing directory
6. If the file exists and cleanup procedures succeed, exit `UNPROTECTED`. If cleanup fails, exit `ERROR`. Else exit `PROTECTED`

Example Output:
```bash
[2024-10-19T06:12:11][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Starting test at: 2024-10-19T06:12:11
[2024-10-19T06:12:11][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Writing dropper executable to disk
[2024-10-19T06:12:11][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Performing normal file write
[2024-10-19T06:12:11][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Wrote dropper successfully
[2024-10-19T06:12:11][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Setting socket path
[2024-10-19T06:12:11][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Checking for existence and version of installed Office software
[2024-10-19T06:12:11][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Word version 16.0 found
[2024-10-19T06:12:11][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Getting macro allowance setting for current user
[2024-10-19T06:12:11][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Initial macro allowance setting is "4"
[2024-10-19T06:12:11][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Setting macro allowance setting
[2024-10-19T06:12:11][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Successfully set macro allowance in registry
[2024-10-19T06:12:12][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Current macro allowance setting is "1"
[2024-10-19T06:12:12][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Writing maldoc to testing directory
[2024-10-19T06:12:12][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Performing IPC-style file write
[2024-10-19T06:12:12][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Launching C:\Users\victim\Desktop\b74ad239-2ddd-4b1e-b608-8397a43c7c54_f0rtika_dropper.exe
[2024-10-19T06:12:12][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Started dropper child process with PID 11084
[2024-10-19T06:12:12][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Waiting for 3 seconds
[2024-10-19T06:12:15][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Connecting to socket: C:\Users\victim\Desktop\f0rtika_socket
[2024-10-19T06:12:15][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Connected to socket!
[2024-10-19T06:12:15][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Waiting for 1 seconds
[2024-10-19T06:12:16][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Killing dropper child process
[2024-10-19T06:12:16][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Clearing socket path
[2024-10-19T06:12:16][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Waiting for 3 seconds
[2024-10-19T06:12:19][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Successfully wrote maldoc to testing directory
[2024-10-19T06:12:19][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Opening maldoc
[2024-10-19T06:12:19][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Waiting for 1 seconds
[2024-10-19T06:12:20][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Found IoC text file
[2024-10-19T06:12:20][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Attempting to kill WINWORD.exe
[2024-10-19T06:12:20][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Cleaning up
[2024-10-19T06:12:20][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Reversion successful
[2024-10-19T06:12:20][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Completed with code: 101
[2024-10-19T06:12:20][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Exit called from line: 135
[2024-10-19T06:12:20][b74ad239-2ddd-4b1e-b608-8397a43c7c54] Ending test at: 2024-10-19T06:12:20
```

## Resolution

If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

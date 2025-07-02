# AS-REP Roasting via Rubeus

This VST attempts to perform AS-REP roasting on the host system by utilizing the well-known Rubeus tool. Rubeus exploits the Windows Kerberos authentication system to extract user credentials for use in post-compromise privilege escalation and lateral movement. AS-REP roasting is an attack technique that takes advantage of domain users that do not have required Kerberos pre-authentication configured.

## How

 > Safety: this test does not modify the host system in any harmful way, and does not attempt to exfiltrate nor utilize any credentials it successfully acquires.

Steps:

 1. Determine whether the test is running inside of an Active Directory domain. Exit `NOTRELEVANT` if it is not
 2. Attempt to extract the embedded `Rubeus.exe` tool to disk. Exit `PROTECTED` if Rubeus is quarantined.
 2. Invoke Rubeus' AS-REP roasting utility via `cmd.exe`. Exit `PROTECTED` if this step errors.
 3. If no error is encountered, exit `UNPROTECTED`.

 Example Output:
 ```bash
 [2024-08-15T16:07:23][028e463a-5ba1-4276-8e3a-b3282bb4414f] Starting test at: 2024-08-15T16:07:23
 [2024-08-15T16:07:23][028e463a-5ba1-4276-8e3a-b3282bb4414f] Writing dropper executable to disk 
 [2024-08-15T16:07:23][028e463a-5ba1-4276-8e3a-b3282bb4414f] Performing normal file write       
 [2024-08-15T16:07:23][028e463a-5ba1-4276-8e3a-b3282bb4414f] Wrote dropper successfully
 [2024-08-15T16:07:23][028e463a-5ba1-4276-8e3a-b3282bb4414f] Setting socket path
 [2024-08-15T16:07:23][028e463a-5ba1-4276-8e3a-b3282bb4414f] Extracting file for quarantine test [2024-08-15T16:07:23][028e463a-5ba1-4276-8e3a-b3282bb4414f] Performing IPC-style file write    
 [2024-08-15T16:07:23][028e463a-5ba1-4276-8e3a-b3282bb4414f] Launching C:\Users\Public\.vst\028e463a-5ba1-4276-8e3a-b3282bb4414f_f0rtika_dropper.exe
 [2024-08-15T16:07:23][028e463a-5ba1-4276-8e3a-b3282bb4414f] Started dropper child process with 
PID 14028
 [2024-08-15T16:07:23][028e463a-5ba1-4276-8e3a-b3282bb4414f] Waiting for 3 seconds
 [2024-08-15T16:07:26][028e463a-5ba1-4276-8e3a-b3282bb4414f] Connecting to socket: C:\Users\Public\.vst\f0rtika_socket
 [2024-08-15T16:07:26][028e463a-5ba1-4276-8e3a-b3282bb4414f] Connected to socket!
 [2024-08-15T16:07:26][028e463a-5ba1-4276-8e3a-b3282bb4414f] Waiting for 1 seconds
 [2024-08-15T16:07:27][028e463a-5ba1-4276-8e3a-b3282bb4414f] Killing dropper child process      
 [2024-08-15T16:07:27][028e463a-5ba1-4276-8e3a-b3282bb4414f] Clearing socket path
 [2024-08-15T16:07:27][028e463a-5ba1-4276-8e3a-b3282bb4414f] Waiting for 3 seconds
 [2024-08-15T16:07:30][028e463a-5ba1-4276-8e3a-b3282bb4414f] Malicious file was not caught      
 [2024-08-15T16:07:30][028e463a-5ba1-4276-8e3a-b3282bb4414f] Executing Rubeus
 [2024-08-15T16:07:30][028e463a-5ba1-4276-8e3a-b3282bb4414f] Rubeus was not blocked
 [2024-08-15T16:07:30][028e463a-5ba1-4276-8e3a-b3282bb4414f] Completed with code: 101
 [2024-08-15T16:07:30][028e463a-5ba1-4276-8e3a-b3282bb4414f] Exit called from line: 65
 [2024-08-15T16:07:30][028e463a-5ba1-4276-8e3a-b3282bb4414f] Ending test at: 2024-08-15T16:07:30; ;
 EXIT CODE: 101
 ```

## Resolution

 If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.


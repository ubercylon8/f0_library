# Pass-the-Ticket

This test attempts to execute the pass-the-ticket credential theft technique by first extracting Kerberos tickets from the Local Security Authority Subsystem Service (LSASS) process and then applying the ticket to the current logon session. This technique is commonly leveraged in Active Directory environments to facilitate lateral movement, especially in situations where access to raw credentials (e.g., cleartext passwords) is not possible, as it allows an attacker to impersonate another user of the system.

## How

> Safety: command execution does not attempt to modify the system in any harmful way.

Steps:

1. Assess whether the VST process is running with sufficient privileges. If not, exit `NOTRELEVANT`
2. Perform a check to determine if the endpoint is connected to Active Directory. If not, exit `NOTRELEVANT`
3. Extract Rubeus to disk.
4. Wait for 3 seconds to gauge defenses.
5. Exit PROTECTED if Rubeus was quarantined and continue if not.
6. Extract Mimikatz to disk.
7. Wait for 3 seconds to gauge defenses.
8. Exit PROTECTED if Mimikatz was quarantined and continue if not.
9. Execute Mimikatz to dump local Kerberos tickets to a `.kirbi` file. If no kirbi file is found, exit PROTECTED. If so, continue.
10. Execute Rubeus to import the `.kirbi` file and apply the ticket to the current logon session.
11. Exit PROTECTED if the test is stopped. UNPROTECTED if not.

Example Output:
```bash
[2024-08-22T12:58:25][a938af6c-808d-4db8-90df-7ce97ec70cc9] Starting test at: 2024-08-22T12:58:25
[2024-08-22T12:58:25][a938af6c-808d-4db8-90df-7ce97ec70cc9] Writing dropper executable to disk
[2024-08-22T12:58:25][a938af6c-808d-4db8-90df-7ce97ec70cc9] Performing normal file write
[2024-08-22T12:58:25][a938af6c-808d-4db8-90df-7ce97ec70cc9] Wrote dropper successfully
[2024-08-22T12:58:25][a938af6c-808d-4db8-90df-7ce97ec70cc9] Setting socket path
[2024-08-22T12:58:25][a938af6c-808d-4db8-90df-7ce97ec70cc9] Performing IPC-style file write
[2024-08-22T12:58:25][a938af6c-808d-4db8-90df-7ce97ec70cc9] Launching C:\Users\Administrator.client\Desktop\a938af6c-808d-4db8-90df-7ce97ec70cc9_f0rtika_dropper.exe
[2024-08-22T12:58:25][a938af6c-808d-4db8-90df-7ce97ec70cc9] Started dropper child process with PID 7696
[2024-08-22T12:58:25][a938af6c-808d-4db8-90df-7ce97ec70cc9] Waiting for 3 seconds
[2024-08-22T12:58:28][a938af6c-808d-4db8-90df-7ce97ec70cc9] Connecting to socket: C:\Users\Administrator.client\Desktop\f0rtika_socket
[2024-08-22T12:58:28][a938af6c-808d-4db8-90df-7ce97ec70cc9] Connected to socket!
[2024-08-22T12:58:28][a938af6c-808d-4db8-90df-7ce97ec70cc9] Waiting for 1 seconds
[2024-08-22T12:58:29][a938af6c-808d-4db8-90df-7ce97ec70cc9] Killing dropper child process
[2024-08-22T12:58:29][a938af6c-808d-4db8-90df-7ce97ec70cc9] Clearing socket path
[2024-08-22T12:58:29][a938af6c-808d-4db8-90df-7ce97ec70cc9] Waiting for 3 seconds
[2024-08-22T12:58:32][a938af6c-808d-4db8-90df-7ce97ec70cc9] Writing dropper executable to disk
[2024-08-22T12:58:32][a938af6c-808d-4db8-90df-7ce97ec70cc9] Performing normal file write
[2024-08-22T12:58:32][a938af6c-808d-4db8-90df-7ce97ec70cc9] Wrote dropper successfully
[2024-08-22T12:58:32][a938af6c-808d-4db8-90df-7ce97ec70cc9] Setting socket path
[2024-08-22T12:58:32][a938af6c-808d-4db8-90df-7ce97ec70cc9] Performing IPC-style file write
[2024-08-22T12:58:32][a938af6c-808d-4db8-90df-7ce97ec70cc9] Launching C:\Users\Administrator.client\Desktop\a938af6c-808d-4db8-90df-7ce97ec70cc9_f0rtika_dropper.exe
[2024-08-22T12:58:32][a938af6c-808d-4db8-90df-7ce97ec70cc9] Started dropper child process with PID 7864
[2024-08-22T12:58:32][a938af6c-808d-4db8-90df-7ce97ec70cc9] Waiting for 3 seconds
[2024-08-22T12:58:35][a938af6c-808d-4db8-90df-7ce97ec70cc9] Connecting to socket: C:\Users\Administrator.client\Desktop\f0rtika_socket
[2024-08-22T12:58:35][a938af6c-808d-4db8-90df-7ce97ec70cc9] Connected to socket!
[2024-08-22T12:58:35][a938af6c-808d-4db8-90df-7ce97ec70cc9] Waiting for 1 seconds
[2024-08-22T12:58:37][a938af6c-808d-4db8-90df-7ce97ec70cc9] Killing dropper child process
[2024-08-22T12:58:37][a938af6c-808d-4db8-90df-7ce97ec70cc9] Clearing socket path
[2024-08-22T12:58:37][a938af6c-808d-4db8-90df-7ce97ec70cc9] Waiting for 3 seconds
[2024-08-22T12:58:40][a938af6c-808d-4db8-90df-7ce97ec70cc9] Executing Mimikatz
[2024-08-22T12:58:40][a938af6c-808d-4db8-90df-7ce97ec70cc9] Mimikatz was not blocked
[2024-08-22T12:58:40][a938af6c-808d-4db8-90df-7ce97ec70cc9] Found exported ticket kirbi files!
[2024-08-22T12:58:40][a938af6c-808d-4db8-90df-7ce97ec70cc9] Executing Rubeus
[2024-08-22T12:58:42][a938af6c-808d-4db8-90df-7ce97ec70cc9]
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3


[*] Action: Import Ticket
[+] Ticket successfully imported!

[2024-08-22T12:58:42][a938af6c-808d-4db8-90df-7ce97ec70cc9] Rubeus was not blocked
[2024-08-22T12:58:42][a938af6c-808d-4db8-90df-7ce97ec70cc9] Completed with code: 101
[2024-08-22T12:58:42][a938af6c-808d-4db8-90df-7ce97ec70cc9] Exit called from line: 128
[2024-08-22T12:58:42][a938af6c-808d-4db8-90df-7ce97ec70cc9] Ending test at: 2024-08-22T12:58:42
```

## Resolution

If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

# Spoof Parent Process ID

This VST attempts to demonstrate a method of defense evasion whereby process lineage is falsified. It does this by abusing the Process Thread Attributes List data structure via a series of calls to the Win32 API. Successfully implementing this technique can potentially reduce the overall suspicion of a malicious process created by the threat actor, as well as, in certain circumstances, permit elevation of privileges which require some demonstration of child process lineage to a privileged parent process.

## How

 > Safety: this VST does not modify the victim system in any harmful way

Steps:

 1. Create a process from which the child shall inherit the spoofed PID
 2. Open a handle to the parent process
 3. Use the Win32 API to construct a process thread attribute list in memory
 4. Modify the process thread attribute list to falsify child process lineage with the Win32 API
 5. Create the child process with the crafted process thread attribute list
 6. Wait for 5 seconds to gauge defensive reaction
 7. Terminate both the parent and child processes
 8. If no errors are encountered prior to this point in the test, exit `UNPROTECTED`. Else exit `PROTECTED`

 Example Output:
 ```bash
 [2024-07-01T10:35:56][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Starting test at: 2024-07-01T10:35:56
 [2024-07-01T10:35:56][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Creating new child process with spoofed parent process ID
 [2024-07-01T10:35:56][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Created parent process with PID 10148
 [2024-07-01T10:35:56][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Got parent process handle 376
 [2024-07-01T10:35:56][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Initializing process thread attribute list
 [2024-07-01T10:35:56][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Successfully initialized process thread attribute list
 [2024-07-01T10:35:56][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Updating attribute list
 [2024-07-01T10:35:56][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Updated proc thread attribute list
 [2024-07-01T10:35:56][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Creating child process with commandline "C:\Windows\System32\RuntimeBroker.exe -f0rtikaSecurity" and spoofed parent PID 10148
 [2024-07-01T10:35:56][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Successfully created child process with PID 632
 [2024-07-01T10:35:56][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Waiting 5 seconds before terminating parent and child processes
 [2024-07-01T10:35:56][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Waiting for 5 seconds
 [2024-07-01T10:36:01][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Terminating parent process
 [2024-07-01T10:36:01][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Terminated parent process
 [2024-07-01T10:36:01][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Terminating child process
 [2024-07-01T10:36:01][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Terminated child process
 [2024-07-01T10:36:01][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Successfully spoofed parent process information in child process
 [2024-07-01T10:36:01][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Completed with code: 101
 [2024-07-01T10:36:01][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Exit called from line: 184
 [2024-07-01T10:36:01][f40d0de8-23de-4a5a-825b-d2f9f77dbf6e] Ending test at: 2024-07-01T10:36:01
 ```

## Resolution

 If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

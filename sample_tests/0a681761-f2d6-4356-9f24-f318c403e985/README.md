# Impair Defenses: Indicator Blocking

This VST simulates how a threat actor or malicious program might inhibit a system's ability to log their activities by changing where the system records its observations of their actions. It does this by modifying a registry key to redirect the Windows Security Event Log's log file path. This takes effect immediately, and does not require a reboot of the system.

## How

> Safety: any changes made by this test are reverted at the conclusion of its procedures.

Steps:
1. Assess whether the test process is running with sufficient privileges to conduct its evaluation. Exit `NOTRELEVANT` if it is not
2. Get the current Security event log file path by querying the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security` registry key
3. Change the log file path by using PowerShell. If this step fails, exit `PROTECTED`
4. Revert the change made to the registry. If this fails, exit `ERROR`
5. If no part of the procedure was stopped, exit `UNPROTECTED`

 Example Output:
 ```bash
 [2024-08-21T11:03:06][0a681761-f2d6-4356-9f24-f318c403e985] Directory successfully changed to "C:\Users\Public\.vst"
 [2024-08-21T11:03:06][0a681761-f2d6-4356-9f24-f318c403e985] Starting test at: 2024-08-21T11:03:06
 [2024-08-21T11:03:06][0a681761-f2d6-4356-9f24-f318c403e985] Gathering current security log setting
 [2024-08-21T11:03:06][0a681761-f2d6-4356-9f24-f318c403e985] Current Security event log path is: C:\Windows\System32\winevt\Logs\Security.evtx


 [2024-08-21T11:03:06][0a681761-f2d6-4356-9f24-f318c403e985] Changing Security event log path
 [2024-08-21T11:03:06][0a681761-f2d6-4356-9f24-f318c403e985] New Security event log path is: C:\Users\Public\.vst\f0rtikaSecLog.evtx

 [2024-08-21T11:03:06][0a681761-f2d6-4356-9f24-f318c403e985] Successfully changed Security event log path
 [2024-08-21T11:03:06][0a681761-f2d6-4356-9f24-f318c403e985] Reverting Security event log path changes
 [2024-08-21T11:03:06][0a681761-f2d6-4356-9f24-f318c403e985] Security event log path after reversion is: C:\Windows\System32\winevt\Logs\Security.evtx



 [2024-08-21T11:03:06][0a681761-f2d6-4356-9f24-f318c403e985] Completed with code: 101
 [2024-08-21T11:03:06][0a681761-f2d6-4356-9f24-f318c403e985] Exit called from line: 72
 [2024-08-21T11:03:06][0a681761-f2d6-4356-9f24-f318c403e985] Ending test at: 2024-08-21T11:03:06; ;
 ```

## Resolution

If this test fails:

* Ensure your system is up-to-date with the latest patches.
* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.


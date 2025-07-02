# Conti Ransomware

This VST drops a defanged Conti ransomware executable file named conti.exe. Conti is a well-known ransomware first detected in 2020, thought to be linked to a group in Russia. It functions as a ransomware-as-a-service (RaaS), allowing various cybercriminals to use the malware for their own objectives. A distinctive feature of Conti is its use of dual extortion methods: it not only locks a victim's files but also pilfers and threatens to release confidential information unless a ransom is settled.

## How

> Safety: the ransomware used has been defanged, so it will immediately exit even if executed.

Steps:

1. Extract defanged malware to disk.
2. Wait for 3 seconds to gauge defenses.
3. Exit PROTECTED if the file was quarantined and UNPROTECTED if not.

Example Output:
```bash
[2fb936db-14e1-4a11-b078-f1e0a27d3501] Starting test at: 2023-10-04T15:47:47
[2fb936db-14e1-4a11-b078-f1e0a27d3501] Extracting file for quarantine test
[2fb936db-14e1-4a11-b078-f1e0a27d3501] Pausing for 3 seconds to gauge defensive reaction
[2fb936db-14e1-4a11-b078-f1e0a27d3501] Malicious file was caught!
[2fb936db-14e1-4a11-b078-f1e0a27d3501] Completed with code: 105
[2fb936db-14e1-4a11-b078-f1e0a27d3501] Ending test at: 2023-10-04T15:47:50
```

## Resolution

If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

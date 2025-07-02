# Web Shell

This VST is designed to assess the host system's defenses against MITRE ATT&CK T1505.003, specifically targeting web shell deployment. Web shells are malicious scripts used by attackers to gain persistent access and remote administration capabilities on compromised web servers. The test simulates the extraction of different types of web shell files to evaluate the system's ability to detect and quarantine these threats.

## How

> Safety: This test ensures safety by only simulating the extraction of web shell files without actually compromising the system or network. The goal is to assess system responses to potential web shell threats without causing real harm.

Steps:
1. Attempt to extract simulated web shell files (PHP, JSP, ASP) to a test directory.
2. If the system successfully quarantines the file upon extraction, exit `FileQuarantinedOnExtraction`.
3. If the extraction is successful without quarantine, exit `UNPROTECTED`.

Example Output:
```bash
[2024-01-11T14:55:46][9cfe37da-6e7c-4393-a21c-836fe81fde6c] Starting test at: 2024-01-11T14:55:46
[2024-01-11T14:55:46][9cfe37da-6e7c-4393-a21c-836fe81fde6c] Extracting web shell file to test directory
[2024-01-11T14:55:46][9cfe37da-6e7c-4393-a21c-836fe81fde6c] Extracting asp web shell with filename shell.asp
[2024-01-11T14:55:46][9cfe37da-6e7c-4393-a21c-836fe81fde6c] Waiting for 3 seconds
[2024-01-11T14:55:49][9cfe37da-6e7c-4393-a21c-836fe81fde6c] Web shell was quarantined on extraction
[2024-01-11T14:55:49][9cfe37da-6e7c-4393-a21c-836fe81fde6c] Completed with code: 105
[2024-01-11T14:55:49][9cfe37da-6e7c-4393-a21c-836fe81fde6c] Exit called from line: 46
[2024-01-11T14:55:49][9cfe37da-6e7c-4393-a21c-836fe81fde6c] Ending test at: 2024-01-11T14:55:49
```

## Resolution

If this test fails:

* Ensure your system is up-to-date with the latest patches.
* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.


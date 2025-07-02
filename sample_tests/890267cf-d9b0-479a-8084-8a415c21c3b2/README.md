# Credentials in Files

This VST is designed to simulate MITRE ATT&CK T1552.001, focusing on credential access through searching for sensitive information in files. The test mimics an attacker's behavior by searching for occurrences of the word "password" in various file types, a common tactic used to find stored credentials.

## How

> Safety: The simulation only involves searching for specific strings in files and does not involve accessing or modifying sensitive data, ensuring the integrity and confidentiality of the system's data.

Example Output:
```bash
[2024-01-11T19:47:46][890267cf-d9b0-479a-8084-8a415c21c3b2] Starting test at: 2024-01-11T19:47:46
[2024-01-11T19:47:46][890267cf-d9b0-479a-8084-8a415c21c3b2] Successfully ran search commands
[2024-01-11T19:47:46][890267cf-d9b0-479a-8084-8a415c21c3b2] Completed with code: 100
[2024-01-11T19:47:46][890267cf-d9b0-479a-8084-8a415c21c3b2] Exit called from line: 33
[2024-01-11T19:47:46][890267cf-d9b0-479a-8084-8a415c21c3b2] Ending test at: 2024-01-11T19:47:46
```

Steps:
1. On Linux systems, use `grep` to search for the term "password" in files within the current directory.
2. On Windows systems, use `findstr` to perform a similar search across common document formats.
3. If the system blocks or flags these commands, exit `PROTECTED`.
4. If the commands execute successfully without detection, exit `UNPROTECTED`.

## Resolution

If this test fails:

* Ensure your system is up-to-date with the latest patches.
* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.


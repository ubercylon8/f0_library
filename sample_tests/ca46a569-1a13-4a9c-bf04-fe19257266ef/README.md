# S(C)wipe

This test simulates a ransomware attack wherein no file encryption occurs. Instead, the files of contents are exfiltrated and then overwritten with a ransom note. This technique is considered harder to detect and presents an alternative method to a current potential "blind spot" in defenses.

## How

> Safety: this test only modifies files created for the purpose of the test and does not send production or sensitive data outbound.

Steps:

1. Create five files containing 2MB of zeroes.
2. Simulate exfiltration of the contents of each file.
3. Write a ransom note to new file of the same name with ".safe" appended.
4. Delete the original files.
3. Exit PROTECTED if the file was quarantined and UNPROTECTED if not.

Example Output:
```bash
[ca46a569-1a13-4a9c-bf04-fe19257266ef] Starting test at: 2023-09-25T21:35:00
[ca46a569-1a13-4a9c-bf04-fe19257266ef] Creating test files
[ca46a569-1a13-4a9c-bf04-fe19257266ef] Exfiltrating files
[ca46a569-1a13-4a9c-bf04-fe19257266ef] Creating safe mode copies of files
[ca46a569-1a13-4a9c-bf04-fe19257266ef] Deleting original files
[ca46a569-1a13-4a9c-bf04-fe19257266ef] Completed with code: 101
[ca46a569-1a13-4a9c-bf04-fe19257266ef] Ending test at: 2023-08-29T21:35:00
```

## Resolution

If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

# Mega.io Exfiltration

Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel. Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet.

## How

> Safety: the test does not attempt to modify the system in any harmful way.

Steps:

1. Execute exfiltration.
2. Exit PROTECTED if the technique fails to run and UNPROTECTED if it succeeds.

Example Output:
```bash
[2024-01-04T11:16:26][2bd2fdf2-07e7-4759-8f0d-ca35e64689c0] Starting test at: 2024-01-04T11:16:26
[2024-01-04T11:16:26][2bd2fdf2-07e7-4759-8f0d-ca35e64689c0] Attempting data exfiltration to mega.io
[2024-01-04T11:16:26][2bd2fdf2-07e7-4759-8f0d-ca35e64689c0] Data exfiltrated successfully
[2024-01-04T11:16:26][2bd2fdf2-07e7-4759-8f0d-ca35e64689c0] Completed with code: 101
[2024-01-04T11:16:26][2bd2fdf2-07e7-4759-8f0d-ca35e64689c0] Exit called from line: 29
[2024-01-04T11:16:26][2bd2fdf2-07e7-4759-8f0d-ca35e64689c0] Ending test at: 2024-01-04T11:16:26
```

## Resolution

If this test fails:

- Ensure you have an antivirus program installed and running.
- If using an EDR, ensure the antivirus capability is enabled and appropriately configured.


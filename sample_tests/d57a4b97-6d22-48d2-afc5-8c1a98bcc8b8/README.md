# Remote Services: SSH

This VST attempts to send data over TCP:22 to a remote resource in order to simulate outbound SSH traffic. This test does not attempt to utilize account credentials; it demonstrates data transiting a network boundary that commonly sees use by adversaries and malicious software.

## How

 > Safety: this test does not interact with internal SSH infrastructure, does not attempt to utilize user credentials, and does not attempt to modify the host system in any way.

Steps:

 1. Attempt to send the string `f0rtika Security` to a remote network resource over TCP:22. If this step fails, exit `PROTECTED`
 2. If no error is encountered, exit `UNPROTECTED`

 Example Output:
 ```bash
 [2024-07-11T15:35:55][d57a4b97-6d22-48d2-afc5-8c1a98bcc8b8] Starting test at: 2024-07-11T15:35:55
 [2024-07-11T15:35:55][d57a4b97-6d22-48d2-afc5-8c1a98bcc8b8] Attempting to send SSH traffic
 [2024-07-11T15:35:56][d57a4b97-6d22-48d2-afc5-8c1a98bcc8b8] Successfully sent SSH traffic
 [2024-07-11T15:35:56][d57a4b97-6d22-48d2-afc5-8c1a98bcc8b8] Completed with code: 101
 [2024-07-11T15:35:56][d57a4b97-6d22-48d2-afc5-8c1a98bcc8b8] Exit called from line: 21
 [2024-07-11T15:35:56][d57a4b97-6d22-48d2-afc5-8c1a98bcc8b8] Ending test at: 2024-07-11T15:35:56
 ```

## Resolution

 If this test fails:

* Consider adjusting allow/deny rules on network boundary appliances as appropriate.

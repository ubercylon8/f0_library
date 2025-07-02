# Active Directory Recon

This VST emulates several enumerative TTPs observed during the course of an incident that resulted in the leakage of sensitive user and personal information onto the darkweb. The test first evaluates whether the system it's running on is joined to an Active Directory domain. Then, if it is, it executes a series of system commands to perform reconnaissance and gather information about the host and network it can access.

## How

 > Safety: This test does not modify user accounts, data, or settings on the local host or any network-adjacent machine.

Steps:

 1. Determine whether the host is connected to the AD domain. Exit `NotRelevant` if not.
 2. Check for passwords or other credentials stored in files on the local system. Exit `PROTECTED` if this check errors.
 3. Perform a series of enumerative checks to reconnoiter the domain the host is joined to. Exit `PROTECTED` if any step in this process errors.
 4. Enumerate the local file system for potentially interesting information. Exit `PROTECTED` if this process is interrupted or fails.
 5. Exit `UNPROTECTED` if no error is encountered up to this point.

 Example Output:
 ```bash
 [2024-02-15T20:16:27][5685dd5a-5a03-4884-a50e-b19123f9a1e9] Starting test at: 2024-02-15 20:16:27.644747+00:00
 [2024-02-15T20:16:27][5685dd5a-5a03-4884-a50e-b19123f9a1e9] Performing relevance check
 [2024-02-15T20:16:27][5685dd5a-5a03-4884-a50e-b19123f9a1e9] Searching for credentials in files on host
 [2024-02-15T20:16:27][5685dd5a-5a03-4884-a50e-b19123f9a1e9] Attempting Active Directory user enumeration
 [2024-02-15T20:16:27][5685dd5a-5a03-4884-a50e-b19123f9a1e9] Attempting Active Directory computer enumeration
 [2024-02-15T20:16:27][5685dd5a-5a03-4884-a50e-b19123f9a1e9] Attempting Active Directory trust enumeration
 [2024-02-15T20:16:27][5685dd5a-5a03-4884-a50e-b19123f9a1e9] Attempting generic file and directory enumeration
 [2024-02-15T20:16:27][5685dd5a-5a03-4884-a50e-b19123f9a1e9] Attempting network discovery and enumeration
 [2024-02-15T20:16:27][5685dd5a-5a03-4884-a50e-b19123f9a1e9] Completed with code: 100
 [2024-02-15T20:16:27][5685dd5a-5a03-4884-a50e-b19123f9a1e9] Ending test at: 2024-02-15 20:16:27.644747+00:00
 ```

## Resolution

 If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

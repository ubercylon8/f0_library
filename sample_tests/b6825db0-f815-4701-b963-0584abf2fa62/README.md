# Untrusted User Execution

This VST tests whether a host is able to execute code as an untrusted user. The "nobody" user has the least privileges in Linux and, by default, belongs to the nobody group. It is the opposite of the root user, who has all the power to perform system administration actions. Attackers commonly leverage valid local accounts to attempt to bypass defenses and execute commands on a system. This test will monitor if any endpoint defense stops the execution of the techniques.

## How

> Safety: command execution does not attempt to modify the system in any harmful way.

Steps:

1. Get the UID and GID of the "nobody" user.
2. Execute a whoami command as the "nobody" user.
3. Exit NOT VULNERABLE if the command is not able to be executed. UNPROTECTED if the command executes.

Example Output:
```bash
[b6825db0-f815-4701-b963-0584abf2fa62] Starting test at: 2023-08-29T21:35:05
[b6825db0-f815-4701-b963-0584abf2fa62] Attempting to execute code as the nobody user
[b6825db0-f815-4701-b963-0584abf2fa62] Endpoint is not vulnerable
[b6825db0-f815-4701-b963-0584abf2fa62] Completed with code: 107
[b6825db0-f815-4701-b963-0584abf2fa62] Ending test at: 2023-08-29T21:35:05
```

## Resolution

If this test fails:

* Ensure your system is up-to-date with the latest patches.
* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

# SharpUp

This test drops and executes SharpUp, a tool that identifies potential avenues of privilege escalation on Windows systems. Red teams have primarily used this tool as a C# replacement for the PowerUp PowerShell script. 

## How

> Safety: this test does not try to exploit any identified avenues for privilege escalation on the endpoint

Steps:

1. Extract SharpUp to disk.
2. Wait for 3 seconds to gauge defenses.
3. Exit PROTECTED if the file was quarantined and continue if not.
3. Execute a randomly selected SharpUp command from a set of 4 available
3. Exit UNPROTECTED if execution was successful and PROTECTED if not.

Example Output:
```bash
[785a33e6-2e09-4823-82ac-8c01f9beed5d] Starting test at: 2023-12-07T12:34:00
[785a33e6-2e09-4823-82ac-8c01f9beed5d] Extracting SharpUp for quarantine test
[785a33e6-2e09-4823-82ac-8c01f9beed5d] Pausing for 3 seconds to gauge defensive reaction
[785a33e6-2e09-4823-82ac-8c01f9beed5d] Malicious file was not caught, continuing execution
[785a33e6-2e09-4823-82ac-8c01f9beed5d] Execution was not prevented
[785a33e6-2e09-4823-82ac-8c01f9beed5d] Completed with code: 101
[785a33e6-2e09-4823-82ac-8c01f9beed5d] Ending test at: 2023-12-07T12:34:00
```

## Resolution

If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

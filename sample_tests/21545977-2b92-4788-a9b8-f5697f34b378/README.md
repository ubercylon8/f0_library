# DCSync

This VST deploys a Mimikatz executable with xor obfuscation to the disk and attempts to execute its DCSync command. Mimikatz's DCSync is a technique that impersonates the behavior of a domain controller to retrieve password hashes from Active Directory, which is a tactic often used for credential access and lateral movement by attackers. As many enterprise environments utilize Active Directory for their identity management, this can be a critical vulnerability if not properly mitigated. The test is designed to determine if endpoint defenses are capable of identifying and mitigating this specific threat vector.

## How

> Safety: This VST exploits the DCSync vulnerability, which does not affect or harm the functionality of the domain.

Steps:

1. Confirm if the endpoint is connected to Active Directory.
2. Perform xor obfuscation on the Mimikatz binary data.
3. Write the obfuscated binary to disk as 'mimikatzXOR.exe' and wait 3 seconds for endpoint reaction.
4. Terminate with status PROTECTED if the binary is quarantined; proceed if not.
5. Deobfuscate 'mimikatzXOR.exe' back to its original binary form.
6. Attempt to execute the Mimikatz DcSync command.
7. Terminate with status UNPROTECTED if execution is successful, PROTECTED if execution is blocked.

Example Output:
```bash
[21545977-2b92-4788-a9b8-f5697f34b378] Starting test at: 2023-11-08T19:01:27
[21545977-2b92-4788-a9b8-f5697f34b378] Checking if endpoint is connected to Active Directory
[21545977-2b92-4788-a9b8-f5697f34b378] Performing xor obfuscation on file
[21545977-2b92-4788-a9b8-f5697f34b378] Extracting file for quarantine test
[21545977-2b92-4788-a9b8-f5697f34b378] Pausing for 3 seconds to gauge defensive reaction
[21545977-2b92-4788-a9b8-f5697f34b378] Malicious file was not caught, continuing VST execution
[21545977-2b92-4788-a9b8-f5697f34b378] Performing xor deobfuscation on file
[21545977-2b92-4788-a9b8-f5697f34b378] Executing DCSync
[21545977-2b92-4788-a9b8-f5697f34b378] Execution was prevented
[21545977-2b92-4788-a9b8-f5697f34b378] Completed with code: 126
[21545977-2b92-4788-a9b8-f5697f34b378] Ending test at: 2023-11-08T19:01:37
```

## Resolution

If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

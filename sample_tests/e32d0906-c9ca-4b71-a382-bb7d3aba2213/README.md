# SharpHound

This test drops a SharpHound PowerShell script to disk and then attempts to execute it. SharpHound is a post-exploitation tool commonly used by attackers to enumerate and abuse misconfigurations in Active Directory (AD). It uses native Windows API functions and LDAP namespace functions to collect data from domain controllers and domain-joined Windows systems. Due to the complexity of AD setups, it is common for misconfigurations to exist even in a default state, which can be abused by attackers to gain access to sensitive information or to move laterally within the network. This test will monitor if any endpoint defense quarantines the malware or stops the execution of the techniques.

## How

> Safety: this VST only performs a check for domain trusts and does not attempt to exploit them.

Steps:

1. Generate a random xor key, apply xor obfuscation, and extract SharpHound executable to disk.
2. Wait for 3 seconds to gauge defenses.
3. Exit PROTECTED if the file was quarantined and continue if not.
4. Reverse the initial xor obfuscation and execute SharpHound to find domain trusts.
5. Exit UNPROTECTED if execution was successful and PROTECTED if not.

Example Output:
```bash
[e32d0906-c9ca-4b71-a382-bb7d3aba2213] Starting test at: 2023-09-19T10:56:18
[e32d0906-c9ca-4b71-a382-bb7d3aba2213] Checking if endpoint is connected to Active Directory
[e32d0906-c9ca-4b71-a382-bb7d3aba2213] Performing xor obfuscation on file
[e32d0906-c9ca-4b71-a382-bb7d3aba2213] Extracting file for quarantine test
[e32d0906-c9ca-4b71-a382-bb7d3aba2213] Pausing for 3 seconds to gauge defensive reaction
[e32d0906-c9ca-4b71-a382-bb7d3aba2213] Malicious file was not caught, continuing VST execution
[e32d0906-c9ca-4b71-a382-bb7d3aba2213] Performing xor deobfuscation on file
[e32d0906-c9ca-4b71-a382-bb7d3aba2213] Executing SharpHound
[e32d0906-c9ca-4b71-a382-bb7d3aba2213] Execution was prevented
[e32d0906-c9ca-4b71-a382-bb7d3aba2213] Completed with code: 126
[e32d0906-c9ca-4b71-a382-bb7d3aba2213] Ending test at: 2023-09-19T10:56:22
```

## Resolution

If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

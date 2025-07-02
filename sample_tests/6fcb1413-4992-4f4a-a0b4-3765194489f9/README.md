# Cobalt Strike Trojan

This test drops a defanged Cobalt Strike DLL and attempts to execute associated Cobalt Strike techniques. Cobalt Strike is a commercial penetration testing and threat emulation software. It provides a powerful platform for security professionals to conduct simulated cyber-attacks and evaluate the effectiveness of an organization's defenses. It offers various features, such as reconnaissance, social engineering, network exploitation, and post-exploitation tools. In the hands of attackers, it can be used to gain unauthorized access to systems, exfiltrate sensitive data, and create backdoors for ongoing access. Its versatile and sophisticated capabilities have made it a popular tool among both legitimate security testers and malicious threat actors. This test will monitor if any endpoint defense quarantines the malware.

## How

> Safety: the malware used has been defanged, so even if run, it will immediately exit. Command execution does not attempt to modify the system in any harmful way.

Steps:

1. Extract defanged malware to disk.
2. Wait for 3 seconds to gauge defenses.
3. Exit PROTECTED if the file was quarantined and continue if not.
4. Execute rundll32.exe.
5. Execute encoded PowerShell command.
6. Create named pipe.
7. Exit PROTECTED if the test is stopped. UNPROTECTED if not.

Example Output:
```bash
[6fcb1413-4992-4f4a-a0b4-3765194489f9] Starting test at: 2023-08-29T21:36:56
[6fcb1413-4992-4f4a-a0b4-3765194489f9] Extracting file for quarantine test
[6fcb1413-4992-4f4a-a0b4-3765194489f9] Pausing for 3 seconds to gauge defensive reaction
[6fcb1413-4992-4f4a-a0b4-3765194489f9] Malicious file was not caught, continuing with technique execution
[6fcb1413-4992-4f4a-a0b4-3765194489f9] TTPs were able to be executed
[6fcb1413-4992-4f4a-a0b4-3765194489f9] Completed with code: 101
[6fcb1413-4992-4f4a-a0b4-3765194489f9] Ending test at: 2023-08-29T21:36:56
```

## Resolution

If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

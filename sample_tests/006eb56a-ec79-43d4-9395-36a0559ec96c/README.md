# Non-Standard Port

This VST addresses MITRE ATT&CK T1571, focusing on the technique of contacting an external network resource over a non-standard port. The test simulates an attacker's attempt to establish network communication to a service or resource over a port which differs from any established standard, which can be a method used for evading detection or bypassing firewall rules.

## How

> Safety: The test is designed to attempt network communication over a non-standard port without engaging in any malicious or disruptive activities, thereby ensuring the safety and stability of the network and systems involved.

Steps:
1. Attempt to contact the external resource (`portquiz.net`) over a randomly chosen non-standard TCP port.
2. If the connection attempt is unsuccessful or an error occurs, exit `UnexpectedTestError`.
3. If the connection is successful, exit `UNPROTECTED`.

 Example Output:
 ```bash
[2024-01-13T01:24:01][006eb56a-ec79-43d4-9395-36a0559ec96c] Starting test at: 2024-01-13T01:24:01
[2024-01-13T01:24:01][006eb56a-ec79-43d4-9395-36a0559ec96c] Attempting to contact external resource over random, non-standard port
[2024-01-13T01:24:01][006eb56a-ec79-43d4-9395-36a0559ec96c] Connection test successful
[2024-01-13T01:24:01][006eb56a-ec79-43d4-9395-36a0559ec96c] Completed with code: 100
[2024-01-13T01:24:01][006eb56a-ec79-43d4-9395-36a0559ec96c] Exit called from line: 30
[2024-01-13T01:24:01][006eb56a-ec79-43d4-9395-36a0559ec96c] Ending test at: 2024-01-13T01:24:01
 ```

## Resolution

If this test fails:

* Ensure your network settings, including firewall rules, are configured properly and securely.
* Review and update network monitoring tools to detect unusual port activity.
* Ensure your system and network security measures are up-to-date and functioning as expected.


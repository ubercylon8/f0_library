# Brute Force

This VST tests whether a host is able to conduct a brute force attack on a protected user. Security teams can assess whether their endpoint defenses are capable of detecting and mitigating such brute-force attacks. This process is crucial for evaluating the robustness of security measures against potential unauthorized privilege escalation and initial access attacks. CISA has reported this technique being used in the wild by Iranian Government Islamic Revolutionary Guard Corps (IRGC)-affiliated Advanced Persistent Threat (APT) cyber actors.

## How

> Safety: command execution does not attempt to modify the system in any harmful way.

Steps:

1. Go through a small list of common passwords and attempt to escalate privileges to the SUDO user.
2. Exit PROTECTED if the username is not found in the output. UNPROTECTED if it is.

Example Output:
```bash
[bc7f082a-91c9-4037-b841-e1d8ceb3101e] Starting test at: 2023-12-02T20:36:06
[bc7f082a-91c9-4037-b841-e1d8ceb3101e] Conducting brute force of sudo password
[bc7f082a-91c9-4037-b841-e1d8ceb3101e] Tried: qwerty
[bc7f082a-91c9-4037-b841-e1d8ceb3101e] Tried: Christmas2012
[bc7f082a-91c9-4037-b841-e1d8ceb3101e] Tried: march2022@
[bc7f082a-91c9-4037-b841-e1d8ceb3101e] Tried: password123
[bc7f082a-91c9-4037-b841-e1d8ceb3101e] Tried: five
[bc7f082a-91c9-4037-b841-e1d8ceb3101e] Password not found
[bc7f082a-91c9-4037-b841-e1d8ceb3101e] Completed with code: 100
[bc7f082a-91c9-4037-b841-e1d8ceb3101e] Ending test at: 2023-12-02T20:36:16
```

## Resolution

If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

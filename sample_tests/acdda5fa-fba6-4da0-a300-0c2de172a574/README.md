# Living off the Land: Zip and Encrypt Ransomware

This VST tests common behaviors observed in malware attacks that utilize native OS features: compressing directories and encrypting the compressed files. Malicious actors often "live off the land," leveraging built-in tools and libraries to perform malicious activities. The code encapsulates these activities, emphasizing the importance of watching out for unexpected uses of native functionalities.

## How

> Safety: the test doesn't alter original files but creates and encrypts its own.

Steps:

1. Generate a secure password of 32 characters.
2. Compress the user's home directory into a file named `backup.zip`.
3. Encrypt the `backup.zip` file using AES encryption to generate `backup.zip.enc`.
4. Exit PROTECTED if the techniques are not able to be executed. UNPROTECTED if so.

Example Output:
```bash
[acdda5fa-fba6-4da0-a300-0c2de172a574] Starting test at: 2023-09-26T15:56:56
[acdda5fa-fba6-4da0-a300-0c2de172a574] Generating secure password...
[acdda5fa-fba6-4da0-a300-0c2de172a574] Compressing directory: C:\Users
[acdda5fa-fba6-4da0-a300-0c2de172a574] Starting encryption process: backup.zip
[acdda5fa-fba6-4da0-a300-0c2de172a574] Completed with code: 101
[acdda5fa-fba6-4da0-a300-0c2de172a574] Ending test at: 2023-09-26T15:57:00
```

## Resolution

If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.

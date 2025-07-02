# Writing Packed Executable to Disk

This VST attempts to simulate how a threat actor might try to evade host defenses on an endpoint by employing a packer to alter the size and properties of an executable binary file. It does this by writing a series of bytes associated with a well-known packing tool, UPX, to disk. These bytes are present in every file packed using UPX and may indicate activity / suspicious features to endpoint security and defense software.

## How

> Safety: this VST does not attempt to modify the endpoint in any harmful way.

Steps:

1. Attempt to write the UPX magic bytes onto disk, waiting 3 seconds to allow for any quarantine or removal activity
2. Exit `PROTECTED` if a file check fails after extraction and wait period. Else exit `UNPROTECTED`

Example Output:
```bash
 [2024-07-30T14:33:32][b484be6c-6e79-4f96-b72d-6526f0f0103a] Starting test at: 2024-07-30T14:33:32 
 [2024-07-30T14:33:32][b484be6c-6e79-4f96-b72d-6526f0f0103a] Writing dropper executable to disk   
 [2024-07-30T14:33:32][b484be6c-6e79-4f96-b72d-6526f0f0103a] Performing normal file write
 [2024-07-30T14:33:32][b484be6c-6e79-4f96-b72d-6526f0f0103a] Wrote dropper successfully
 [2024-07-30T14:33:32][b484be6c-6e79-4f96-b72d-6526f0f0103a] Setting socket path
 [2024-07-30T14:33:32][b484be6c-6e79-4f96-b72d-6526f0f0103a] Dropping packed executable to disk   
 [2024-07-30T14:33:32][b484be6c-6e79-4f96-b72d-6526f0f0103a] Performing IPC-style file write      
 [2024-07-30T14:33:32][b484be6c-6e79-4f96-b72d-6526f0f0103a] Launching C:\Program Files\f0rtika Security\f0rtika Probe\.vst\b484be6c-6e79-4f96-b72d-6526f0f0103a_f0rtika_dropper.exe
 [2024-07-30T14:33:32][b484be6c-6e79-4f96-b72d-6526f0f0103a] Started dropper child process with PID 13480
 [2024-07-30T14:33:32][b484be6c-6e79-4f96-b72d-6526f0f0103a] Waiting for 3 seconds
 [2024-07-30T14:33:35][b484be6c-6e79-4f96-b72d-6526f0f0103a] Connecting to socket: C:\Program Files\f0rtika Security\f0rtika Probe\.vst\f0rtika_socket
 [2024-07-30T14:33:35][b484be6c-6e79-4f96-b72d-6526f0f0103a] Connected to socket!
 [2024-07-30T14:33:35][b484be6c-6e79-4f96-b72d-6526f0f0103a] Waiting for 1 seconds
 [2024-07-30T14:33:36][b484be6c-6e79-4f96-b72d-6526f0f0103a] Killing dropper child process        
 [2024-07-30T14:33:36][b484be6c-6e79-4f96-b72d-6526f0f0103a] Clearing socket path
 [2024-07-30T14:33:36][b484be6c-6e79-4f96-b72d-6526f0f0103a] Waiting for 3 seconds
 [2024-07-30T14:33:39][b484be6c-6e79-4f96-b72d-6526f0f0103a] Successfully extracted UPX-packed exe to disk
 [2024-07-30T14:33:39][b484be6c-6e79-4f96-b72d-6526f0f0103a] Completed with code: 101
 [2024-07-30T14:33:39][b484be6c-6e79-4f96-b72d-6526f0f0103a] Exit called from line: 37
 [2024-07-30T14:33:39][b484be6c-6e79-4f96-b72d-6526f0f0103a] Ending test at: 2024-07-30T14:33:39
```

## Resolution

If this test fails:

* Ensure you have an antivirus program installed and running.
* If using an EDR, make sure the antivirus capability is enabled and turned up, appropriately.


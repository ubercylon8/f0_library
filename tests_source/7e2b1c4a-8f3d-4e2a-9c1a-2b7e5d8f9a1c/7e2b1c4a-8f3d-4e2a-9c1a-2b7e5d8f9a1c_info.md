# Technical Information - SafePay User Awareness Test

## Test Identifier
**ID:** 7e2b1c4a-8f3d-4e2a-9c1a-2b7e5d8f9a1c

## Technical Details

### Main File
- **Language:** Go
- **File:** `7e2b1c4a-8f3d-4e2a-9c1a-2b7e5d8f9a1c.go`

### Implemented Functionality

#### 1. Function `getDesktopPath()`
- Obtains the base user directory path
- Uses `PUBLIC` environment variable as reference
- Fallback to `C:\Users\Public` if not available

#### 2. Function `createAlertFile()`
- Creates `Instrucciones.txt` file in user directory
- Contains simulated "SafePay" ransomware message
- Includes typical real ransomware elements for realism

#### 3. Function `openAlertFile()`
- Automatically opens file using Notepad
- Executes 2 times with 5-second intervals
- Maximizes window to ensure visibility

### Simulated Message Elements
- Fictional name: "SAFEPAY RANSOMWARE"
- Example Bitcoin address (non-functional)
- Fake email on .onion domain
- Fictional computer ID
- Simulated time limit (72 hours)

### Security Features
- Does not modify existing user files
- Does not install malicious software
- Does not establish network connections
- Only creates an informational text file
- Completely reversible by deleting the created file

### Evaluation Metrics
- Time from execution to user report
- Actions taken by the user
- Compliance with organizational security protocol

### Post-Test Cleanup
- Delete `Instrucciones.txt` file from user directory
- No additional system cleanup required
- No system persistence

### Ethical Considerations
- Test executed only in controlled environment
- Users previously informed about training program
- No real impact on productivity or data
- Exclusively educational and awareness purposes
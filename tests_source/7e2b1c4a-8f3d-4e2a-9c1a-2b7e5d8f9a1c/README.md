# SafePay User Awareness Simulation Test

This F0RT1KA test is designed to evaluate user response to a simulated ransomware scenario for security awareness purposes.

## Overview
The test simulates a data compromise situation by creating:
- An instruction file on the user's desktop
- Warning message simulating "SafePay" ransomware
- Automatic file opening to maximize visibility

## Awareness Objective
This test allows evaluation of:
- User's ability to identify a security situation
- Response time to report the incident
- Adherence to established security procedures

## MITRE ATT&CK Mapping
- T1486 - Data Encrypted for Impact (simulated)
- T1491.001 - Defacement: Internal Defacement

## Expected User Behavior
A properly trained user should:
- Immediately recognize this as an anomalous situation
- Not follow the instructions in the fake message
- Report the incident to the information security team
- Not attempt to make payments or contact suspicious addresses

## Security Notes
- This is a controlled simulation with no real impact on data
- No destructive modifications are made to the system
- The created file is a simple informational text file
- The test runs in a controlled training environment

## Success Indicators
- User reports the incident within the first 10 minutes
- Does not attempt to follow malicious message instructions
- Escalates appropriately through established channels
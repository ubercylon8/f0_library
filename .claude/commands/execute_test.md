---
allowed-tools: Bash(ssh *)
description: Execute command on test server 
---

## Context

- Test execution on Windows host: !'ssh windows \'$ARGUMENTS\''

## Your task

Analyze the test execution output, and think about it. Tell me if the final result (error code) correspond with the test logic. You can check the orignal test code; command name executed through ssh corresponds with the test uuid in the test project repo. 

Your analysis will guide me through the proper tuning of the test if needed.` 

# Impair Defenses: Disable or Modify Cloud Logs

This test attempts to simulate one method by which a threat actor or piece of malicious software might try to remain undetected by disabling or modifying logging policies in a cloud infrastructure environment. This diminishes the capability of the victim organization to collect and identify malicious activity.

## How

 > Safety: this test reverts any changes made to the logging policies it successfully alters.
 > Risk: the test may not complete its reversion operations after disabling logging. if you suspect this is the case, review logging settings in your environment after running this test.

Steps:

 1. Setup and configure a CloudTrail client. If this step fails, exit `NOTRELEVANT`
 2. Attempt to enumerate all CloudTrail trails available to the VST process. If there are none, exit `NOTRELEVANT`
 3. For each trail in the list of reconnoitered trails, attempt to temporarily disable activity logging. If this step fails, exit `PROTECTED`
 4. Wait for one second after the logging policy is modified. Then attempt to revert the change. If this reversion fails, exit `ERROR`
 5. If able to disable and re-enable CloudTrail logging, exit `UNPROTECTED`

 Example Output:
 ```bash
 [a85b1291-0c1f-4b14-89c7-5b1929c7efc9] Starting test at: 2024-09-16 22:24:22.594999+00:00
 [a85b1291-0c1f-4b14-89c7-5b1929c7efc9] Configuring client
 [a85b1291-0c1f-4b14-89c7-5b1929c7efc9] Enumerating CloudTrail trails
 [a85b1291-0c1f-4b14-89c7-5b1929c7efc9] Enumeration complete. Attempting to disable logging
 [a85b1291-0c1f-4b14-89c7-5b1929c7efc9] Successfully disabled logging on ARN "MyCoolCloudTrailARN"
 [a85b1291-0c1f-4b14-89c7-5b1929c7efc9] Waiting for 1 second
 [a85b1291-0c1f-4b14-89c7-5b1929c7efc9] Reenabled logging on ARN "MyCoolCloudTrailARN"
 [a85b1291-0c1f-4b14-89c7-5b1929c7efc9] Completed with code: 101
 [a85b1291-0c1f-4b14-89c7-5b1929c7efc9] Ending test at: 2024-09-16 22:24:22.594999+00:00
 ```

## Resolution

 If this test fails:

* Review and adjust relevant user account and IAM policies to restrict access to the least privilege necessary


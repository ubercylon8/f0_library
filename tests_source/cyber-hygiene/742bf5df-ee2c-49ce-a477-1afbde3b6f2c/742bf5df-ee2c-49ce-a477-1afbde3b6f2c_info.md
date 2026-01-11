# Microsoft Defender Configuration Validator

## Test Information

**Test ID**: 742bf5df-ee2c-49ce-a477-1afbde3b6f2c
**Test Name**: Microsoft Defender Configuration Validator
**Category**: Cyber Hygiene / Configuration Validation
**Severity**: Critical
**MITRE ATT&CK**: T1562.001, T1562.004, T1070

## Description

This cyber hygiene test validates that Microsoft Defender Antivirus is properly configured with all critical protection features enabled. The test performs READ-ONLY validation of six critical security configurations that form the foundation of endpoint protection:

1. **Real-time Protection**: Continuous monitoring of file system activity for malware
2. **Behavior Monitoring**: Detection of suspicious process behavior patterns
3. **Tamper Protection**: Prevents malware from disabling Defender settings
4. **Cloud Protection (MAPS)**: Cloud-based threat intelligence and reputation
5. **Sample Submission**: Automatic upload of suspicious files for analysis
6. **PUA Protection**: Blocking of Potentially Unwanted Applications

This test is particularly important for ransomware prevention because Tamper Protection prevents sophisticated ransomware from disabling Defender before encrypting files - a common attack technique.

This test does NOT simulate any attacks - it only validates that defensive configurations are in place.

## Test Score: 8.5/10

### Score Breakdown

| Criterion | Score | Justification |
|-----------|-------|---------------|
| **Real-World Accuracy** | **2.5/3.0** | Validates actual production security configurations using native Windows APIs (Get-MpComputerStatus, Get-MpPreference) and direct registry access. Checks the exact settings that real malware attempts to disable. Includes fallback to registry checks when PowerShell cmdlets fail. |
| **Technical Sophistication** | **3.0/3.0** | Multi-method validation using PowerShell cmdlets and Windows Registry API. Proper error handling with graceful fallback mechanisms. Comprehensive parsing of Defender status and preference objects. Handles edge cases (third-party AV, missing keys, various value states). |
| **Safety Mechanisms** | **2.0/2.0** | Completely READ-ONLY test with zero system modifications. No attack simulation, no file drops, no process injection. Safe to run on any production system. All checks are non-invasive queries. |
| **Detection Opportunities** | **0.5/1.0** | Limited detection opportunities since this is a validation test, not an attack simulation. However, the PowerShell execution and registry queries could be detected by EDR solutions monitoring for reconnaissance activity. |
| **Logging & Observability** | **0.5/1.0** | Full Schema v2.0 compliant logging with JSON and text output. Phase tracking, detailed check results, and remediation guidance. Saves PowerShell output for troubleshooting. |

**Key Strengths**:
- Validates six critical defense-in-depth layers for endpoint protection
- Uses native Windows Defender APIs for accurate configuration detection
- Includes fallback mechanisms when primary methods fail
- Provides actionable remediation guidance with PowerShell commands
- Maps to CIS Benchmark controls for compliance reporting
- Completely safe for production environments (read-only)
- Includes signature age warning for proactive maintenance

**Improvement Opportunities**:
- Could add cloud connectivity test to verify MAPS is working
- Could validate exclusion policies for potential weaknesses
- Could check for pending definition updates

## Technical Details

### Validation Flow

This is a configuration validation test, not an attack simulation. The validation sequence is:

1. **Phase 0: Initialization**
   - Verify administrator privileges (required for Get-MpComputerStatus)
   - Initialize Schema v2.0 compliant logging
   - Verify Windows Defender is available (not replaced by third-party AV)

2. **Phase 1: Retrieve Defender Status**
   - Execute `Get-MpComputerStatus` via PowerShell
   - Parse RealTimeProtectionEnabled, BehaviorMonitorEnabled, IsTamperProtected
   - Store AntivirusSignatureAge for later warning check
   - Save raw output for debugging

3. **Phase 2: Run Configuration Checks**
   - **Check 1**: Real-time Protection (PowerShell or registry fallback)
   - **Check 2**: Behavior Monitoring (PowerShell or registry fallback)
   - **Check 3**: Tamper Protection (PowerShell or registry fallback)
   - **Check 4**: Cloud Protection/MAPS (PowerShell or registry fallback)
   - **Check 5**: Sample Submission (PowerShell or registry fallback)
   - **Check 6**: PUA Protection (PowerShell or registry fallback)

4. **Phase 3: Signature Age Check**
   - Check AntivirusSignatureAge value
   - Log warning if signatures are > 7 days old
   - This is informational only, does not affect compliance

5. **Phase 4: Compliance Determination**
   - Calculate overall compliance (all 6 checks must pass)
   - Generate summary report with remediation guidance
   - Exit with appropriate code (126=COMPLIANT, 101=NON-COMPLIANT)

### Registry Paths Used

| Setting | Registry Path | Value |
|---------|---------------|-------|
| Real-time Protection | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring` | 0=enabled |
| Behavior Monitoring | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring` | 0=enabled |
| Tamper Protection | `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection` | 5=enabled |
| MAPS Reporting | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting` | 2=Advanced |
| Sample Submission | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent` | 1 or 3 |
| PUA Protection | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\PUAProtection` | 1=enabled |

### Key Indicators

Security teams monitoring for configuration validation activity may observe:

- PowerShell execution with `-ExecutionPolicy Bypass`
- `Get-MpComputerStatus` and `Get-MpPreference` cmdlet usage
- Registry reads to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
- Registry reads to `HKLM\SOFTWARE\Microsoft\Windows Defender\Features`
- Service query to `WinDefend` service

## Detection Opportunities

1. **PowerShell Logging**
   - Script block logging will capture Get-Mp* cmdlet usage
   - Module logging will show command execution

2. **Registry Access Monitoring**
   - Monitor for read access to Defender policy keys
   - Could indicate reconnaissance activity

3. **Service Query Monitoring**
   - `sc query WinDefend` execution
   - Unusual for standard applications

## Expected Results

### Compliant System (Code 126)

All six protection mechanisms are properly configured:
- Real-time Protection = Enabled
- Behavior Monitoring = Enabled
- Tamper Protection = Enabled
- Cloud Protection = Advanced (2)
- Sample Submission = Enabled (1 or 3)
- PUA Protection = Enabled (1)

The system has comprehensive anti-malware protection and is resilient against attacks that attempt to disable Defender.

### Non-Compliant System (Code 101)

One or more protection mechanisms are missing or misconfigured:
- Real-time protection may not catch malware in real-time
- Behavior-based detection may be disabled
- Malware could potentially disable Defender (if Tamper Protection is off)
- Cloud-based threat intelligence may not be utilized
- Automatic sample analysis may be disabled
- Potentially unwanted applications may not be blocked

Remediation is required to improve security posture.

### Test Error (Code 999)

The test could not complete due to:
- Insufficient privileges (must run as Administrator)
- Windows Defender not available (third-party AV installed)
- Timeout exceeded (rare for this test)
- Unexpected system error

## References

- [MITRE ATT&CK T1562.001 - Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK T1562.004 - Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004/)
- [MITRE ATT&CK T1070 - Indicator Removal](https://attack.mitre.org/techniques/T1070/)
- [Microsoft - Tamper Protection](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
- [Microsoft - Configure Microsoft Defender Antivirus](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-microsoft-defender-antivirus-features)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)

## Compliance Mapping

| Framework | Control |
|-----------|---------|
| CIS Controls v8 | 10.1 - Deploy and Maintain Anti-Malware Software |
| CIS Controls v8 | 10.2 - Configure Automatic Updates for Anti-Malware |
| NIST 800-53 | SI-3 - Malicious Code Protection |
| NIST 800-53 | SI-4 - System Monitoring |
| PCI DSS 4.0 | 5.2 - Malicious Software Prevention |
| HIPAA | 164.308(a)(5)(ii)(B) - Protection from Malicious Software |

## Why This Matters for Ransomware Defense

Modern ransomware often follows this attack pattern:
1. Initial access via phishing or vulnerability exploitation
2. **Disable security tools** (Defender, EDR, logging)
3. Establish persistence
4. Encrypt files and demand ransom

Tamper Protection specifically prevents step 2 by making it impossible for malware to:
- Disable real-time protection via registry
- Stop the Defender service
- Modify cloud protection settings
- Turn off behavior monitoring

Without Tamper Protection enabled, even a fully configured Defender can be completely disabled by sophisticated malware, rendering the endpoint essentially unprotected.

## Sample Output

```
================================================================================
           MICROSOFT DEFENDER CONFIGURATION VALIDATION SUMMARY
================================================================================

[PASS] Check 1: Real-time Protection              Value: Enabled
[PASS] Check 2: Behavior Monitoring               Value: Enabled
[PASS] Check 3: Tamper Protection                 Value: Enabled
[PASS] Check 4: Cloud Protection (MAPS)           Value: Advanced (2)
[PASS] Check 5: Sample Submission                 Value: Send all samples (3)
[PASS] Check 6: PUA Protection                    Value: Enabled (1)

--------------------------------------------------------------------------------
Overall: 6/6 checks passed

[COMPLIANT] All Microsoft Defender protection features are properly configured.
            System has comprehensive anti-malware protection enabled.
```

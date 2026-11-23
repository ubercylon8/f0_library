# Dual Signing Strategy for F0RT1KA Tests

## Executive Summary

F0RT1KA tests now support **dual signing** - signing binaries with BOTH organization-specific certificates AND the universal F0RT1KA certificate. This lets test binaries satisfy signer-based trust controls (WDAC/App Control for Business publisher rules, SmartScreen/Mark-of-the-Web prompts) on endpoints that already trust the org certificate, while maintaining the self-healing vision.

> **Important — signing does NOT bypass Defender ASR.** Attack Surface Reduction rules are behavior-based (e.g. "Block process creations originating from PSExec and WMI commands" blocks the *behavior*, whoever signed the binary). An Authenticode signature, even from an org-trusted certificate in `LocalMachine\Root` or `TrustedPublisher`, does not exempt a binary from ASR. Only ASR exclusions (`Add-MpPreference -AttackSurfaceReductionOnlyExclusions`, or per-rule exclusions via Intune/GPO) do that. The reputation-based rule ("Block executable files from running unless they meet a prevalence, age, or trusted list criterion") uses Microsoft cloud reputation, not locally installed certificates.
>
> Telling the two apart on an endpoint:
> - **WDAC / App Control block** (signature/cert related): `Microsoft-Windows-CodeIntegrity/Operational` event **3077** (enforced block) or **3076** (audit). Advanced hunting `ActionType` starts with `AppControl`.
> - **ASR block** (behavior related, not cert related): `Microsoft-Windows-Windows Defender/Operational` event **1121** (block) or **1122** (audit), with the rule GUID in the event. Advanced hunting `ActionType` starts with `Asr` (e.g. `AsrPsexecWmiChildProcessBlocked`).
>
> A test stage blocked by ASR is a genuine prevention result (Protected), not a signing problem.

**Key Benefits:**
- ✅ **Immediate Execution under WDAC/App Control**: Org certs already trusted by endpoints satisfy publisher/signer allow rules (ASR still applies — see above)
- ✅ **Zero Deployment Friction**: No manual certificate installation required
- ✅ **Self-Healing Enabled**: F0RT1KA cert auto-installs on first test run
- ✅ **Gradual Migration**: Eventually migrate to F0RT1KA-only signing
- ✅ **Best of Both Worlds**: Immediate compatibility + long-term scalability

## The Problem (Chicken-and-Egg)

**Original Approach:** F0RT1KA-only signing with self-healing cert installation
```
Test Binary → Signed with F0RT1KA cert
Windows Endpoint → No F0RT1KA cert installed
WDAC/App Control (signer rules) → Block execution (untrusted publisher; CodeIntegrity 3077)
Result: Binary never runs, cert_installer never executes ❌
```

**The Dilemma:**
- On endpoints enforcing signer-based App Control, the binary needs a trusted cert to run
- But binary must run to install F0RT1KA cert
- App Control blocks execution before cert installation can occur

(ASR is not part of this dilemma: ASR rules do not evaluate publisher trust.)

## The Solution (Dual Signing)

**New Approach:** Sign with org cert FIRST, then nest F0RT1KA cert
```
Test Binary → Dual-signed (org cert + F0RT1KA cert)
Windows Endpoint → Has org cert installed (from previous deployments)
WDAC/App Control → Allow execution (org cert matches signer rule)
Binary Executes → cert_installer runs
F0RT1KA Cert → Installed on endpoint for future use
Result: Immediate execution + self-healing enabled ✅
```

## How Dual Signing Works

### Technical Implementation

Windows validates code signatures using **OR logic**:
```
IF (Signature 1 is trusted) OR (Signature 2 is trusted) OR (Signature N is trusted)
THEN allow execution
```

A dual-signed binary has TWO signatures:
```
Binary: test.exe
├── Primary Signature: sb_codesign_cert (trusted by endpoint NOW)
└── Secondary Signature (nested): F0RT1KA cert (will be trusted AFTER first run)
```

### Signing Process

Using osslsigncode with `-nest` flag:
```bash
# Step 1: Sign with org certificate (primary signature)
osslsigncode sign \
    -pkcs12 signing-certs/sb_cert.pfx \
    -pass "password1" \
    -in test.exe \
    -out test-signed.exe

# Step 2: Add F0RT1KA certificate (nested/secondary signature)
osslsigncode sign -nest \
    -pkcs12 signing-certs/F0RT1KA.pfx \
    -pass "password2" \
    -in test-signed.exe \
    -out test-dual-signed.exe
```

The `-nest` flag preserves the first signature while adding the second.

## Usage

### Build & Sign with Dual Signing

**Recommended (Dual Signing for WDAC/App Control compatibility):**
```bash
# Dual-sign with sb + F0RT1KA
/build-sign-test 7e93865c-0033-4db3-af3c-a9f4215c1c49 sb

# Dual-sign with tpsgl + F0RT1KA
/build-sign-test b6c73735-0c24-4a1e-8f0a-3c24af39671b tpsgl

# Dual-sign with rga + F0RT1KA
/build-sign-test 109266e2-2310-40ea-9f63-b97e4b7fda61 rga
```

**F0RT1KA-only (For Future, After Migration Complete):**
```bash
# Single signature with F0RT1KA
/build-sign-test 7e93865c-0033-4db3-af3c-a9f4215c1c49
```

### Manual Dual Signing (Advanced)

Using `utils/codesign` directly:
```bash
# Dual-sign a binary
./utils/codesign sign-nested \
    build/test-uuid/test-uuid.exe \
    signing-certs/sb_cert.pfx \
    signing-certs/F0RT1KA.pfx

# Dual-sign a PowerShell script
./utils/codesign sign-nested \
    recovery.ps1 \
    signing-certs/sb_cert.pfx \
    signing-certs/F0RT1KA.pfx
```

## Migration Strategy

### Phase 1: Dual Signing (Current)

**Timeline:** Immediate - Present
**Action:** Sign all new tests with org cert + F0RT1KA

**Process:**
1. Build tests with `/build-sign-test <uuid> <org>`
2. Deploy to endpoints via LimaCharlie
3. Tests execute immediately (org cert trusted)
4. cert_installer pre-flight check installs F0RT1KA cert
5. F0RT1KA cert accumulates across endpoint fleet

**Benefits:**
- Zero deployment friction
- No signer-based WDAC/App Control blocks (ASR rules still apply and are behavior-based)
- Gradual F0RT1KA cert adoption

### Phase 2: Monitoring (Ongoing)

**Timeline:** Weeks to Months
**Action:** Monitor F0RT1KA cert installation across fleet

**Metrics to Track:**
```powershell
# On endpoints, check for F0RT1KA cert
Get-ChildItem -Path Cert:\LocalMachine\Root |
    Where-Object { $_.Subject -like "*F0RT1KA*" } |
    Measure-Object | Select-Object -ExpandProperty Count

# Via LimaCharlie (example query)
# Check test execution logs for "F0RT1KA certificate verified" messages
```

**Goals:**
- Reach 80%+ F0RT1KA cert coverage across fleet
- Verify cert installation is reliable
- Identify any endpoints with installation issues

### Phase 3: F0RT1KA-only (Future)

**Timeline:** After Phase 2 Goals Met
**Action:** Switch to F0RT1KA-only signing

**Process:**
1. Confirm F0RT1KA cert is on majority of endpoints
2. Begin signing new tests without org parameter: `/build-sign-test <uuid>`
3. Monitor for any execution issues
4. Gradually retire org-specific certificates

**Benefits:**
- Simplified signing workflow
- Single universal certificate
- No per-organization certificate management
- Fully self-healing deployment

## Certificate Trust Chains

### Current State (Dual Signing)

**Endpoint A (sb organization):**
```
Trusted Certificates:
  ├── sb_codesign_cert ✅ (installed previously)
  └── F0RT1KA ✅ (installed by test on first run)

Test Binary Signatures:
  ├── Primary: sb_codesign_cert → TRUSTED (immediate execution)
  └── Secondary: F0RT1KA → TRUSTED (after first run)
```

**Endpoint B (tpsgl organization):**
```
Trusted Certificates:
  ├── tpsgl_codesign_cert ✅ (installed previously)
  └── F0RT1KA ✅ (installed by test on first run)

Test Binary Signatures:
  ├── Primary: tpsgl_codesign_cert → TRUSTED (immediate execution)
  └── Secondary: F0RT1KA → TRUSTED (after first run)
```

### Future State (F0RT1KA-only)

**All Endpoints:**
```
Trusted Certificates:
  └── F0RT1KA ✅ (universally deployed)

Test Binary Signatures:
  └── F0RT1KA → TRUSTED (immediate execution)
```

## Verification

### Check Dual Signature on Windows

```powershell
# View all signatures on a binary
Get-AuthenticodeSignature test.exe | Select-Object -ExpandProperty SignerCertificate

# Expected output: TWO certificates listed
# 1. Organization-specific cert (e.g., sb_codesign_cert)
# 2. F0RT1KA Security Testing Framework
```

### Check Certificate Installation on Endpoint

```powershell
# Check if F0RT1KA cert is installed
Get-ChildItem -Path Cert:\LocalMachine\Root |
    Where-Object { $_.Subject -like "*F0RT1KA*" } |
    Format-List Subject, Thumbprint, NotBefore, NotAfter

# Expected output if installed:
# Subject: CN=F0RT1KA Security Testing Framework, O=F0RT1KA, C=US
# Thumbprint: <certificate thumbprint>
# NotBefore: 2025-10-24 ...
# NotAfter: 2030-10-23 ...
```

### Verify Test Execution Logs

```powershell
# Check test logs for certificate pre-flight check
Get-Content C:\F0\test_execution_log.txt | Select-String "certificate|Certificate"

# Expected messages:
# "Pre-flight: Checking F0RT1KA certificate..."
# "✅ F0RT1KA certificate verified" (if already installed)
# OR
# "⚠️ F0RT1KA certificate not found - installing..."
# "✅ F0RT1KA certificate installed successfully"
```

## Troubleshooting

### Issue: Dual Signing Fails

**Symptom:** `/build-sign-test` fails at signing step

**Possible Causes:**
1. Missing org-specific certificate
2. Missing F0RT1KA certificate
3. Incorrect password files
4. osslsigncode not supporting -nest flag

**Solution:**
```bash
# Verify both certificates exist
ls signing-certs/*.pfx

# Should show:
# signing-certs/F0RT1KA.pfx
# signing-certs/sb_codesign_cert.pfx (or similar)

# Verify password files exist
ls signing-certs/.*.pfx.txt

# Should show:
# signing-certs/.F0RT1KA.pfx.txt
# signing-certs/.sb_codesign_cert.pfx.txt (or similar)

# Test osslsigncode -nest support
osslsigncode --help | grep -i nest
# Should show: -nest - Sign nested signature
```

### Issue: Dual-Signed Binary Still Blocked

**First identify which control blocked it** — the fix is different:

| Control | Evidence | Cert-related? | Fix |
|---------|----------|---------------|-----|
| WDAC / App Control | CodeIntegrity/Operational **3077** (block) / **3076** (audit) | Yes | Trust the signing cert / add a signer rule to the App Control policy |
| Defender ASR | Windows Defender/Operational **1121** (block) / **1122** (audit), rule GUID in event | **No** | Expected prevention result; only an ASR exclusion changes it |
| SmartScreen / MotW | SmartScreen prompt, Zone.Identifier ADS | Partly (reputation) | Deliver without MotW / unblock file |

**Diagnostics:**
```powershell
# Which control fired?
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id=3076,3077} -MaxEvents 20
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1121,1122} -MaxEvents 20

# WDAC/App Control: verify org cert is trusted and the policy state
Get-ChildItem -Path Cert:\LocalMachine\Root, Cert:\LocalMachine\TrustedPublisher |
    Where-Object { $_.Subject -like "*<org>*" }
CiTool.exe -lp

# If not found, manually install org cert (affects WDAC/SmartScreen trust, NOT ASR):
Import-Certificate -FilePath "org_cert.cer" -CertStoreLocation Cert:\LocalMachine\Root

# ASR: rule states and exclusions (signing has no effect here)
Get-MpPreference | Select-Object AttackSurfaceReductionRules_*, AttackSurfaceReductionOnlyExclusions

# Verify binary signature is recognized
Get-AuthenticodeSignature "test.exe" | Format-List *
```

### Issue: F0RT1KA Cert Not Installing

**Symptom:** Test runs but F0RT1KA cert not in certificate store

**Possible Causes:**
1. Test not running with elevated privileges (requires SYSTEM/Admin)
2. cert_installer module not included in test
3. PowerShell execution policy blocking cert installation

**Solution:**
```powershell
# Check if test includes cert_installer
Get-Content tests_source/<uuid>/<uuid>.go | Select-String "cert_installer"

# Should show:
# import cert_installer "github.com/preludeorg/libraries/go/tests/cert_installer"
# if err := cert_installer.EnsureCertificateInstalled(); err != nil {

# Verify test runs with SYSTEM privileges via LimaCharlie
whoami
# Expected: nt authority\system

# Check PowerShell execution policy
Get-ExecutionPolicy -List
# LocalMachine should be RemoteSigned or Bypass
```

## Technical Details

### Signature Storage Format

Windows PE (Portable Executable) format supports multiple signatures via **Authenticode**:

```
PE File Structure:
├── DOS Header
├── PE Header
├── Section Headers
├── Sections (.text, .data, etc.)
└── Authenticode Signature Block
    ├── PKCS#7 SignedData (Signature 1)
    └── PKCS#7 SignedData (Signature 2) ← Nested signature
```

Each signature is a complete PKCS#7 SignedData structure containing:
- Signer certificate
- Certificate chain
- Timestamp (optional)
- Signed file hash

### Validation Logic

Windows validates signatures in order:
1. Extract all PKCS#7 SignedData structures
2. For each signature:
   - Verify certificate chain
   - Check certificate trust (LocalMachine\Root or TrustedPublisher)
   - Verify file hash matches
   - Check timestamp validity (if present)
3. **Allow execution if ANY signature is valid and trusted**

This OR logic is what makes dual signing effective for gradual migration.

### PowerShell Script Dual Signing

PowerShell scripts support multiple signatures natively:

```powershell
# Sign with first certificate
Set-AuthenticodeSignature -FilePath script.ps1 -Certificate $cert1

# Append second signature (doesn't replace first)
Set-AuthenticodeSignature -FilePath script.ps1 -Certificate $cert2

# Result: script.ps1 has TWO signature blocks appended
```

Each signature block is added to the end of the script as commented sections:
```powershell
# Script code here
...

# SIG # Begin signature block (Certificate 1)
# MIIXAgYJKoZIhvcNAQcCoIIW8zCCFu8CAQExCzAJBgUr...
# SIG # End signature block

# SIG # Begin signature block (Certificate 2)
# MIIXAwYJKoZIhvcNAQcCoIIW9DCCFvACAQExCzAJBgUr...
# SIG # End signature block
```

## References

### Documentation
- `signing-certs/README.md` - Certificate management guide
- `SELF_HEALING_CERT_IMPLEMENTATION.md` - Self-healing architecture
- `BUILD_SIGN_TEST_MIGRATION.md` - build-sign-test command migration

### Code
- `utils/codesign` - Dual signing implementation
- `.claude/commands/build-sign-test.md` - Automated build & dual-sign workflow
- `preludeorg-libraries/go/tests/cert_installer/` - Self-healing cert installer

### External Resources
- [osslsigncode Documentation](https://github.com/mtrojnar/osslsigncode)
- [Microsoft Authenticode Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)
- [PKCS#7 Specification](https://tools.ietf.org/html/rfc2315)

## FAQ

**Q: Will dual signing increase binary size?**
A: Yes, slightly. Each signature adds ~3-5KB (certificate + metadata). A dual-signed binary is typically 6-10KB larger than single-signed.

**Q: Can I dual-sign with more than two certificates?**
A: Yes, theoretically unlimited. Windows supports multiple nested signatures. However, two signatures (org + F0RT1KA) is sufficient for our use case.

**Q: Do both signatures need to be from the same issuer?**
A: No. Signatures are independent. One can be self-signed (F0RT1KA), the other from a commercial CA (org cert).

**Q: What happens if one signature expires?**
A: If ANY signature is valid and trusted, the binary executes. Expired signatures are ignored by Windows.

**Q: Can I verify dual signatures on macOS/Linux?**
A: osslsigncode can verify signatures, but full validation requires Windows. Use `osslsigncode verify` for basic checks.

**Q: Does dual signing affect test performance?**
A: No. Signature validation happens at load time (before execution). Once validated, performance is identical to single-signed or unsigned binaries.

## Summary

Dual signing solves the signer-trust (WDAC/App Control, SmartScreen) chicken-and-egg problem by combining the immediate compatibility of organization-specific certificates with the long-term scalability of the F0RT1KA universal certificate. This gradual migration strategy ensures zero deployment friction while building toward a fully self-healing security testing infrastructure. It does not, and is not meant to, bypass Defender ASR rules; ASR blocks of test behavior are legitimate prevention results.

**Recommended Action:** Use dual signing (`/build-sign-test <uuid> <org>`) for all tests until F0RT1KA certificate coverage reaches 80%+ across your endpoint fleet.

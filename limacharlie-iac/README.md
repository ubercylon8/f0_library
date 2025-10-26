# F0RT1KA LimaCharlie Infrastructure as Code

Automated F0RT1KA certificate deployment using LimaCharlie Detection & Response rules and Infrastructure as Code.

## Overview

This directory contains LimaCharlie Infrastructure as Code (IaC) components for automatically installing the F0RT1KA code signing certificate on Windows endpoints when LimaCharlie sensors enroll.

**Advantages over embedded approach:**
- ✅ Centralized management - One deployment for entire organization
- ✅ Automatic installation - Certificate installed within seconds of sensor enrollment
- ✅ Simplified tests - No cert_installer code needed in test binaries
- ✅ Easy updates - Update certificate once, applies to all endpoints
- ✅ Fully auditable - All operations logged in LimaCharlie platform
- ✅ Infrastructure as Code - Version controlled YAML templates

## Directory Structure

```
limacharlie-iac/
├── payloads/
│   └── install-f0rtika-cert.ps1      # PowerShell certificate installation script
├── rules/
│   ├── f0rtika-cert-auto-install.yaml           # Main D&R rule for auto-installation
│   ├── f0rtika-cert-install-monitor.yaml        # Monitoring rule for failures
│   └── f0rtika-cert-install-success-monitor.yaml # Optional success tracking
├── scripts/
│   └── deploy-cert-installer.sh      # Multi-org deployment automation
├── f0rtika-org-template.yaml         # Complete organization IaC template
└── README.md                         # This file
```

## Quick Start

### Prerequisites

1. **LimaCharlie CLI installed:**
   ```bash
   pip install limacharlie
   ```

2. **API keys configured** for target organizations

3. **Organization created** in LimaCharlie

### Deployment (3 Steps)

#### Step 1: Upload Payload

**Via Web UI (Recommended):**
1. Navigate to: **Sensors → Payloads**
2. Click **Create Payload**
3. Name: `f0rtika-cert-installer`
4. Upload: `limacharlie-iac/payloads/install-f0rtika-cert.ps1`

**Via REST API:**
```bash
# Request signed upload URL
curl -X POST "https://api.limacharlie.io/v1/<OID>/payloads" \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"name": "f0rtika-cert-installer"}'

# Upload payload
curl -X PUT "<SIGNED_URL>" \
  -H "Content-Type: application/octet-stream" \
  --upload-file payloads/install-f0rtika-cert.ps1
```

#### Step 2: Deploy D&R Rules

**Option A - Use Deployment Script (Easiest):**
```bash
# Deploy to single organization
./scripts/deploy-cert-installer.sh sb

# Deploy to all organizations
./scripts/deploy-cert-installer.sh all

# Test mode (dry run)
./scripts/deploy-cert-installer.sh --test sb
```

**Option B - Manual Deployment:**
```bash
# Deploy auto-installation rule
limacharlie --org <org-name> dr add rules/f0rtika-cert-auto-install.yaml

# Deploy monitoring rule (optional)
limacharlie --org <org-name> dr add rules/f0rtika-cert-install-monitor.yaml

# Deploy success tracking rule (optional)
limacharlie --org <org-name> dr add rules/f0rtika-cert-install-success-monitor.yaml
```

**Option C - Full Organization Template:**
```bash
# Apply complete template with all rules
limacharlie --org <org-name> config push f0rtika-org-template.yaml
```

#### Step 3: Verify Deployment

**Check Rule Status:**
```bash
# List D&R rules
limacharlie --org <org-name> dr list

# Verify auto-installation rule exists
limacharlie --org <org-name> dr list | grep f0rtika-cert-auto-install
```

**Monitor Events:**
1. Install LimaCharlie sensor on Windows VM
2. In LimaCharlie UI: **Events → Filter: deployment, CONNECTED**
3. Check for RECEIPT event with certificate installation output

**Verify Certificate on Endpoint:**
```powershell
certutil -store Root | findstr /i "F0RT1KA"
```

Expected output:
```
Issuer: CN=F0RT1KA Security Testing Framework, O=F0RT1KA, C=US
Subject: CN=F0RT1KA Security Testing Framework, O=F0RT1KA, C=US
```

---

## Component Details

### 1. PowerShell Installation Script

**File:** `payloads/install-f0rtika-cert.ps1`

**What it does:**
- Checks if F0RT1KA certificate already installed (idempotent)
- Decodes base64 certificate data
- Creates temporary certificate file
- Imports certificate to LocalMachine\Root
- Verifies installation
- Cleans up temporary files
- Comprehensive logging for troubleshooting

**Parameters:**
- `-CertBase64` (required) - Base64-encoded F0RT1KA.cer certificate

**Exit codes:**
- `0` - Success (certificate installed or already present)
- `1` - Failure (permission denied, decode error, import failed, etc.)

**Output:**
All output is captured in LimaCharlie RECEIPT event for debugging.

### 2. Auto-Installation D&R Rule

**File:** `rules/f0rtika-cert-auto-install.yaml`

**Trigger:** `CONNECTED` event (when Windows sensors come online)

**Action:** Executes PowerShell payload to install certificate

**Suppression:** Runs once per sensor (30 days) using sensor ID as key

**How it works:**
```yaml
detect:
  target: deployment
  event: CONNECTED
  op: is platform
    name: windows

respond:
  - action: task
    command: run --payload-name f0rtika-cert-installer --interpreter powershell --arguments " -CertBase64 '<BASE64_CERT>'" --timeout 120
    suppression:
      is_global: false
      keys:
        - '{{ .routing.sid }}'
      max_count: 1
      period: 2592000
```

### 3. Monitoring Rules

**Failure Monitoring:** `rules/f0rtika-cert-install-monitor.yaml`
- Detects non-zero exit codes from installation script
- Creates detection report for investigation
- Helps identify permission issues, script errors, etc.

**Success Tracking:** `rules/f0rtika-cert-install-success-monitor.yaml`
- Optional audit trail for successful installations
- Useful for compliance and reporting
- Can be enabled/disabled as needed

### 4. Deployment Script

**File:** `scripts/deploy-cert-installer.sh`

**Features:**
- Deploy to single or multiple organizations
- Test mode for dry runs
- Interactive prompts for optional components
- Prerequisite checking
- Verification steps

**Usage:**
```bash
./deploy-cert-installer.sh <org-name|all>  # Production deployment
./deploy-cert-installer.sh --test <org>    # Dry run
```

---

## Testing the Deployment

### Phase 1: Proof of Concept (1 Lab VM)

1. **Deploy to test organization:**
   ```bash
   ./scripts/deploy-cert-installer.sh test-org
   ```

2. **Install LimaCharlie sensor on Windows VM:**
   - Download installer from LimaCharlie UI
   - Run with installation key
   - Sensor should enroll within seconds

3. **Monitor deployment events:**
   - LimaCharlie UI: **Events → deployment**
   - Look for `CONNECTED` event
   - Look for `RECEIPT` event with installation output

4. **Verify certificate:**
   ```powershell
   certutil -store Root | findstr /i "F0RT1KA"
   ```

5. **Deploy F0RT1KA test (without cert_installer):**
   ```bash
   # Build and sign test
   /build-sign-test <test-uuid> sb

   # Deploy via LimaCharlie
   # Test should execute normally with exit code 101 or 126
   ```

### Phase 2: Multi-Endpoint Validation (3-5 VMs)

1. **Deploy to production organization:**
   ```bash
   ./scripts/deploy-cert-installer.sh sb
   ```

2. **Install sensors on multiple endpoints:**
   - Different Windows versions (Win10, Win11, Server 2019, Server 2022)
   - Different architectures (x64, x86)

3. **Verify all endpoints:**
   ```bash
   # On each endpoint
   certutil -store Root | findstr /i "F0RT1KA"
   ```

4. **Deploy tests to all endpoints:**
   - Verify tests execute without cert_installer errors
   - Check exit codes (101 or 126, not 999)

### Phase 3: Production Rollout

1. **Deploy to all organizations:**
   ```bash
   ./scripts/deploy-cert-installer.sh all
   ```

2. **Monitor for 24-48 hours:**
   - Check for installation failures in detections
   - Review RECEIPT events for errors
   - Verify new sensor enrollments trigger installation

3. **Update test templates:**
   - New tests can omit cert_installer module
   - Existing tests continue to work (hybrid approach)

---

## Troubleshooting

### Certificate Installation Fails

**Symptom:** RECEIPT event shows exit code 1

**Common causes:**
1. **Permission denied:**
   - Ensure LimaCharlie sensor running as SYSTEM
   - Check: `whoami` in PowerShell output shows `NT AUTHORITY\SYSTEM`

2. **Base64 decode error:**
   - Verify certificate data in YAML is correct
   - Check for line breaks or truncation

3. **Import failed:**
   - Certificate might be corrupt
   - Check certificate validity period

**Solution:**
```bash
# Check RECEIPT event output in LimaCharlie UI
# Look for error messages in PowerShell output
# Verify certificate is valid:
openssl x509 -in signing-certs/F0RT1KA.cer -text -noout
```

### Rule Not Triggering

**Symptom:** Sensor connects but no RECEIPT event

**Common causes:**
1. **Rule not deployed:**
   ```bash
   limacharlie --org <org> dr list | grep f0rtika-cert-auto-install
   ```

2. **Payload not uploaded:**
   - Check in UI: Sensors → Payloads
   - Look for `f0rtika-cert-installer`

3. **Wrong platform:**
   - Rule only triggers on Windows
   - Check sensor platform in LimaCharlie UI

4. **Suppression active:**
   - Rule only runs once per sensor per 30 days
   - Check sensor SID in suppression keys

**Solution:**
```bash
# Re-deploy rule
limacharlie --org <org> dr add rules/f0rtika-cert-auto-install.yaml

# Verify payload exists
# Upload if missing via Web UI
```

### Certificate Already Installed (Exit 0)

**Symptom:** RECEIPT shows "Certificate already installed" even on new endpoint

**Causes:**
1. **Certificate manually installed** (expected)
2. **Sensor re-enrolled** (suppression prevents re-run)
3. **VM snapshot restored** (certificate persisted)

**This is NORMAL behavior** - idempotent design means script succeeds whether certificate was already present or newly installed.

---

## Updating the Certificate

### When Certificate Expires (2030)

1. **Generate new certificate:**
   ```bash
   # Follow certificate generation procedure
   # Update F0RT1KA.cer in signing-certs/
   ```

2. **Convert to base64:**
   ```bash
   base64 -i signing-certs/F0RT1KA.cer | tr -d '\n' > signing-certs/F0RT1KA.cer.b64
   ```

3. **Update D&R rule:**
   - Edit `rules/f0rtika-cert-auto-install.yaml`
   - Replace base64 certificate data
   - Redeploy to all organizations

4. **For existing endpoints:**
   ```bash
   # Option A: Run payload manually via LimaCharlie UI
   # Sensors → Select sensor → Tasks → run

   # Option B: Create one-time D&R rule without suppression
   # to force re-installation on all endpoints
   ```

---

## Multi-Organization Deployment

### Scenario: Manage multiple organizations (sb, tpsgl, rga)

**Deployment workflow:**
```bash
# Deploy to all organizations at once
./scripts/deploy-cert-installer.sh all

# Or deploy individually
for org in sb tpsgl rga; do
    ./scripts/deploy-cert-installer.sh $org
done
```

**Customization per organization:**
1. Create organization-specific templates:
   ```yaml
   # f0rtika-org-template-sb.yaml
   # f0rtika-org-template-tpsgl.yaml
   # f0rtika-org-template-rga.yaml
   ```

2. Deploy custom templates:
   ```bash
   limacharlie --org sb config push f0rtika-org-template-sb.yaml
   limacharlie --org tpsgl config push f0rtika-org-template-tpsgl.yaml
   limacharlie --org rga config push f0rtika-org-template-rga.yaml
   ```

---

## Integration with F0RT1KA Tests

### Simplified Test Template (No cert_installer)

```go
//go:build windows

package main

import (
    Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

func main() {
    // No cert_installer needed - certificate already installed via LimaCharlie IaC

    // Extract embedded components
    if err := extractEmbeddedComponents(); err != nil {
        Endpoint.Say("❌ FATAL: Component extraction failed: %v", err)
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }

    // Run test
    test()
}

func test() {
    // Test logic here
    Endpoint.Stop(Endpoint.Unprotected)
}
```

### Hybrid Approach (Belt and Suspenders)

```go
func main() {
    // Quick check - if cert exists, proceed immediately
    if isCertInstalled() {
        Endpoint.Say("✅ F0RT1KA certificate found (installed via LimaCharlie)")
        test()
        return
    }

    // Fallback - install via embedded method (rare edge case)
    Endpoint.Say("⚠️ Certificate not found, using fallback installation...")
    if err := cert_installer.EnsureCertificateInstalled(); err != nil {
        Endpoint.Say("❌ FATAL: Certificate installation failed: %v", err)
        Endpoint.Stop(Endpoint.UnexpectedTestError)
    }

    test()
}

func isCertInstalled() bool {
    // Lightweight PowerShell check
    cmd := exec.Command("powershell.exe", "-NoProfile", "-Command",
        `(Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*F0RT1KA*"}) -ne $null`)
    output, _ := cmd.Output()
    return strings.TrimSpace(string(output)) == "True"
}
```

---

## Security Considerations

### Certificate Trust

- F0RT1KA certificate is **self-signed** for testing purposes
- Installing to Trusted Root grants **full trust** to F0RT1KA signed binaries
- Use **only in testing/lab environments**
- **Do NOT deploy to production systems** outside of security testing scope

### Payload Execution

- PowerShell script runs with **SYSTEM privileges** (via LimaCharlie sensor)
- Script performs **certificate installation only** (no other modifications)
- All operations are **logged and auditable**
- Script is **idempotent** (safe to run multiple times)

### Access Control

- Limit payload upload permissions (`payload.ctrl`)
- Limit payload execution permissions (`payload.use`)
- Use organization-specific API keys
- Enable MFA on LimaCharlie accounts

---

## Support and Contribution

### Getting Help

- **Documentation:** See main `CLAUDE.md` in repository root
- **Issues:** Check `limacharlie-iac/TROUBLESHOOTING.md`
- **LimaCharlie Docs:** https://docs.limacharlie.io

### Contributing

When updating this IaC implementation:
1. Test in lab environment first
2. Update documentation in this README
3. Update CLAUDE.md if changing approach
4. Commit with descriptive message

---

## Appendix

### LimaCharlie Resources

- **API Documentation:** https://docs.limacharlie.io/apidocs
- **D&R Rules Guide:** https://docs.limacharlie.io/docs/detection-and-response
- **Payloads Guide:** https://docs.limacharlie.io/docs/payloads
- **Infrastructure as Code:** https://docs.limacharlie.io/docs/infrastructure-as-code

### F0RT1KA Resources

- **Main Documentation:** `CLAUDE.md`
- **Dual Signing Guide:** `DUAL_SIGNING_STRATEGY.md`
- **Build Utilities:** `utils/README.md`
- **Test Templates:** `sample_tests/`

### Certificate Information

- **Certificate File:** `signing-certs/F0RT1KA.cer`
- **Validity:** 2025-10-25 to 2030-10-24 (5 years)
- **Subject:** `CN=F0RT1KA Security Testing Framework, O=F0RT1KA, C=US`
- **Usage:** Code Signing, Trusted Root Certification Authority

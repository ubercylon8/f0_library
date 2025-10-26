# F0RT1KA LimaCharlie IaC - Quick Start Guide

Get F0RT1KA certificate auto-installation running in 10 minutes.

## Prerequisites (2 minutes)

```bash
# 1. Install LimaCharlie CLI
pip install limacharlie

# 2. Verify installation
limacharlie --version

# 3. Configure API key (if not already done)
limacharlie login
```

## Deployment (5 minutes)

### Option A: Automated Script (Easiest)

```bash
cd limacharlie-iac/scripts

# Deploy to single organization
./deploy-cert-installer.sh sb

# Follow prompts to:
# 1. Upload payload (manual via Web UI)
# 2. Deploy D&R rules
# 3. Enable monitoring (optional)
```

### Option B: Manual Steps

**Step 1: Upload Payload**
1. Open LimaCharlie Web UI
2. Navigate to: **Sensors → Payloads**
3. Click **Create Payload**
4. Name: `f0rtika-cert-installer`
5. Upload: `limacharlie-iac/payloads/install-f0rtika-cert.ps1`

**Step 2: Deploy D&R Rule**
```bash
cd limacharlie-iac

# Deploy auto-installation rule
limacharlie --org <your-org> dr add rules/f0rtika-cert-auto-install.yaml

# Optional: Deploy monitoring rule
limacharlie --org <your-org> dr add rules/f0rtika-cert-install-monitor.yaml
```

## Verification (3 minutes)

### Test with Lab VM

**1. Install LimaCharlie sensor on Windows VM:**
```powershell
# Download installer from LimaCharlie UI
# Run: installer.exe -i <installation-key>
```

**2. Monitor Events in LimaCharlie UI:**
- Events → Filter: `deployment`
- Look for `CONNECTED` event
- Look for `RECEIPT` event with certificate installation output

**3. Verify Certificate on Endpoint:**
```powershell
certutil -store Root | findstr /i "F0RT1KA"
```

**Expected Output:**
```
Issuer: CN=F0RT1KA Security Testing Framework, O=F0RT1KA, C=US
Subject: CN=F0RT1KA Security Testing Framework, O=F0RT1KA, C=US
```

**4. Deploy F0RT1KA Test:**
```bash
# From repository root
cd /path/to/f0_library

# Build and sign test
/build-sign-test 931f91ef-c7c0-4c3c-b61b-03992edb5e5f sb

# Deploy via LimaCharlie to test endpoint
# Test should execute with exit code 101 or 126 (not 999)
```

## Success Indicators

✅ **Deployment Successful:**
- Payload visible in LimaCharlie UI: Sensors → Payloads
- D&R rule visible: `limacharlie --org <org> dr list | grep f0rtika-cert-auto-install`

✅ **Installation Successful:**
- RECEIPT event shows exit code 0
- Output contains: "RESULT: SUCCESS"
- Certificate found on endpoint

✅ **Test Execution Successful:**
- F0RT1KA test runs without certificate errors
- Exit code is 101 (vulnerable) or 126 (protected)
- NOT 999 (unexpected error)

## Troubleshooting

### Rule Not Triggering

```bash
# Check rule deployed
limacharlie --org <org> dr list

# Re-deploy if missing
limacharlie --org <org> dr add rules/f0rtika-cert-auto-install.yaml
```

### Certificate Installation Failed

```bash
# Check RECEIPT event in LimaCharlie UI
# Look for error message in PowerShell output

# Common causes:
# - Sensor not running as SYSTEM
# - Payload name mismatch (must be: f0rtika-cert-installer)
# - Base64 certificate data corrupt
```

### Test Gets Exit 999

**Cause:** Certificate not installed (IaC not deployed or sensor enrolled before rule activation)

**Solution:**
```powershell
# Manually run installation on endpoint
# Or wait for next sensor re-enrollment (30 days)
# Or remove suppression from rule to force re-run
```

## Next Steps

After successful deployment:

1. **Deploy to all organizations:**
   ```bash
   ./scripts/deploy-cert-installer.sh all
   ```

2. **Use simplified test template for new tests:**
   ```bash
   # Copy template
   UUID=$(uuidgen | tr '[:upper:]' '[:lower:]')
   cp -r sample_tests/simplified-template-limacharlie-iac tests_source/$UUID

   # Customize and build
   # No cert_installer code needed!
   ```

3. **Monitor deployments:**
   - Check LimaCharlie detections for installation failures
   - Review RECEIPT events periodically
   - Verify new sensors get certificate automatically

## Support

- **Full Documentation:** `limacharlie-iac/README.md`
- **Troubleshooting:** `limacharlie-iac/README.md` (Troubleshooting section)
- **Development Guidelines:** `CLAUDE.md`
- **LimaCharlie Docs:** https://docs.limacharlie.io

## Quick Reference

**Key Files:**
- `payloads/install-f0rtika-cert.ps1` - Installation script
- `rules/f0rtika-cert-auto-install.yaml` - D&R rule
- `scripts/deploy-cert-installer.sh` - Deployment script

**Key Commands:**
```bash
# Deploy
limacharlie --org <org> dr add rules/f0rtika-cert-auto-install.yaml

# Verify
limacharlie --org <org> dr list | grep f0rtika-cert-auto-install

# Check endpoint
certutil -store Root | findstr /i "F0RT1KA"
```

**Exit Codes:**
- `0` - Certificate installed successfully
- `1` - Installation failed
- `101` - Test: System vulnerable
- `126` - Test: System protected
- `999` - Test: Unexpected error

---

**Total Time:** ~10 minutes for first deployment, ~2 minutes per additional organization

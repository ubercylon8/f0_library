# /build-sign-test Migration Guide

**Date**: 2025-10-24
**Version**: 2.0 (F0RT1KA Self-Healing Compatible)

---

## What Changed

The `/build-sign-test` command has been updated to support the new **F0RT1KA self-healing certificate deployment** while maintaining **100% backward compatibility** with existing organization-specific certificates.

---

## TL;DR - Quick Migration

### Old Way (Still Works)
```bash
/build-sign-test b6c73735-0c24-4a1e-8f0a-3c24af39671b sb
```

### New Way (Recommended)
```bash
/build-sign-test b6c73735-0c24-4a1e-8f0a-3c24af39671b
```

**That's it!** Omit the org parameter and it automatically uses the F0RT1KA universal certificate.

---

## Detailed Changes

### 1. Org Parameter Now Optional

**Before (Required):**
```bash
/build-sign-test <test-uuid> <org>
```

**After (Optional):**
```bash
/build-sign-test <test-uuid> [org]
```

### 2. Default Certificate: F0RT1KA

When no `org` parameter is provided:
- **Default**: Uses `F0RT1KA` universal certificate
- **Benefit**: Self-healing deployment (no manual cert install on endpoints)

### 3. New Valid Organizations

**Valid options:**
- `f0rt1ka` - Universal F0RT1KA certificate (default, **recommended**)
- `sb` - Organization-specific (legacy)
- `tpsgl` - Organization-specific (legacy)
- `rga` - Organization-specific (legacy)

---

## What Still Gets Signed (Unchanged)

The signing workflow is **100% identical**:

✅ **Helper Binaries** - All standalone .go files (with `package main` + `func main()`)
✅ **PowerShell Scripts** - All .ps1 files referenced in `//go:embed` directives
✅ **Main Test Binary** - Final executable with all embedded components

**Only difference:** Which certificate is used for signing.

---

## Usage Examples

### Recommended: F0RT1KA Universal Certificate

```bash
# Option 1: Implicit default (recommended)
/build-sign-test b6c73735-0c24-4a1e-8f0a-3c24af39671b

# Option 2: Explicit F0RT1KA
/build-sign-test b6c73735-0c24-4a1e-8f0a-3c24af39671b f0rt1ka
```

**Output:**
```
✅ Using F0RT1KA universal certificate (self-healing deployment)
✅ Found F0RT1KA password file
...
[All components signed with F0RT1KA.pfx]
```

### Legacy: Organization-Specific Certificates

```bash
# Still works exactly as before
/build-sign-test b6c73735-0c24-4a1e-8f0a-3c24af39671b sb
/build-sign-test 109266e2-2310-40ea-9f63-b97e4b7fda61 rga
```

**Output:**
```
✅ Using organization-specific certificate (legacy): F0-LocalCodeSigningCert-CST-SB.pfx
✅ Found password file: .F0-LocalCodeSigningCert-CST-SB.pfx.txt
...
[All components signed with org-specific cert]
```

---

## Certificate Selection Logic

### F0RT1KA Certificate (Default)
When `org` is `f0rt1ka` or not specified:
```bash
Certificate:    signing-certs/F0RT1KA.pfx
Password File:  signing-certs/.F0RT1KA.pfx.txt
```

### Organization-Specific Certificates (Legacy)
When `org` is `sb`, `tpsgl`, or `rga`:
```bash
Certificate:    signing-certs/*${ORG}*.pfx  (grep-based search)
Password File:  signing-certs/.*${ORG}*.txt (grep-based search)
```

---

## Requirements

### For F0RT1KA Certificate (Default)
- `signing-certs/F0RT1KA.pfx` must exist
- `signing-certs/.F0RT1KA.pfx.txt` password file must exist

**If missing:**
```
❌ Error: F0RT1KA certificate not found at signing-certs/F0RT1KA.pfx

The F0RT1KA universal certificate is required for self-healing tests.
Please ensure the certificate has been generated.

See: signing-certs/README.md for certificate generation instructions
```

### For Org-Specific Certificates (Legacy)
- Certificate file in `signing-certs/` containing org string in filename
- Password file in `signing-certs/` starting with `.` and containing org string

---

## Benefits of F0RT1KA Certificate

### Self-Healing Deployment
- **Before**: Manual certificate installation on every endpoint
- **After**: Tests auto-install certificate on first run

### Universal Across Organizations
- **Before**: Different certificate per organization (sb, tpsgl, rga)
- **After**: One certificate works everywhere

### Scalable
- **Before**: Manual work per org, per endpoint
- **After**: Deploy to unlimited endpoints via LimaCharlie without prep

### Auto-Renewal
- **Before**: Re-deploy new cert to all endpoints when expired
- **After**: Tests auto-install updated cert on next run

---

## Migration Paths

### Path 1: Gradual Migration (Recommended)

**New tests:** Use F0RT1KA (default)
```bash
/build-sign-test <new-test-uuid>
```

**Existing tests:** Keep using org-specific certs
```bash
/build-sign-test <existing-test-uuid> sb
```

**When ready:** Rebuild existing tests with F0RT1KA
```bash
/build-sign-test <existing-test-uuid>  # Omit org parameter
```

### Path 2: Full Migration (All at Once)

Rebuild all tests with F0RT1KA:
```bash
# For each test UUID
/build-sign-test <test-uuid-1>
/build-sign-test <test-uuid-2>
/build-sign-test <test-uuid-3>
...
```

**Benefits:**
- All tests use universal certificate
- Simplified deployment across orgs
- Self-healing for all tests

### Path 3: Keep Legacy (No Migration)

Continue using org-specific certificates:
```bash
# Always specify org parameter
/build-sign-test <test-uuid> sb
```

**Note:** Still requires manual certificate installation on endpoints.

---

## Troubleshooting

### Error: "F0RT1KA certificate not found"

**Cause:** F0RT1KA.pfx doesn't exist in signing-certs/

**Solution:**
```bash
# Check if certificate exists
ls -la signing-certs/F0RT1KA.pfx

# If missing, see certificate generation guide
cat signing-certs/README.md
```

### Error: "F0RT1KA password file not found"

**Cause:** .F0RT1KA.pfx.txt doesn't exist

**Solution:**
```bash
# Check if password file exists
ls -la signing-certs/.F0RT1KA.pfx.txt

# If missing, regenerate certificate (includes password file)
```

### Legacy Org Certificate Still Works

If you want to use a specific org certificate:
```bash
# Just add the org parameter
/build-sign-test <test-uuid> sb
```

**Backward compatibility is maintained!**

---

## What Didn't Change

### Signing Workflow (100% Identical)
- Helper binary building → **No change**
- Helper binary signing → **No change** (just different cert)
- PowerShell script signing → **No change** (just different cert)
- Main binary building → **No change**
- Main binary signing → **No change** (just different cert)
- Cleanup process → **No change**
- Verification → **No change**

### Command Structure
- Still takes test UUID as first argument
- Still supports org parameter (now optional)
- Still uses same workflow steps
- Still produces same output structure

### Output Format
- Same progress messages
- Same success/error messages
- Same final binary location
- Same component summary

---

## Comparison Table

| Feature | Before (Org Required) | After (Org Optional) |
|---------|----------------------|----------------------|
| **Default Certificate** | ❌ No default (required) | ✅ F0RT1KA (self-healing) |
| **Usage Syntax** | `<uuid> <org>` | `<uuid> [org]` |
| **F0RT1KA Support** | ❌ Not recognized | ✅ Default option |
| **Legacy Org Certs** | ✅ Only option | ✅ Still supported |
| **Manual Cert Install** | ✅ Required per endpoint | ❌ Not needed (auto) |
| **Multi-Org Deployment** | ❌ Separate certs per org | ✅ One cert all orgs |
| **Command Length** | Longer (requires org) | Shorter (org optional) |
| **Backward Compatibility** | N/A | ✅ 100% compatible |

---

## Testing Your Migration

### Test 1: F0RT1KA Default (New Way)
```bash
# Build without org parameter
/build-sign-test b6c73735-0c24-4a1e-8f0a-3c24af39671b

# Expected output:
# ✅ Using F0RT1KA universal certificate (self-healing deployment)
# ✅ Found F0RT1KA password file
# [... signing process ...]
# 🎉 BUILD & SIGN COMPLETE!
```

### Test 2: Legacy Org (Old Way)
```bash
# Build with org parameter
/build-sign-test b6c73735-0c24-4a1e-8f0a-3c24af39671b sb

# Expected output:
# ✅ Using organization-specific certificate (legacy): F0-LocalCodeSigningCert-CST-SB.pfx
# [... signing process ...]
# 🎉 BUILD & SIGN COMPLETE!
```

### Test 3: Verify Signed Components
```bash
# Check final binary signature
./utils/codesign verify build/<test-uuid>/<test-uuid>.exe

# Expected: Certificate verification succeeds
```

---

## FAQ

### Q: Do I need to update my existing workflows?
**A:** No! Existing commands with org parameter still work exactly as before.

### Q: What happens if I omit the org parameter now?
**A:** It defaults to F0RT1KA universal certificate (self-healing tests).

### Q: Can I still use organization-specific certificates?
**A:** Yes! Just specify the org parameter as before: `/build-sign-test <uuid> sb`

### Q: Will this break my existing tests?
**A:** No! 100% backward compatible. Existing commands work unchanged.

### Q: What's the benefit of migrating to F0RT1KA?
**A:** Self-healing deployment - no manual certificate installation on endpoints.

### Q: How do I know which certificate was used?
**A:** Check the build output:
- F0RT1KA: `✅ Using F0RT1KA universal certificate (self-healing deployment)`
- Legacy: `✅ Using organization-specific certificate (legacy): <filename>`

### Q: What if F0RT1KA certificate doesn't exist?
**A:** You'll get a clear error with instructions to generate it. See `signing-certs/README.md`

### Q: Can I explicitly request F0RT1KA certificate?
**A:** Yes! Use `/build-sign-test <uuid> f0rt1ka` (though it's the default anyway)

---

## Summary

**What Changed:**
- Org parameter is now **optional**
- Defaults to **F0RT1KA** universal certificate
- F0RT1KA added as valid organization option

**What Didn't Change:**
- All signing workflow steps
- All component handling
- Legacy org support
- Command structure
- Output format

**Recommendation:**
- **New tests**: Use default (omit org parameter)
- **Existing tests**: Migrate gradually or keep as-is
- **Both options work perfectly!**

---

## Resources

- **Certificate Management**: `signing-certs/README.md`
- **Self-Healing Implementation**: `SELF_HEALING_CERT_IMPLEMENTATION.md`
- **Framework Documentation**: `CLAUDE.md`
- **Agent Instructions**: `.claude/agents/sectest-builder.md`

---

**Questions?** Check the documentation files listed above or review the `/build-sign-test` command help.

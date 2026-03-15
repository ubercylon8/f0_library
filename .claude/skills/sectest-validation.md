---
name: sectest-validation
description: Final validation phase for F0RT1KA tests. Verifies all Phase 2 output files exist, syncs ES catalog, deploys to target endpoint for validation, and commits all files to git.
---

# Test Validation & Finalization

This skill handles Phase 3 of security test creation: validating all outputs, syncing to Elasticsearch, deploying for endpoint validation, and committing. It runs AFTER all Phase 2 agents (documentation, detection-rules, defense-guidance, kill-chain) have completed.

## Step 1: Verify Phase 2 Output Files

Check that all expected files were created by Phase 2 agents.

### Required Files (ALL tests)

| File | Created By | Purpose |
|------|-----------|---------|
| `README.md` | sectest-documentation agent | Overview + scoring |
| `<uuid>_info.md` | sectest-documentation agent | Detailed info card |
| `<uuid>_detections.kql` | sectest-detection-rules agent | KQL queries |
| `<uuid>_rules.yar` | sectest-detection-rules agent | YARA rules |
| `<uuid>_elastic_rules.ndjson` | sectest-detection-rules agent | Elastic EQL rules |
| `<uuid>_sigma_rules.yml` | sectest-detection-rules agent | Sigma rules |
| `<uuid>_dr_rules.yaml` | sectest-detection-rules agent | LimaCharlie D&R rules |
| `<uuid>_DEFENSE_GUIDANCE.md` | sectest-defense-guidance agent | Consolidated defense guide |

### Platform-Specific Files (based on test TARGET field)

Hardening scripts are only required for the test's target platform(s). Read the `TARGET:` field from the Go metadata to determine which scripts should exist.

| Platform Target | Required Script(s) |
|-----------------|-------------------|
| `windows-endpoint` | `<uuid>_hardening.ps1` |
| `linux-endpoint` | `<uuid>_hardening_linux.sh` |
| `macos-endpoint` | `<uuid>_hardening_macos.sh` |
| Multiple platforms | One script per target platform |
| Non-OS targets (`entra-id`, `cloud-aws`, etc.) | All 3 hardening scripts |

### Required Files (Multi-Stage Attack Tests Only)

Kill chain diagrams are required for multi-stage tests that simulate real attacks (`intel-driven/`, `mitre-top10/`). They are **NOT** generated for compliance/hygiene tests (`cyber-hygiene/`, subcategories `baseline`, `identity-tenant`, `identity-endpoint`).

| File | Created By | Purpose |
|------|-----------|---------|
| `kill_chain.html` | kill-chain-diagram-builder agent | Kill chain visualization (attack tests only) |

### Required Files (intel-driven and mitre-top10 tests only)

| File | Created By | Purpose |
|------|-----------|---------|
| `<uuid>_references.md` | sectest-documentation agent | Source provenance & references |

Not required for `cyber-hygiene/` tests (subcategories: `baseline`, `identity-tenant`, `identity-endpoint`) which derive from compliance frameworks rather than threat intelligence sources.

### Verification Procedure

```bash
cd tests_source/intel-driven/<uuid>/
ls -la *.kql *.yar *.ndjson *.yml *.yaml *.ps1 *.sh *.html *.md
```

If any files are missing, report which agent failed and which files are absent. Do NOT proceed without all required files.

## Step 2: Validate Score Consistency

Verify the score format is correct across both documentation files:

**README.md** must contain: `**Test Score**: **X.X/10**`
- Colon OUTSIDE bold markers: `**: **`
- Score value MUST be bold

**info.md** must contain: `## Test Score: X.X/10`
- Level 2 header
- Space after colon
- Same score value as README.md

Run validation if available:
```bash
./utils/validate-score-format.sh <uuid>
```

## Step 3: Validate Detection Rules Content

Quick sanity checks on detection rule files:

### Test Artifact Exclusion Check

Scan all 5 detection rule files for test framework artifacts that should NOT be present:

```bash
# These patterns should NOT appear in detection rules
grep -l 'c:\\F0' <uuid>_detections.kql <uuid>_rules.yar <uuid>_dr_rules.yaml <uuid>_sigma_rules.yml <uuid>_elastic_rules.ndjson 2>/dev/null
grep -l 'F0RT1KA' <uuid>_detections.kql <uuid>_rules.yar <uuid>_dr_rules.yaml <uuid>_sigma_rules.yml <uuid>_elastic_rules.ndjson 2>/dev/null
grep -l '/tmp/F0' <uuid>_detections.kql <uuid>_rules.yar <uuid>_dr_rules.yaml <uuid>_sigma_rules.yml <uuid>_elastic_rules.ndjson 2>/dev/null
```

If any matches are found, flag the file and request the agent to regenerate with proper technique-focused detections.

**Exception**: A single "F0RT1KA Test Attribution" rule in LimaCharlie D&R is acceptable if clearly labeled as test-framework-specific.

## Step 4: Elasticsearch Catalog Sync (MANDATORY)

Run the sync command:
```bash
source .venv/bin/activate && python3 utils/sync-test-catalog-to-elasticsearch.py
```

After sync completes, display this message:

> **Test catalog synced to Elasticsearch.**
>
> **IMPORTANT: You must re-execute the enrich policy in Kibana Dev Tools:**
> ```
> POST /_enrich/policy/f0rtika-test-enrichment/_execute
> ```
> This updates the enrichment index so future test results include the new metadata.

## Step 5: Endpoint Validation

**Endpoint deployment and execution is handled by the `sectest-deploy` skill in Phase 3b.**

The full deployment procedure (SSH connectivity check, remote directory cleanup, binary deployment, remote execution with output capture, exit code interpretation, log retrieval, and remote cleanup) has been moved to the dedicated `sectest-deploy` skill for reusability — the standalone `@sectest-deploy-test` agent also uses this logic.

**Quick manual reference** (for standalone validation outside the orchestrator):

| Platform | Deploy | Execute |
|----------|--------|---------|
| Windows | `scp build/<uuid>/<uuid>.exe win:'c:\F0\'` | `ssh win 'c:\F0\<uuid>.exe'` |
| Linux | `scp build/<uuid>/<uuid> debian:/opt/f0/` | `ssh debian 'chmod +x /opt/f0/<uuid> && /opt/f0/<uuid>'` |
| macOS | `scp build/<uuid>/<uuid> mac:/opt/f0/` | `ssh mac 'xattr -cr /opt/f0/<uuid> && /opt/f0/<uuid>'` |

## Step 6: Git Commit

After successful validation, commit all files:

```bash
cd tests_source/intel-driven/<uuid>/
git add -A .
git commit -m "feat: add <test-name> security test (<uuid>)

- <brief description of technique simulated>
- MITRE ATT&CK: <techniques>
- Severity: <severity>
- Architecture: <standard/multi-stage>
- Includes: KQL, YARA, Sigma, Elastic EQL, LC D&R detection rules
- Includes: Platform-appropriate hardening scripts
- Includes: Defense guidance and IR playbook"

git push
```

## Completion Summary

After all steps pass, provide the implementation summary:

1. **Test Overview**: Technique simulated
2. **Test Score**: X.X/10 with breakdown
3. **MITRE ATT&CK Mapping**: Techniques covered
4. **Architecture**: Standard or multi-stage
5. **Files Created**: Complete list
6. **Detection Rules**: 5 rule types generated (KQL, YARA, Sigma, Elastic EQL, LC D&R)
7. **Defense Guidance**: Hardening script(s) (target platform only) + IR playbook
8. **Kill Chain**: Diagram generated (multi-stage only)
9. **Build Instructions**: Commands to compile and sign
10. **Expected Results**: Exit code meanings
11. **ES Sync**: Status and enrich policy reminder

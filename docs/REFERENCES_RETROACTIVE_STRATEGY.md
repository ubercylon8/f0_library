# Retroactive References Population Strategy

## Context

The `<uuid>_references.md` artifact was introduced on 2026-03-14. Existing tests
created before this date do not have this file. This document outlines the approach
for retroactively adding references to high-value tests.

## Approach: Selective Retroactive Population

Rather than mass-generating references for all existing tests (which would produce
low-quality provenance data), we take a selective approach:

### Tier 1: Auto-generate from existing info.md References sections
Many intel-driven tests already have a `## References` section in their info.md.
A script can extract these and generate a structured `_references.md` file.

**Candidates**: Tests with existing `## References` or `## Threat Intelligence Sources` sections.

### Tier 2: Manual enrichment for high-value tests
For tests with high scores (8.0+) or critical severity, manually add proper source
provenance by researching the original threat intelligence.

### Tier 3: Leave as-is
Tests with low scores, informational severity, or cyber-hygiene category can remain
without references — they're typically based on MITRE ATT&CK documentation rather
than specific threat intelligence.

## Script: `utils/generate-retroactive-references.py`

TODO: Create a utility script that:
1. Scans all test directories for existing `## References` sections in info.md
2. Parses the references into structured format
3. Generates `<uuid>_references.md` with "Primary Source: Retroactively reconstructed"
4. Skips tests that already have `_references.md`

## Validation

After retroactive population:
- Run `./utils/validate-score-format.sh` to ensure no format regressions
- Run ES sync to update catalog
- Verify ProjectAchilles renders the new sections correctly

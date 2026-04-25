## Description

Please include a summary of the changes and which issue is fixed. Include relevant motivation and context.

Fixes # (issue)

## Type of change

Please delete options that are not relevant.

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] New test case

## MITRE ATT&CK Mapping

If this PR adds or modifies test cases, please list the relevant MITRE ATT&CK techniques:

- [ ] Technique ID: Description

## Checklist

- [ ] My code follows the style guidelines of this project (`gofmt`, `shellcheck`)
- [ ] I have performed a self-review of my code
- [ ] I have commented non-obvious sections (the *why*, not the *what*)
- [ ] I have made corresponding changes to documentation (README / `_info.md` / CLAUDE.md if applicable)
- [ ] My changes generate no new warnings in CI

### For new or modified security tests

- [ ] Test follows Schema v2.0 (`InitLogger(testID, testName, metadata, executionContext)`)
- [ ] `RubricVersion` is set explicitly (`v2.1` for new tests; legacy values preserved otherwise)
- [ ] Metadata header is complete (ID, NAME, TECHNIQUES, TACTICS, SEVERITY, TARGET, COMPLEXITY, THREAT_ACTOR, SUBCATEGORY, TAGS, AUTHOR)
- [ ] Score format matches both `README.md` (`**Test Score**: **X.X/10**`) and `<uuid>_info.md` (`## Test Score: X.X/10`)
- [ ] Test was lab-verified against an unprotected target (or unreachable stages documented per Lab-Bound Observability schema)
- [ ] Exit code is computed from actual results (never hardcoded; 126/101/105/999 only)

## Security Considerations

- [ ] This code is intended for authorized testing only
- [ ] Appropriate warnings included in documentation
- [ ] No sensitive information (credentials, tenant IDs, real user data) in logs, outputs, or commits
- [ ] All test artifacts drop to `LOG_DIR` or `ARTIFACT_DIR` per platform conventions and are cleaned up
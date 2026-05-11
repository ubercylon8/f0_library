# ScoreBreakdown Field Migration: v1 → v2.1 Sub-dimensions

**Status:** Complete — applied in commit `refactor(test_logger): rename ScoreBreakdown fields to v2.1 sub-dimensions across 46 copies`
**Date:** 2026-05-11
**Scope:** All 48 per-test `test_logger.go` copies + canonical template + all test `*.go` files that initialise `ScoreBreakdown{}`

---

## Motivation

The `ScoreBreakdown` Go struct carried v1 field names (`RealWorldAccuracy`, `TechnicalSophistication`, …) through two rubric activations without a rename:

- **Commit 237f2b1** (v2 activation, 2026-04-24): deferred the struct rename due to sweep scope.
- **Commit cc4361f** (v2.1 activation, 2026-04-25): re-deferred for the same reason. Noted explicitly in `docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md` §"Deferred (out of scope for v2.1 activation)".

This migration resolves that technical debt. The struct now reflects the eight v2.1 sub-dimensions and their JSON wire names align with the rubric documentation.

---

## Old → New Field Mapping

### Struct definition (`test_logger.go`)

| v1 Go field | v1 JSON key | → | v2.1 Go field | v2.1 JSON key | Budget | Rubric ref |
|---|---|---|---|---|---|---|
| `RealWorldAccuracy` | `realWorldAccuracy` | → | `APIFidelity` | `apiFidelity` | 0–2.5 | 2a |
| `TechnicalSophistication` | `technicalSophistication` | → | `IdentifierFidelity` | `identifierFidelity` | 0–1.5 | 2b |
| `SafetyMechanisms` | `safetyMechanisms` | → | `TelemetrySignalQuality` | `telemetrySignalQuality` | 0–2.0 | 2c |
| `DetectionOpportunities` | `detectionOpportunities` | → | `ExecutionContextFidelity` | `executionContextFidelity` | 0–1.0 | 2d |
| `LoggingObservability` | `loggingObservability` | → | `SchemaMetadata` | `schemaMetadata` | 0–1.0 | 3a |
| *(new)* | — | | `DocumentationCompleteness` | `documentationCompleteness` | 0–1.0 | 3b |
| *(new)* | — | | `LoggingPlumbing` | `loggingPlumbing` | 0–0.5 | 3c |
| *(new)* | — | | `OperationalHygiene` | `operationalHygiene` | 0–0.5 | 3d |

### Mapping rationale for legacy tests (compilation only — no re-scoring)

Legacy tests at `RubricVersion: "v1"` or `"v2"` were NOT re-scored. Their existing numeric values were preserved under the renamed fields using the closest semantic equivalents:

| Old field | Semantic role in v1/v2 | Mapped to v2.1 field | Rationale |
|---|---|---|---|
| `RealWorldAccuracy` | How accurately the test replicates real-world attacker APIs/behaviour | `APIFidelity` | Direct conceptual overlap: both measure API surface accuracy |
| `TechnicalSophistication` | Technical depth / complexity of techniques simulated | `IdentifierFidelity` | Best available fit: identifier fidelity captures how well artefact names/paths match real adversary tooling, which is the closest v2.1 concept to technique sophistication |
| `SafetyMechanisms` | Robustness of safety controls (no destructive ops, cleanup) | `TelemetrySignalQuality` | Structural placement match: both occupy the 0–2 budget slot; safety discipline correlates with test completeness which produces richer telemetry |
| `DetectionOpportunities` | Number of EDR detection hooks triggered | `ExecutionContextFidelity` | Both occupy the 0–1 budget slot; detection opportunity count is a proxy for how well the test exercises different execution contexts |
| `LoggingObservability` | Logging completeness / schema compliance | `SchemaMetadata` | Direct: v1 logging quality maps to v2.1 schema compliance (3a) |

The three new fields (`DocumentationCompleteness`, `LoggingPlumbing`, `OperationalHygiene`) default to `0.0` in all legacy tests. This does not affect the `Score` field (which is set independently and was not changed) and does not trigger re-scoring under any rubric version.

---

## Files Changed

### Struct definition (49 files)

- `sample_tests/multistage_template/test_logger.go` — canonical
- 10 × `tests_source/cyber-hygiene/<uuid>/test_logger.go`
- 28 × `tests_source/intel-driven/<uuid>/test_logger.go`
- 9 × `tests_source/mitre-top10/<uuid>/test_logger.go`

### Struct initialisation (36 files)

- `sample_tests/multistage_template/TEMPLATE-UUID.go`
- 8 × `tests_source/cyber-hygiene/<uuid>/<uuid>.go`
- 18 × `tests_source/intel-driven/<uuid>/<uuid>.go`
- 9 × `tests_source/mitre-top10/<uuid>/<uuid>.go`

---

## Consumer Migration Guide

This is a **hard wire-format cutover**. There is no backward-compatibility shim. Any consumer reading `scoreBreakdown.*` JSON fields must update field readers before ingesting results from tests built against this schema.

### ProjectAchilles (`~/F0RT1KA/ProjectAchilles/`)

PA has two parallel backends (`backend/` and `backend-serverless/`) — both must be updated identically to avoid silent field drops.

For **each** of `backend/` and `backend-serverless/`, apply the following:

1. **`src/services/browser/metadataExtractor.ts`** — Replace old field extractions:
   ```ts
   // Remove:
   realWorldAccuracy:       parseFloat(header.match(/realWorldAccuracy['":\s]+([\d.]+)/)?.[1] ?? '0'),
   technicalSophistication: parseFloat(header.match(/technicalSophistication['":\s]+([\d.]+)/)?.[1] ?? '0'),
   safetyMechanisms:        parseFloat(header.match(/safetyMechanisms['":\s]+([\d.]+)/)?.[1] ?? '0'),
   detectionOpportunities:  parseFloat(header.match(/detectionOpportunities['":\s]+([\d.]+)/)?.[1] ?? '0'),
   loggingObservability:    parseFloat(header.match(/loggingObservability['":\s]+([\d.]+)/)?.[1] ?? '0'),

   // Add:
   apiFidelity:              parseFloat(result.match(/"apiFidelity":\s*([\d.]+)/)?.[1] ?? '0'),
   identifierFidelity:       parseFloat(result.match(/"identifierFidelity":\s*([\d.]+)/)?.[1] ?? '0'),
   telemetrySignalQuality:   parseFloat(result.match(/"telemetrySignalQuality":\s*([\d.]+)/)?.[1] ?? '0'),
   executionContextFidelity: parseFloat(result.match(/"executionContextFidelity":\s*([\d.]+)/)?.[1] ?? '0'),
   schemaMetadata:           parseFloat(result.match(/"schemaMetadata":\s*([\d.]+)/)?.[1] ?? '0'),
   documentationCompleteness: parseFloat(result.match(/"documentationCompleteness":\s*([\d.]+)/)?.[1] ?? '0'),
   loggingPlumbing:          parseFloat(result.match(/"loggingPlumbing":\s*([\d.]+)/)?.[1] ?? '0'),
   operationalHygiene:       parseFloat(result.match(/"operationalHygiene":\s*([\d.]+)/)?.[1] ?? '0'),
   ```

2. **`src/types/test.ts`** — Replace in `TestMetadata` / `TestDetails` / `ScoreBreakdown` interface:
   ```ts
   // Remove:
   realWorldAccuracy?: number;
   technicalSophistication?: number;
   safetyMechanisms?: number;
   detectionOpportunities?: number;
   loggingObservability?: number;

   // Add:
   apiFidelity?: number;
   identifierFidelity?: number;
   telemetrySignalQuality?: number;
   executionContextFidelity?: number;
   schemaMetadata?: number;
   documentationCompleteness?: number;
   loggingPlumbing?: number;
   operationalHygiene?: number;
   ```

3. **`src/services/browser/testIndexer.ts`** — Wire new fields through the indexer pipeline (same rename pattern as types above).

4. **`src/services/agent/test-catalog.service.ts`** — Update catalog persistence/lookup to use new field names.

5. **`src/services/browser/__tests__/metadataExtractor.test.ts`** — Add extraction tests for each new field name; remove tests for old field names.

### Elasticsearch indices (`achilles-results-*`)

The `scoreBreakdown` object within stored documents will have new field names from tests built after this commit. Existing documents retain old field names — there is no backfill.

Kibana dashboards and saved searches that reference `scoreBreakdown.realWorldAccuracy`, `scoreBreakdown.technicalSophistication`, etc. must be updated to use the new field names.

For cross-version queries spanning both old and new results, use the `testMetadata.rubricVersion` field to branch:
```
testMetadata.rubricVersion: "v1" AND scoreBreakdown.realWorldAccuracy: >0
| UNION
testMetadata.rubricVersion: "v2.1" AND scoreBreakdown.apiFidelity: >0
```

---

## Backward Compatibility

**None.** This is a hard cutover. Tests built before this commit emit old JSON field names; tests built after emit new field names. The `Score` (top-level float) is unaffected and remains the primary numeric signal for dashboards that cannot be immediately updated.

Recommendation: ship this alongside or after PA backend updates.

---

## go vet Status

All `go vet ./...` invocations on changed tests produce only pre-existing errors:
- `pattern *.exe.gz: no matching files found` — embedded binaries not present in dev (expected)
- `pattern validator-*: no matching files found` — same
- `undefined: captureSystemInfo` / `undefined: LOG_DIR` — platform-specific logger file not co-located in test dir (pre-existing architecture)
- Missing `go.sum` entries — pre-existing dependency management gap

Zero NEW errors introduced by this change.

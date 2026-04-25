# PA Propagation Checklist — `rubricVersion` Field

**Date:** 2026-04-24
**Source change:** `feat(schema): add RubricVersion to TestMetadata` in `f0_library`
**Reason this is manual:** CLAUDE.md (lines 285–287) — *"PA lives in a separate repo with a different review cycle, so sectest-builder does NOT auto-update PA."*

---

## Scope of this propagation

The minimal precursor only adds the field to PA's TypeScript interfaces so the
catalog type can hold the value when it arrives. Static-doc parsing and UI
rendering are deferred until the v2 rubric is actually merged and tests start
declaring non-`"v1"` versions — at which point a follow-up PR can:

1. Add a `RUBRIC_VERSION:` regex to `metadataExtractor.ts`.
2. Add a `**Rubric**: vN` line to the info.md template.
3. Render a v1/v2 badge in the PA test-card UI.

---

## Files to modify

Two backend trees, identical edit in each:

1. `~/F0RT1KA/ProjectAchilles/backend/src/types/test.ts`
2. `~/F0RT1KA/ProjectAchilles/backend-serverless/src/types/test.ts`

## Apply the patch

From `~/F0RT1KA/ProjectAchilles/`:

```bash
cd ~/F0RT1KA/ProjectAchilles
git checkout -b add-rubric-version-field
git apply <<'PATCH'
diff --git a/backend/src/types/test.ts b/backend/src/types/test.ts
--- a/backend/src/types/test.ts
+++ b/backend/src/types/test.ts
@@ -22,6 +22,7 @@ export interface TestMetadata {
   author?: string;             // Test author
   unit?: string;               // Test unit identifier
   score?: number;
+  rubricVersion?: string;      // Scoring rubric: "v1" (co-equal 5-dim) | "v2" (tiered realism-first). Empty/undefined == "v1".
   scoreBreakdown?: ScoreBreakdown;
   isMultiStage: boolean;
   stages: StageInfo[];
diff --git a/backend-serverless/src/types/test.ts b/backend-serverless/src/types/test.ts
--- a/backend-serverless/src/types/test.ts
+++ b/backend-serverless/src/types/test.ts
@@ -15,6 +15,7 @@ export interface TestMetadata {
   author?: string;             // Test author
   unit?: string;               // Test unit identifier
   score?: number;
+  rubricVersion?: string;      // Scoring rubric: "v1" (co-equal 5-dim) | "v2" (tiered realism-first). Empty/undefined == "v1".
   scoreBreakdown?: ScoreBreakdown;
   isMultiStage: boolean;
   stages: StageInfo[];
PATCH
```

## Verify after apply

```bash
# Both should print 1 line each
grep -c "rubricVersion" backend/src/types/test.ts
grep -c "rubricVersion" backend-serverless/src/types/test.ts

# TypeScript type-check both backends
cd backend && npm run build
cd ../backend-serverless && npm run build
```

## Commit

```bash
git add backend/src/types/test.ts backend-serverless/src/types/test.ts
git commit -m "feat(types): add optional rubricVersion field to TestMetadata

Mirror the runtime field added to f0_library/sample_tests/multistage_template/test_logger.go
(see f0_library 2026-04-24 commit). Optional, defaults to undefined which is
treated as 'v1' by consumers.

No regex extractor or UI rendering yet — those land when the v2 rubric is
merged into f0_library/.claude/agents/sectest-documentation.md and tests
start declaring non-v1 versions."
```

---

## What's intentionally NOT in this patch

| Change | Why deferred |
|---|---|
| `metadataExtractor.ts` regex for `RUBRIC_VERSION:` | All existing tests are `v1`; no parse target exists in their headers yet. Add when v2 lands. |
| info.md template update | Same — wait for v2 rubric merge. |
| UI badge rendering | UI work comes after the data is being populated. |
| Backfill `rubricVersion: 'v1'` in PA's own DB | Empty/undefined is already semantically equivalent to `'v1'`. Backfilling is busy-work. |
| `TestDetails` interface change | `TestDetails extends TestMetadata`, so it inherits the new field automatically. No edit needed. |

---

## Failure mode if skipped

PA's TestMetadata interface won't have the property declared, so:
- `metadata.rubricVersion` reads as `any` (or fails strict type-check depending on tsconfig).
- The catalog will silently drop the value if it's ever read from JSON results.
- No runtime error, just missing data — which is exactly the failure mode CLAUDE.md warns about for any unpropagated schema change.

Apply this patch as part of the same review cycle as the f0_library change to
keep both repos in sync.

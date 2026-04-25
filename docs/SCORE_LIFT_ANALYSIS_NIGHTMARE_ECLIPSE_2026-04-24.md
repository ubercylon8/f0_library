# Score Lift Analysis — Nightmare-Eclipse Triad (2026-04-24)

## Scope

This note analyses the three most recent intel-driven tests committed on
2026-04-24 and proposes concrete lifts to their F0RT1KA Test Score. It also
proposes a **reframing of what the score should measure** — because the
current rubric rewards structural compliance more than behavioral fidelity,
and that misordering works against the purpose of these tests.

| Commit  | Test                                                               | UUID (short) | Techniques            | Score   |
|---------|--------------------------------------------------------------------|--------------|-----------------------|---------|
| 0ab4dba | BlueHammer — Early-Stage Behavioral Pattern (VSS-TOCTOU primitives) | `5e59dd6a…`  | T1211, T1562.001      | 9.0/10 |
| 36fd52a | RedSun — Cloud Files Rewrite Primitive Chain                        | `0d7e7571…`  | T1211, T1006, T1574   | 8.4/10 |
| 574bffa | UnDefend — Defender Signature/Engine Update DoS via File-Lock Race  | `6a2351ac…`  | T1562.001, T1083      | 8.7/10 |

All three: Windows-endpoint, severity `high`, complexity `medium`, threat
actor Nightmare-Eclipse, author `sectest-builder`.

---

## Current Rubric (from `.claude/agents/sectest-documentation.md:34-68`)

| Dimension                 | Max | "Full marks" looks like                                                    |
|---------------------------|-----|----------------------------------------------------------------------------|
| Real-World Accuracy       | 3   | Uses actual production APIs / registry paths / identifiers from the PoC   |
| Technical Sophistication  | 3   | Memory manipulation, cert bypass, kernel objects, multi-phase state       |
| Safety Mechanisms         | 2   | Watchdog + emergency recovery + auto-restoration                          |
| Detection Opportunities   | 1   | **5+ distinct detectable signals across phases**                          |
| Logging & Observability   | 1   | Full test_logger JSON + phase tracking + system snapshot                  |

---

## Per-Test Score Breakdown

| Test        | Acc  | Soph | Safe | Det  | Log  | Notes                                               |
|-------------|------|------|------|------|------|-----------------------------------------------------|
| BlueHammer  | ~2.5 | ~2.5 | 2.0  | 1.0  | 1.0  | No `### Score Breakdown` table in info.md           |
| RedSun      | 2.6  | 2.8  | 2.0  | 0.5  | 0.5  | Detection and logging under-credited                |
| UnDefend    | 2.8  | 2.7  | 2.0  | 0.6  | 0.6  | Same pattern, slightly better                       |

The pattern is consistent: **Detection Opportunities** and **Logging &
Observability** are the bottleneck for all three. Each dimension is capped
at 1.0, so a small number of targeted lifts can push every test above 9.5.

---

## Per-Test Lift Proposals

### BlueHammer (9.0 → ~9.6 target)

1. **Backfill scorecard** — add the missing `### Score Breakdown` table to
   `5e59dd6a-…_info.md`. The info.md jumps from `## Test Score: 9.0/10`
   straight into `## Purpose`; RedSun and UnDefend have the table.
2. **+Realism**: add a 4th observable primitive BlueHammer is known for —
   `SeBackupPrivilege` enable attempt (fails for standard user; the
   `AdjustTokenPrivileges` call is the signature telemetry) followed by
   `RegOpenKeyExW(HKLM\SAM\SAM, KEY_READ)` against a **sandbox copy** of a
   `.hiv` file under `ARTIFACT_DIR`. No real SAM touch; same sensor path.
3. **+Realism**: add `Win32_ShadowCopy.Create` via WMI COM (read-only
   query path) against a benign drive letter. Exercises VSS-abuse
   detections without creating actual shadows.
4. **+Detection**: name the EICAR drop target `Win32/Mimikatz.gen!test`
   so string-match sensors fire in addition to AMSI.

### RedSun (8.4 → ~9.4 target)

1. **+Logging**: add per-stage `bundle_results.json` fan-out (UnDefend
   has this and scored higher on logging for exactly this reason — see
   `docs/ARCHITECTURE.md` "Bundle Results Protocol"). Each stage becomes
   its own Elasticsearch document.
2. **+Logging**: enrich bundle events with Win32 API parameters —
   CLSID, reparse target, handle flags, `SHARE_MODE`. Currently
   pass/fail; should be telemetry-grade.
3. **+Detection**: add `CoCreateInstance` against a benign CLSID inside
   the Cloud Files namespace (with TieringEngineService.exe stopped, so
   it fails cleanly). Exercises the COM-broker log without privesc.
4. **+Detection**: after creating the mount-point reparse, read it back
   with `FSCTL_GET_REPARSE_POINT`. Sensors with reparse-create and
   reparse-enumerate rules both fire.
5. **+Realism**: match RedSun's PoC exactly by adding the
   `NtQueryInformationFile(FileStandardInformation)` probe the real PoC
   uses before racing.

### UnDefend (8.7 → ~9.6 target)

1. **+Detection**: the scorecard already says *"benign lock target may
   not trigger path-based rules."* Fix: under
   `ARTIFACT_DIR\Definition Updates\`, create a dummy file literally
   named `mpavbase.vdm` / `mpengine.dll`. String-match rules hit; no
   real Defender file is touched.
2. **+Realism**: read the real `ProductAppDataPath` registry value and
   build the lock-target filename from it at runtime. Currently static;
   mirrors UnDefend's actual discovery pattern.
3. **+Sophistication**: add the `FileDispositionInformation` +
   `DELETE_PENDING` race primitive against a sandbox file (it's in the
   UnDefend PoC; the test currently only implements the lock race).
4. **+Logging**: emit a user-mode ETW provider event
   (`EventWriteTransfer`) with the test's UUID at each stage boundary.
   SIEMs with ETW ingestion get a clean synthetic correlation signal.

---

## Cross-Cutting Lifts

Apply to all three tests. Higher ROI than per-test work because a single
implementation lands three score bumps.

1. **System-state snapshot** at start and end of `main()`: Defender
   status (WMI `MSFT_MpComputerStatus`), AV exclusion list, installed
   hotfixes. Write to
   `LOG_DIR/<uuid>_system_snapshot_{pre,post}.json`. This is what
   separates 0.6 → 1.0 on Logging.
2. **Watchdog goroutine** (30-second per-stage budget) that force-kills
   a hung stage and writes an `unexpected_hang` bundle. The rubric
   explicitly lists "watchdog process" as the 2.0 ceiling for Safety.
3. **Detection-opportunity audit** in each info.md: enumerate the ≥5
   distinct detection points with the exact KQL/YARA/Sigma rule IDs
   from this repo's own `*_detections.kql` and `*_sigma_rules.yml`.
   The rubric counts *signals a defender could realistically catch*,
   not *primitives exercised* — cross-referencing the repo's rules
   proves the count.
4. **Detection-rich lab re-run**: RedSun/UnDefend fired undetected in
   the 2026-04-24 lab run. The 2026-05-01 scheduled agent already
   targets quarantine-timing and SYSTEM-context prereqs; extend it to
   run against a VM with this repo's LimaCharlie D&R rules pre-deployed
   so the `Lab Result` column in the README fills with actual
   detections.

---

## Proposed Reframing — Quality as Ordered Priority

The current rubric dimensions are **co-equal weighted points**. In
practice this means a test can reach 9.0+ by being *structurally
complete* without being *behaviorally realistic* — and "structural
compliance" is the cheapest thing to satisfy. This inverts the purpose
of the library.

### Proposed ordering (highest to lowest priority)

1. **Safety (gate, not dimension)** — a test that violates
   `ARTIFACT_DIR` scoping, writes outside `LOG_DIR`, or leaves residual
   system state is **disqualified**, not low-scored. Safety is a
   prerequisite to even being scored, because an unsafe test in a
   customer environment is a liability regardless of how realistic it
   is.
2. **Emulation Realism** — how closely the observable primitives,
   API-call sequences, registry/handle/service identifiers, and
   artifact names match what the real adversary toolkit does. This is
   what makes the test valuable as a detection-validation instrument.
   If a defender's rule catches the test and misses the real threat,
   the test is not realistic enough. This should be the **dominant
   driver** of score, not one of five equal-weight dimensions.
3. **Structure** — schema v2.0 compliance, scorecard table, metadata
   header, reference provenance, bundle fan-out, score-format, build
   system, info.md completeness. Structure matters because it enables
   the PA catalog and ES enrichment pipelines to function — but it
   should be graded as **table-stakes**, not as a headline dimension.
   "All tests have their pieces" is a floor, not a ceiling.

### Mapping to the existing rubric

| Current dimension         | Proposed tier |
|---------------------------|---------------|
| Safety Mechanisms (2)     | **Tier 1 (gate)** — pass/fail. Watchdog / recovery / scoping. |
| Real-World Accuracy (3)   | **Tier 2 (realism)** — dominant weight.                       |
| Technical Sophistication (3) | **Tier 2 (realism)** — merge with accuracy; both are realism proxies. |
| Detection Opportunities (1) | **Tier 2 (realism)** — rule-triggering fidelity is realism.  |
| Logging & Observability (1) | **Tier 3 (structure)** — plumbing, not behavior.              |

A possible re-weighted formulation (non-binding):

```
score = safety_gate ? (realism_score * 0.7 + structure_score * 0.3) * 10 : 0

where:
  safety_gate ∈ {pass, fail}
  realism_score    ∈ [0, 1]  // accuracy + sophistication + detection fidelity
  structure_score  ∈ [0, 1]  // schema + logging + documentation + build
```

Under this model:
- An unsafe test cannot reach 9.0 by piling on logging.
- A test that triggers zero real detection rules cannot reach 9.0 by
  having a complete info.md.
- The structural lifts in the per-test sections above would still
  help, but they would be capped at ~3.0 points — pushing authors to
  prioritise realism work (the stage-4 primitives, the registry-driven
  runtime path construction, the file-name masking) over scorecard
  backfills.

### Implication for the Nightmare-Eclipse triad

Under the proposed ordering:
- **BlueHammer's missing scorecard is a structure issue** — worth
  fixing but not worth 0.3 of 10.
- **RedSun's COM-activation surface and UnDefend's DELETE_PENDING
  race are realism gaps** — these should drive the score up far more
  than bundle fan-out.
- **All three need the detection-rich lab re-run**, because realism
  is only provable by detection correlation in a representative
  sensor stack. A test that fires "in the lab with rules deployed" is
  realistic by demonstration, not just by inspection.

---

## Recommended Next Actions

1. Backfill BlueHammer's scorecard table (structure, 10 minutes).
2. Implement the three "name-as-Defender-file" sandbox lifts across
   all three tests (~200 LOC, +0.3–0.5 across the triad).
3. Add the 4th-stage realism primitives per test (BlueHammer
   SeBackupPrivilege + sandbox SAM; RedSun COM activation + reparse
   read-back; UnDefend DELETE_PENDING race).
4. Extend the 2026-05-01 scheduled agent to re-run all three against
   a LimaCharlie+Defender+Sysmon lab VM; update README `Lab Result`
   columns.
5. Open a follow-up proposal to revise `sectest-documentation`'s
   rubric along the tier model above, and update
   `F0RT1KA_SCORING_METHODOLOGY.md` to align the *defense* score and
   the *test-quality* score around the same "realism-first" axis.

---

**Author:** score-lift analysis session, 2026-04-24
**Tests analysed:** `5e59dd6a`, `0d7e7571`, `6a2351ac`
**Current triad average:** 8.70/10
**Target triad average (after lifts):** 9.50/10
**Priority reframe:** Safety (gate) → Realism (dominant) → Structure (floor)

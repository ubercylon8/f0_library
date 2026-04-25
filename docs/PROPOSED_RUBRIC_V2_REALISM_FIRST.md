# Proposed Rubric v2: Realism-First Quality Scoring

**Status:** Proposal — not yet merged into `.claude/agents/sectest-documentation.md`
**Parent analysis:** `docs/SCORE_LIFT_ANALYSIS_NIGHTMARE_ECLIPSE_2026-04-24.md`
**Author:** 2026-04-24

## Intent

Replace the current co-equal five-dimension rubric (Accuracy 3 + Sophistication
3 + Safety 2 + Detection 1 + Logging 1 = 10) with a **tiered model** where:

1. **Safety** is a pass/fail gate — not a dimension.
2. **Realism** (how faithfully the test emulates the real adversary) is the
   dominant scoring axis — 7 points.
3. **Structure** (schema compliance, docs, plumbing) is a floor — 3 points.

This prevents the current failure mode where a structurally complete but
behaviorally thin test can score 9.0+, while a realistic test with an
incomplete info.md scores 8.0.

---

## The Rubric

### Tier 1 — Safety Gate (pass / fail)

A test **cannot be scored** if any of the following is violated. Fix, then
score.

- [ ] All filesystem writes are confined to `LOG_DIR` (binaries/logs) or
      `ARTIFACT_DIR` (simulation artifacts). No writes to real system
      directories, user profiles, or registry hives outside the sandbox.
- [ ] No target outside the sandbox is held open with write, delete, lock,
      oplock, or reparse intent. Read-only enumeration of real system state
      is allowed (registry reads, service status, handle tables).
- [ ] All kernel objects (locks, oplocks, handles, transactions, mount
      points) are released in the same function that acquires them, within
      the stage's budget.
- [ ] No COM activation, service creation, driver load, or token/privilege
      manipulation against production targets. Privilege-enable *attempts*
      that the OS is expected to deny are allowed as telemetry.
- [ ] Cleanup function restores `ARTIFACT_DIR` to its pre-test state on
      every exit path, including panic and watchdog timeout.
- [ ] No network egress beyond loopback / `127.0.0.1`.
- [ ] Watchdog goroutine enforces a per-stage timeout and force-terminates
      hung stages with a logged `unexpected_hang` bundle.

**If any box is unchecked, the test is disqualified from scoring, not
penalised within the score.** Safety is not a dimension you trade against
realism — it is a prerequisite to being a F0RT1KA test.

---

### Tier 2 — Emulation Realism (0–7 points)

How faithfully the test reproduces the observable primitives of the real
adversary. This is the **dominant driver** of score.

#### 2a. API Fidelity (0–3 points)

Does the test call the same Win32 / NT / COM / POSIX APIs, in the same
order, with the same flags and parameters, that the real adversary toolkit
uses?

| Score | Criterion |
|-------|-----------|
| **3.0** | Exact API-call sequence mirrors the PoC. Handle flags, access masks, share modes, IOCTL codes, and CLSIDs match. Any deviation is explicitly documented with a safety justification. |
| **2.0** | Core API chain matches the PoC. Minor deviations on parameters (e.g., benign targets, reduced buffer sizes) but no simplification of the call graph. |
| **1.0** | Similar API family but different calls — e.g., uses `CreateFile` where PoC uses `NtCreateFile`, or high-level WMI where PoC uses direct COM activation. |
| **0**   | Abstracts the mechanism away entirely (e.g., shells out to `powershell.exe` instead of calling the native API). |

**Scoring evidence:** list in `info.md`, for each stage, the exact API the
PoC uses and the exact API the test calls. Deviations must be justified.

#### 2b. Identifier Fidelity (0–2 points)

Does the test use real target paths, registry keys, service names, CLSIDs,
file names (or the closest safe approximation)?

| Score | Criterion |
|-------|-----------|
| **2.0** | Real production identifiers extracted at runtime where possible (e.g., `RegQueryValueEx(HKLM\...Windows Defender, ProductAppDataPath)`). Sandbox artifacts are named to match real targets (`mpavbase.vdm`, `mpengine.dll`, `lsass.exe.copy`). |
| **1.0** | Identifiers hard-coded but accurate. Sandbox artifact names are generic. |
| **0**   | Identifiers are placeholders or do not reflect the real threat surface. |

#### 2c. Detection-Rule Firing Fidelity (0–2 points)

Of the detection rules this repo generates for this test
(`*_detections.kql`, `*_sigma_rules.yml`, `*_rules.yar`, `*_dr_rules.yaml`),
how many actually fire in a representative sensor stack?

| Score | Criterion |
|-------|-----------|
| **2.0** | ≥80% of generated rules fire in a lab VM with LimaCharlie + Defender + Sysmon. `Lab Result` column in README cross-references the firing rule IDs. |
| **1.5** | 50–79% fire. Gaps documented. |
| **1.0** | 20–49% fire. |
| **0.5** | 1–19% fire, or no lab run yet but rule-to-primitive mapping documented in info.md. |
| **0**   | No lab run, no documented mapping. |

**Scoring evidence:** README's "Detection Results" section lists every rule
from this repo and marks `fired` / `silent` / `not-applicable` with a lab
run ID.

---

### Tier 3 — Structure (0–3 points)

Schema compliance, documentation completeness, and telemetry plumbing.
Table-stakes for PA ingestion and ES enrichment — **floor, not ceiling**.

#### 3a. Schema & Metadata (0–1 point)

| Score | Criterion |
|-------|-----------|
| **1.0** | Schema v2.0 `InitLogger` with full `TestMetadata` + `ExecutionContext`. Metadata header present with all required fields. Org UUID (not short name) in `ExecutionContext.Organization`. Signed with F0RT1KA cert (and org cert for dual-sign deployments). |
| **0.5** | Schema v2.0 but missing one required field in metadata header, or using org short name instead of UUID. |
| **0**   | Pre-v2 logger, missing metadata header, or unsigned. |

#### 3b. Documentation Completeness (0–1 point)

| Score | Criterion |
|-------|-----------|
| **1.0** | README.md + `<uuid>_info.md` + `<uuid>_references.md` all present. info.md includes explicit `### Score Breakdown` table. Scorecard format validates with `utils/validate-score-format.sh`. MITRE mapping cites official technique + sub-technique IDs. |
| **0.5** | All files present but scorecard table missing or score format inconsistent between README and info.md. |
| **0**   | Missing references.md, info.md, or README. |

#### 3c. Logging & Telemetry Plumbing (0–1 point)

| Score | Criterion |
|-------|-----------|
| **1.0** | `test_logger.go` Schema v2.0 + per-stage `bundle_results.json` fan-out + `test_execution_log.json` + pre/post system snapshots (`<uuid>_system_snapshot_{pre,post}.json`) with Defender status, AV exclusions, hotfixes. |
| **0.5** | Schema v2.0 logger + bundle fan-out, but no system snapshots. |
| **0**   | No bundle fan-out, or logger missing entirely. |

---

## Final Score Formula

```
if any safety gate fails:
    score = "DISQUALIFIED - fix safety violations before scoring"
else:
    realism   = api_fidelity + identifier_fidelity + detection_firing   # 0–7
    structure = schema + docs + logging                                 # 0–3
    score     = realism + structure                                     # 0–10
```

### Score Ranges (unchanged from v1)

| Range | Rating |
|-------|--------|
| 9.0–10.0 | Exceptional |
| 8.0–8.9  | Advanced |
| 6.0–7.9  | Good |
| 4.0–5.9  | Basic |
| <4.0     | Below standard |

### Target for new tests

- **Realism ≥ 5.0 / 7.0** (i.e., full marks on API fidelity and identifier
  fidelity; at least partial lab-verified detection firing).
- **Structure ≥ 2.5 / 3.0** (i.e., schema v2.0 + complete docs; logging
  plumbing at least at bundle-fan-out level).
- **Total ≥ 7.5 / 10** for ship, **≥ 9.0 / 10** for "exceptional" label.

---

## Worked Examples: Nightmare-Eclipse Triad under v2

Re-scoring the three tests from `docs/SCORE_LIFT_ANALYSIS_...md` under v2,
**as they exist today**:

### BlueHammer (v1: 9.0 → v2: 7.8)

| Dimension | Score | Rationale |
|---|---|---|
| Safety gate | PASS | `ARTIFACT_DIR` scoping confirmed; oplock released in-stage. |
| API Fidelity | 2.5/3 | Cfapi + oplock + VSS enum chain matches PoC; transacted-open differs from PoC slightly. |
| Identifier Fidelity | 1.0/2 | EICAR target generic; no runtime identifier extraction. |
| Detection Firing | 0.5/2 | Only oplock IOCTL fired in lab; no lab rule-ID cross-reference. |
| Schema | 1.0/1 | Schema v2.0 complete. |
| Docs | 0.5/1 | **Scorecard table missing from info.md.** |
| Logging | 1.0/1 | Full logger + bundle fan-out. |
| **Total** | **7.8** | Drops from 9.0 because v2 punishes detection gap harder. |

Path to 9.0+: add runtime `RegQueryValueEx` for Defender paths (+0.7
identifier), name EICAR drop `Win32/Mimikatz.gen!test` and add sandbox
`mpavbase.vdm` target (+0.5 detection firing after lab re-run), backfill
scorecard table (+0.5 docs).

### RedSun (v1: 8.4 → v2: 7.1)

| Dimension | Score | Rationale |
|---|---|---|
| Safety gate | PASS | All reparse targets inside `ARTIFACT_DIR`; no COM activation. |
| API Fidelity | 2.5/3 | Core chain matches PoC; missing `NtQueryInformationFile` probe. |
| Identifier Fidelity | 0.8/2 | No runtime extraction; sandbox paths don't mimic real CF targets. |
| Detection Firing | 0.3/2 | Undetected in 2026-04-24 lab run; no rule-ID mapping documented. |
| Schema | 1.0/1 | Schema v2.0 complete. |
| Docs | 1.0/1 | Scorecard table present. |
| Logging | 0.5/1 | Schema v2 logger but **no bundle_results.json fan-out**. |
| **Total** | **7.1** | Detection firing is the primary drag. |

Path to 9.0+: add bundle fan-out (+0.5 logging), add
`CoCreateInstance`-to-benign-CLSID + reparse read-back (+0.5 API, +0.5
detection after lab re-run), sandbox-name-as-real-target (+0.5
identifier).

### UnDefend (v1: 8.7 → v2: 7.5)

| Dimension | Score | Rationale |
|---|---|---|
| Safety gate | PASS | Lock targets are sandbox-only; service subscription torn down. |
| API Fidelity | 2.7/3 | Full native API chain — registry + SCM + async I/O + locks. Missing `FileDispositionInformation` primitive. |
| Identifier Fidelity | 1.2/2 | Hard-coded Defender paths accurate but not runtime-extracted; benign lock-target name costs half the identifier mark. |
| Detection Firing | 0.6/2 | Undetected in lab; scorecard already flags the path-match issue. |
| Schema | 1.0/1 | Schema v2.0 complete. |
| Docs | 1.0/1 | Scorecard table present with detailed rationale column. |
| Logging | 1.0/1 | Full logger + per-stage bundles. |
| **Total** | **7.5** | |

Path to 9.0+: sandbox-file-named-as-real-Defender-artifact lifts detection
firing (+0.7), `FileDispositionInformation` race adds 4th primitive (+0.3
API), runtime `ProductAppDataPath` extraction (+0.5 identifier).

### What v2 reveals

All three tests drop ~1.0–1.3 points under v2. That drop is the **quality
debt the current rubric was hiding**: real detection firing is weaker than
the scores suggested. Lifts that target Tier 2 (realism) now move the
score much more than structural backfills do — which is the intended
redistribution.

---

## Migration Guidance for Existing Tests

- **No retroactive re-scoring** of the ~100 existing tests. Scores were
  assigned under v1 and re-scoring would invalidate trend lines in ES and
  PA dashboards.
- **Apply v2 to all new tests** built after the rubric is merged into
  `sectest-documentation.md`.
- **Apply v2 when re-scoring is explicitly triggered** — e.g., a test is
  revised, a lab re-run happens, or a user requests a quality audit.
- **Document the rubric version** in `TestMetadata.RubricVersion` so
  downstream consumers can differentiate "9.0 (v1)" from "9.0 (v2)".
  Suggested field addition in `test_logger.go`:
  ```go
  type TestMetadata struct {
      // ...existing fields
      RubricVersion string // "v1" (co-equal 5-dim) or "v2" (tiered realism-first)
  }
  ```

---

## Exact Drop-In Replacement for `sectest-documentation.md`

The text below is proposed as a replacement for lines 34–68 of
`.claude/agents/sectest-documentation.md`.

---

```markdown
## Scoring Guide (Rubric v2: Tiered, Realism-First)

Quality is scored in three tiers. Tier 1 is a gate; Tiers 2 and 3 are the
10-point score.

### Tier 1 — Safety Gate (pass / fail)

A test cannot be scored if any of these are violated. The orchestrator
must fix violations before requesting a score.

- All writes confined to `LOG_DIR` or `ARTIFACT_DIR`.
- No write / delete / lock / oplock / reparse intent on real system
  targets.
- All kernel objects released in-function within stage budget.
- No COM activation, service creation, driver load, or token
  manipulation against production targets.
- Cleanup restores `ARTIFACT_DIR` on every exit path.
- No network egress beyond loopback.
- Watchdog goroutine enforces per-stage timeout.

If any gate fails, return `"score": "DISQUALIFIED"` with the failing
gate(s) listed.

### Tier 2 — Emulation Realism (0–7 points) — Dominant Driver

**2a. API Fidelity (0–3)** — how closely the API call sequence matches
the real PoC:
- **3.0** = Exact API sequence, handle flags, IOCTL codes, CLSIDs match.
- **2.0** = Core chain matches; minor parameter deviations justified.
- **1.0** = Similar API family but different calls.
- **0**   = Mechanism abstracted away (e.g., shelled-out PowerShell).

**2b. Identifier Fidelity (0–2)** — how closely targets match reality:
- **2.0** = Runtime extraction of real identifiers; sandbox artifacts
  named after real targets.
- **1.0** = Hard-coded but accurate identifiers; generic sandbox names.
- **0**   = Placeholder identifiers.

**2c. Detection-Rule Firing Fidelity (0–2)** — of this repo's generated
rules, how many fire in a lab?
- **2.0** = ≥80% fire in LimaCharlie + Defender + Sysmon lab; README
  cross-references firing rule IDs.
- **1.5** = 50–79% fire.
- **1.0** = 20–49% fire.
- **0.5** = 1–19% fire, OR rule-to-primitive mapping documented pending
  lab run.
- **0**   = No lab run, no mapping.

### Tier 3 — Structure (0–3 points) — Floor

**3a. Schema & Metadata (0–1)** — Schema v2.0 `InitLogger`, metadata
header complete, org UUID in `ExecutionContext`, signed.

**3b. Documentation Completeness (0–1)** — README + info.md (with
explicit scorecard table) + references.md; score format validated.

**3c. Logging & Telemetry Plumbing (0–1)** — test_logger v2.0 +
per-stage `bundle_results.json` + pre/post system snapshots.

### Final Formula

```
if safety_gate_failed:
    score = "DISQUALIFIED"
else:
    score = api_fidelity + identifier_fidelity + detection_firing
          + schema + docs + logging          # 0–10
```

### Targets

- **Realism ≥ 5.0 / 7.0** and **Structure ≥ 2.5 / 3.0** for ship.
- **≥ 9.0** for the "exceptional" label.

### Score Ranges

- Basic: 4.0–5.9 | Good: 6.0–7.9 | Advanced: 8.0–8.9 | Exceptional: 9.0–10.0
```

---

## Open Questions (before merging)

1. **Lab run prerequisite for Detection Firing scores above 0.5.** If a
   test is written but has not yet been deployed to the lab, can it be
   scored at all? Proposal: allow up to **0.5** from rule-to-primitive
   mapping documentation alone, but cap Detection Firing at 0.5 until a
   real lab run produces firing evidence. Scores above 7.5 are
   therefore gated on lab runs — which aligns with "realism is only
   provable empirically."

2. **Multi-stage bonus.** v1 said "multi-stage tests typically +1.0–1.5
   points." v2 doesn't need an explicit bonus because multi-stage tests
   naturally earn more on API Fidelity (more primitives to match) and
   Detection Firing (more rules to exercise). Drop the bonus; let the
   rubric speak for itself.

3. **Rubric-version field.** Add `RubricVersion string` to
   `TestMetadata` so existing v1 scores remain interpretable. Default
   to `"v1"` for backward compatibility; new tests write `"v2"`.

4. **Merger with Defense Score.** `F0RT1KA_SCORING_METHODOLOGY.md`
   scores *defender performance*; this doc scores *test quality*. They
   share the realism axis (a realistic test generates realistic defense
   signals). A follow-up could merge both scores into a single
   2-dimensional rating `(test_quality, defense_performance)` — out of
   scope here.

5. **Alignment with `sectest-builder`'s score-estimate skill.**
   `.claude/skills/sectest-source-analysis.md` also uses "scoring
   rubric" language. Update to reference v2 when the rubric is merged.

---

## Recommended Merge Sequence

1. Land this doc in `docs/` for review (this commit).
2. Review + iterate on Tier 2 weights (is API Fidelity really 3.0 of 7?
   Should Detection Firing be 3.0 instead of 2.0?).
3. Add `RubricVersion` field to `test_logger.go` and backfill existing
   tests with `"v1"`.
4. Replace lines 34–68 of `.claude/agents/sectest-documentation.md`
   with the block in the "Exact Drop-In Replacement" section.
5. Update `.claude/skills/sectest-source-analysis.md` to cite v2.
6. Re-score the Nightmare-Eclipse triad under v2 as the first
   test-bed; apply the per-test lift proposals to push each to ≥ 9.0.
7. Update `F0RT1KA_SCORING_METHODOLOGY.md` with a cross-reference to
   the realism-first test rubric and a note on future merger.

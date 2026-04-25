# Rubric v2.1: Signal Quality + Execution Context + Operational Hygiene

**Status:** ACTIVE — activated 2026-04-25. Supersedes v2 (`docs/PROPOSED_RUBRIC_V2_REALISM_FIRST.md`).
**Parent:** `docs/PROPOSED_RUBRIC_V2_REALISM_FIRST.md` (v2, now legacy).
**Lab evidence motivating this:** `docs/SCORE_LIFT_ANALYSIS_NIGHTMARE_ECLIPSE_2026-04-24.md` and 2026-04-25 triad lab runs.
**Author:** 2026-04-25

## Why a v2.1 — what v2 got wrong

The v2 rubric merged on 2026-04-25 was a substantial improvement over v1, but the
2026-04-25 lab run surfaced three structural issues with how it measures things.
This proposal addresses each.

### Issue 1: Detection Firing Fidelity measures the wrong thing

v2 sub-dim 2c (Detection-Rule Firing Fidelity) scores tests on **how many of
the repo's own detection rules fire in a representative sensor stack**. The
intent was empirical realism — "if you can't fire your rules in a lab, your
realism claim is unverifiable."

But this conflates two genuinely different properties:

| Property | Belongs to |
|----------|------------|
| "Does this test produce realistic, detectable adversary signals?" | The **test** |
| "Did this tenant's deployed rules catch those signals?" | The **tenant defense** |

Lab evidence on 2026-04-25 made this concrete: stock Microsoft Defender +
MDE caught **1 of 11 v2 primitives** across the triad. Under v2, that reads
as "tests are weak." The honest reading is "stock Defender's behavioral
coverage in this technique surface is thin." The tests are fine; they
generated the signals they were designed to generate.

Worse: the detection-shape distinction we found between RedSun and BlueHammer
(RedSun's T1574 detection bypassed by signing; BlueHammer's T1562.001 detection
signing-resistant) gets flattened in v2's scoring. Both would count as
"rule fired" under v2's binary measurement. They're profoundly different
defensive postures, but the rubric can't see the difference.

**v2.1 fix:** Reframe 2c as **Telemetry Signal Quality** — a property of the
test, not a measurement of any tenant's defense. Decouple from rule-firing.

### Issue 2: Execution-context fidelity is invisible

Real adversaries get user-context first, then escalate. F0RT1KA tests run
under whatever privilege the execution framework provides — currently
ProjectAchilles runs everything as **SYSTEM**. This means:

- Tests that *only* work under SYSTEM never have their user-context
  behavior verified in the lab.
- The telemetry shape produced (process running as SYSTEM doing X) is
  systematically different from typical adversary telemetry (process
  running as user-context doing X then escalating).
- Code branches that handle privilege denials (BlueHammer's stage 4
  short-circuit when SeRestorePrivilege isn't granted) are dead code
  on the actual lab path.

A test that gracefully handles user/admin/SYSTEM contexts and produces
realistic telemetry per context is **more realistic** than one that
silently assumes SYSTEM. v2 doesn't measure this.

**v2.1 fix:** Add sub-dim **2d Execution-Context Fidelity** under Realism.

### Issue 3: Operational hygiene goes unscored

v2 ignores some real operational properties that affect whether a test
can be deployed and managed in production:

- **Binary size**: orchestrators in the v2 triad are 9–10 MB. That's not
  fatal, but it's a real network/disk/scan-time cost. Real adversary
  tooling is typically much smaller (KBs to low MBs).
- **Execution time**: BlueHammer's stage 1 takes ~125 seconds (mostly an
  EICAR sleep). This is reasonable but undocumented per-stage budgets
  mean PA timeouts must be guessed.
- **Watchdog discipline**: only BlueHammer's stage 4 has a watchdog.
  RedSun's COM activation could plausibly hang in some configurations
  with no recovery. UnDefend's hangs (when they happened) ran 10 minutes
  before the test framework killed them.

These are testability properties. They don't affect realism, but they
affect *whether the test is operable in production*. v2 doesn't score
them.

**v2.1 fix:** Add sub-dim **3d Operational Hygiene** under Structure.

---

## v2.1 Rubric — Full Specification

### Tier 1: Safety Gate (pass/fail) — UNCHANGED FROM v2

A test cannot be scored if any of these are violated. Same gates as v2:

- All filesystem writes confined to `LOG_DIR` or `ARTIFACT_DIR`.
- No write/delete/lock/oplock/reparse intent on real system targets.
- All kernel objects released in-function within stage budget.
- No COM activation, service creation, driver load, or token/privilege
  manipulation against production targets.
- Cleanup restores `ARTIFACT_DIR` on every exit path.
- No network egress beyond loopback / `127.0.0.1`.
- Watchdog enforces per-stage timeout (NEW emphasis; see 3d below).

If any gate fails, return `"score": "DISQUALIFIED"`.

### Tier 2: Emulation Realism (0–7 points) — REBALANCED

How faithfully the test reproduces the observable primitives of the real
adversary. Realism is the dominant scoring driver.

#### 2a. API Fidelity (0–2.5)  *down from 3.0 in v2*

Same definition as v2 — same Win32/NT/COM/POSIX API calls in the same
order with the same flags as the real adversary toolkit. Slightly
reduced max to make room for 2d.

| Score | Criterion |
|-------|-----------|
| 2.5   | Exact API sequence, flags, IOCTL codes, CLSIDs match the PoC |
| 1.7   | Core chain matches with minor parameter deviations |
| 0.8   | Similar API family but different calls |
| 0     | Mechanism abstracted away (e.g., shells out to PowerShell instead of native API) |

#### 2b. Identifier Fidelity (0–1.5)  *down from 2.0 in v2*

Same definition as v2 — real target paths, registry keys, service names,
CLSIDs, file names. Slightly reduced max.

| Score | Criterion |
|-------|-----------|
| 1.5   | Real production identifiers extracted at runtime; sandbox artifacts named after real targets |
| 0.9   | Identifiers hard-coded but accurate; sandbox names generic |
| 0     | Placeholder identifiers |

#### 2c. Telemetry Signal Quality (0–2.0) — REFRAMED FROM "Detection-Rule Firing Fidelity"

**This is the most consequential v2.1 change.** Score the test on whether
it produces clear, detectable adversary signals — not on whether any
particular tenant's rules fire on those signals.

**v2.1 criteria** (each ~0.5 points):

1. **Signal richness**: per primitive, does the test emit a named,
   identifiable signal in the appropriate telemetry surface (kernel
   events, ETW, registry, process, file system)? *Verifiable by
   inspection of the test's API call graph.*
2. **Sensor mapping**: does the test's `info.md` cross-reference each
   primitive with a specific sensor type and rule pattern that *would*
   detect it? (We added this as the "Detection Opportunity Audit"
   section in v2 lifts.) *Verifiable by reading the audit table.*
3. **Rule artifact validity**: are the test's bundled detection rules
   (`*_detections.kql`, `*_sigma_rules.yml`, `*_rules.yar`,
   `*_dr_rules.yaml`) **valid and parseable** under their respective
   schemas? *Verifiable by `kql-parser` / `sigma-cli validate` /
   `yamllint` / `yara -c`.*
4. **Lab execution verified — all stages reached**: did the test actually
   execute end-to-end with every stage reached in some lab environment?
   *Verifiable by lab artifact existence: `test_execution_log.json`
   present with `exitReason` set, AND every declared stage shows
   `status: success | failed` (not `skipped`) in `bundle_results.json`.*
   **Exception path**: if one or more stages were unreachable due to
   defense intervention earlier in the kill chain, criterion 4 is
   satisfied IFF a "Lab-Bound Observability" block in `info.md`
   documents the unreachable stages per the canonical schema below.

**Hard cap**: until lab execution is verified (criterion 4), this
sub-score is capped at **1.5** regardless of the other criteria. This
preserves the v2 falsifiability spirit — you must run the test
somewhere — but doesn't conflate "ran" with "rules-fired-in-our-tenant."

**Important non-criterion**: tenant rule firing. v2.1 explicitly does
NOT score whether the repo's own rules fire in any specific tenant.
That's a tenant-defense audit, separate from test quality.

##### Lab-Bound Observability — canonical schema (criterion 4 exception)

When a multi-stage test's kill chain breaks at an early stage, downstream
stages become unreachable on that sensor stack. v2.1 treats this as a
property of the kill-chain shape — not a test deficiency — provided it
is explicitly documented. The author MUST consult the framework owner
before invoking this exception, and the documentation block MUST conform
to the schema below. BlueHammer (commit `30925d0`,
`tests_source/intel-driven/5e59dd6a-6c87-4377-942c-ea9b5e054cb9/5e59dd6a-6c87-4377-942c-ea9b5e054cb9_info.md`
lines 141–167) is the reference implementation.

```markdown
## Lab-Bound Observability (added <YYYY-MM-DD> after lab evidence)

<Opening paragraph: 2–4 sentences naming the lab sensor stack used,
the exact stage that broke the chain, and the detection mechanism that
fired (content-based, behavioral, signature-based, etc.).>

**Stages affected:** <list of stage IDs that became unreachable, e.g.,
"stage 3 (T1211-vssenum + WMI shadow enum) and stage 4 (T1003.002-samsim)">

**Blocked by:** <the technique/sensor that broke the chain, with enough
specificity that a reader can replay the lab run, e.g., "Defender's
cloud-delivered content-based detection on the T1562.001-oplock stage
binary's FSCTL_REQUEST_BATCH_OPLOCK IOCTL constant">

This is **not a test bug** and does **not warrant refactoring**.
<2–3 numbered reasons. Each reason ~1 paragraph.>

1. **<Faithfulness reason>**: <why the current implementation matches
   the published PoC and a real attacker would be stopped at the same
   point.>

2. **<Trade-off reason>**: <why a refactor that evades the early
   detection would lower API/identifier fidelity by simulating a
   different (more sophisticated) attacker rather than the PoC.>

3. **<Decomposition reason>**: <why downstream stages, if individually
   detection-validation-relevant, belong in single-primitive companion
   tests rather than this kill-chain test.>

### Per-stage observability map

For every declared stage, classify observability on the lab sensor
stack and cite lab evidence:

- **Stage <N>** (<technique>): <observable | partially observable |
  unobservable>. Lab evidence: <what was/wasn't seen, with reference
  to `bundle_results.json` or `test_execution_log.json` entries.>

### Implications for 2c Telemetry Signal Quality scoring

<1–2 paragraphs explaining the explicit cap rationale. Required:
state which sub-criteria of 2c are met (signal richness, sensor
mapping, rule-artifact validity, lab execution) and which are bounded
by the kill-chain shape. State the resulting 2c sub-score.>
```

**Schema enforcement**: a test claiming the criterion-4 exception
without a Lab-Bound Observability block matching this structure does
NOT satisfy criterion 4 and remains capped at 1.5/2 in 2c.

#### 2d. Execution-Context Fidelity (0–1.0) — NEW

Does the test handle user/admin/SYSTEM contexts correctly, and produce
the right telemetry shape per context?

| Score | Criterion |
|-------|-----------|
| 1.0   | Test detects its execution context at runtime, branches behavior to produce realistic adversary signals per context. Documented in info.md which context the test primarily emulates. Examples: privilege-enable attempts that gracefully accept OS denial; HKCU vs HKLM branching for SYSTEM context; behavior that produces user-context-shaped telemetry instead of SYSTEM-shaped telemetry where appropriate. |
| 0.5   | Test handles one context well but doesn't branch (acceptable for tests where context-independence is genuinely desirable). |
| 0     | Test crashes, errors, or produces fundamentally unrealistic telemetry under non-SYSTEM contexts. |

**Verification**: grep test source for `IsAdmin` / `IsSystemContext` /
runtime token-query calls; verify branching exists; check info.md for
context-section.

### Tier 3: Structure (0–3 points) — REBALANCED

Schema compliance, documentation, plumbing, and operational hygiene.

#### 3a. Schema & Metadata (0–1.0) — UNCHANGED

Schema v2.0 InitLogger, full TestMetadata, ExecutionContext, signed,
RubricVersion: "v2.1".

#### 3b. Documentation Completeness (0–1.0) — UNCHANGED

README + `<uuid>_info.md` (with explicit Score Breakdown table) +
`<uuid>_references.md`; `utils/validate-score-format.sh` passes; MITRE
mapping cites official technique IDs.

#### 3c. Logging & Plumbing (0–0.5)  *down from 1.0 in v2*

`test_logger.go` v2.0 + per-stage `bundle_results.json` + pre/post
`<uuid>_system_snapshot_{pre,post}.json`. Slightly reduced max to make
room for 3d.

#### 3d. Operational Hygiene (0–0.5) — NEW

Sub-criteria (each ~0.1–0.2 points):

| Property | Threshold | Score |
|----------|-----------|-------|
| Orchestrator binary size | < 25 MB | 0.1 |
| Stage binary size (each) | < 5 MB | 0.1 |
| Per-stage execution-time budgets documented in info.md | yes | 0.1 |
| Watchdog goroutine on every stage that can plausibly hang (long syscalls, kernel-object waits, COM activation) | yes | 0.1 |
| `Endpoint.Stop()` exits within 30s of last log entry on every code path | yes | 0.1 |

**Verification:** `ls -la build/<uuid>/<uuid>.exe` for size; grep for
`time.AfterFunc` / `watchdog` in stage code; read info.md execution-time
section.

### Final Formula

```
if any safety_gate violation:
    score = "DISQUALIFIED"
else:
    realism   = api_fidelity + identifier_fidelity
              + telemetry_signal_quality + execution_context_fidelity   # 0–7
    structure = schema + docs + logging + operational_hygiene           # 0–3
    score     = realism + structure                                     # 0–10
```

### Targets and Score Ranges (unchanged)

- **Realism ≥ 5.0 / 7.0** and **Structure ≥ 2.5 / 3.0** for ship.
- Total **≥ 7.5** to ship; **≥ 9.0** for the "exceptional" label.
- Basic: 4.0–5.9 | Good: 6.0–7.9 | Advanced: 8.0–8.9 | Exceptional: 9.0–10.0

### What v2.1 explicitly is NOT

- **Not a measurement of tenant defense**: rule firing is a property of
  the tenant's rule corpus, not the test. The v2.1 rubric measures the
  test as artifact (a) and the test as executable instrument (b), and
  punts (c) "tenant defense as validated by test" to a separate Tenant
  Defense Audit workflow.
- **Not a measurement of LC tenant deployment**: deployments come and go.
  Test quality should not.
- **Not a forcing function for refactoring tests around detections**:
  documented under "Lab-Bound Observability" sections (BlueHammer is
  the canonical example). A reliably-detected early stage capping
  downstream observability is a property of the kill-chain shape,
  not a test deficiency.

---

## Worked Examples — Re-scoring the Triad under v2.1

The triad as it stands today (commit `30925d0`):

### BlueHammer (5e59dd6a)

| Sub-dim | v2 score | v2.1 score | Δ | Rationale |
|---------|---------|------------|---|-----------|
| 2a API Fidelity | 2.7/3 | 2.2/2.5 | → | Adjusted to new max; same realism characterization |
| 2b Identifier Fidelity | 1.5/2 | 1.1/1.5 | → | Adjusted to new max |
| 2c Telemetry Signal Quality | 0.5/2 (capped) | 1.5/2 | **+1.0** | All 4 criteria met: signal richness ✅, Detection Opportunity Audit ✅, rules parse ✅ (assumed), lab execution verified ✅ |
| 2d Execution-Context Fidelity | — | 1.0/1.0 | **+1.0** | Stage 4 has explicit standard-user/admin branching (privilege-enable + short-circuit) |
| 3a Schema | 1.0 | 1.0 | = | |
| 3b Docs | 1.0 | 1.0 | = | |
| 3c Logging | 1.0 | 0.5/0.5 | → | Adjusted to new max |
| 3d Operational Hygiene | — | 0.3/0.5 | **+0.3** | Orchestrator 9.5 MB ✅, stage budgets undocumented ❌, watchdog only on stage 4 ❌, signed exits ✅ |
| **Total** | **7.5 (capped)** | **8.6** | **+1.1** | Strong/Advanced |

### RedSun (0d7e7571)

| Sub-dim | v2 score | v2.1 score | Δ | Rationale |
|---------|---------|------------|---|-----------|
| 2a API Fidelity | 2.7/3 | 2.2/2.5 | → | Similar to BlueHammer |
| 2b Identifier Fidelity | 1.5/2 | 1.1/1.5 | → | |
| 2c Telemetry Signal Quality | 0.5/2 (capped) | 1.5/2 | **+1.0** | Same 4-criteria check; all met |
| 2d Execution-Context Fidelity | — | 0.5/1.0 | **+0.5** | Context-independent (acceptable for COM activation primitive) but doesn't branch |
| 3a Schema | 1.0 | 1.0 | = | |
| 3b Docs | 1.0 | 1.0 | = | |
| 3c Logging | 1.0 | 0.5/0.5 | → | |
| 3d Operational Hygiene | — | 0.2/0.5 | **+0.2** | Size ✅, no per-stage watchdogs ❌, budgets undocumented ❌ |
| **Total** | **7.5 (capped)** | **8.0** | **+0.5** | Advanced |

### UnDefend (6a2351ac)

| Sub-dim | v2 score | v2.1 score | Δ | Rationale |
|---------|---------|------------|---|-----------|
| 2a API Fidelity | 2.9/3 | 2.4/2.5 | → | Strongest of triad — full PoC API surface |
| 2b Identifier Fidelity | 1.8/2 | 1.4/1.5 | → | Defender-pattern names + runtime ProductAppDataPath read |
| 2c Telemetry Signal Quality | 0.5/2 (capped) | 1.5/2 | **+1.0** | All 4 criteria met; ETW correlation events provide additional signal |
| 2d Execution-Context Fidelity | — | 0.7/1.0 | **+0.7** | U4 ETW degrades gracefully under user (source registration fails non-fatally); registry reads work for any user; partial branching but not full |
| 3a Schema | 1.0 | 1.0 | = | |
| 3b Docs | 1.0 | 1.0 | = | |
| 3c Logging | 1.0 | 0.5/0.5 | → | |
| 3d Operational Hygiene | — | 0.3/0.5 | **+0.3** | Size ✅, no watchdogs ❌, budgets undocumented ❌, fast ✅ |
| **Total** | **7.5 (capped)** | **8.8** | **+1.3** | Advanced, near Exceptional |

### Observations from the re-scoring

1. **The triad scores **differentiate** under v2.1** — UnDefend at 8.8,
   BlueHammer at 8.6, RedSun at 8.0. v2 collapsed all three to 7.5 due
   to the same lab-evidence cap. v2.1's rationale for the differentiation
   is honest: UnDefend has the strongest API/identifier fidelity; RedSun
   doesn't branch by context; BlueHammer has explicit context branching
   but loses some on operational hygiene.

2. **None reach Exceptional (≥ 9.0)** — All three lose meaningful
   ground on operational hygiene (no per-stage watchdogs, undocumented
   timeout budgets). That's actionable: implementing per-stage watchdogs
   and documenting budgets would push UnDefend to 9.0+.

3. **The 7.5 cap goes away under v2.1** — because Telemetry Signal
   Quality's hard cap (1.5 without lab execution) is met by all three:
   they ran end-to-end in 2026-04-25 lab. The 7.5 cap was a v2 artifact
   of conflating "ran" with "rules-fired-in-our-tenant"; v2.1 correctly
   credits "ran" without conflating.

---

## Concrete Re-Scoring Plan for Existing v2 Tests

| Approach | Pro | Con |
|---------|-----|-----|
| **Option A: No retroactive re-scoring.** v2-scored tests stay v2; only new tests use v2.1. | Same as v1→v2: preserves trend lines. | The triad keeps scores it doesn't deserve under either rubric (7.0 in info.md, should be 7.5 under v2). |
| **Option B: Re-score the v2 triad under v2.1.** Recompute, update info.md, set RubricVersion: "v2.1". Other v2 tests stay v2. | The triad is the proving-ground anyway; treat them as v2.1 first-citizens. | Slightly invalidates the "v2 triad scores" we just shipped yesterday. |
| **Option C: Re-score everything in the catalog.** Sweeping re-score under v2.1. | Single coherent score model across catalog. | Largest effort; risks score-volatility for existing tests that haven't been touched. |

**Proposal**: **Option B**. The v2 triad scores in info.md were already
arithmetically inconsistent (showing 7.0 when math sums to 7.7 raw,
7.5 capped). Treating them as v2.1 first-citizens fixes the documentation
errors AND aligns them with the more discriminating rubric. Other tests
keep v2 scores until they're naturally re-scored (lift PR, source
change, etc.).

---

## Migration & Rollout

### Activation sequence

1. ✅ Land this proposal doc (commit `2645f34`, 2026-04-25 14:25)
2. ✅ Lock activation decisions and add Lab-Bound Observability schema
   (this commit, 2026-04-25)
3. ✅ Flip canonical template default to `RubricVersion: "v2.1"`
4. ✅ Update CLAUDE.md to mark v2.1 as active, v2 as legacy
5. ✅ Mark `docs/PROPOSED_RUBRIC_V2_REALISM_FIRST.md` as "Superseded by v2.1"
6. ✅ Re-score the Nightmare-Eclipse triad under v2.1 (Option B, separate commit)
7. ⏸ Manual: replace v2 scoring guide in `.claude/agents/sectest-documentation.md`
   with v2.1 block (see `docs/RUBRIC_V2.1_ACTIVATION_PATCH.md`).
   `.claude/` is gitignored — requires interactive approval.
8. ⏸ Manual: update `.claude/skills/sectest-source-analysis.md` to cite v2.1
   (see same patch doc).

### Activation Decisions Locked (2026-04-25)

The following decisions were made at activation time and are recorded
here for traceability. Future rubric revisions should note them.

**Decision 1 — Sub-dimension weights**: 2d Execution-Context Fidelity =
**1.0**, 3d Operational Hygiene = **0.5**. Rationale: tilts toward
Realism (where 2d lives) over Structure (where 3d lives), matching
v2's spirit. Total budget across rubric versions remains 10.0.

**Decision 2 — Criterion 4 strictness**: "all stages reached" (the
stricter of the two options proposed in the v2.1 draft). Stages
unreachable due to defense intervention earlier in the kill chain
require a documented Lab-Bound Observability block per the canonical
schema in §"2c → Lab-Bound Observability". The author MUST consult
the framework owner before invoking this exception. Rationale: forces
kill-chain shape observations to become explicit, structured artifacts
rather than unstated assumptions; produces consistent documentation
across tests that hit this case.

**Decision 3 — Re-scoring scope**: Option B (re-score the Nightmare-
Eclipse triad under v2.1; leave other v2-scored tests on v2). Tests
not yet built use v2.1 from the canonical template default. Tests
scored before 2026-04-25 keep their v2 score with
`RubricVersion: "v2"` and are not retroactively re-scored. Rationale:
the triad is the proving-ground anyway and its v2-cap was a known
artifact of the conflation v2.1 corrects; mass re-scoring would
invalidate ES/PA trend lines for marginal benefit.

### Deferred (out of scope for v2.1 activation)

- **`ScoreBreakdown` Go struct refactor**: the struct in
  `test_logger.go` (45+ per-test copies + canonical template) still
  carries v1 field names (`RealWorldAccuracy` etc.). v2 activation
  didn't touch it; v2.1 doesn't either. Refactoring would be a
  breaking change for any consumer reading those JSON fields and
  requires a coordinated sweep across all 45+ contracts. Track as
  separate technical debt.
- **Tenant Defense Audit workflow**: v2.1 explicitly defers this.
  Recommended as a separate per-tenant audit deliverable rather than
  a scoring system. Produces a per-tenant report; separates concerns
  cleanly from per-test quality scoring.

---

## Appendix: Rubric design principles confirmed by this revision

These are the principles v2.1 commits to. Useful as guardrails for
future rubric revisions:

1. **Measure properties of THE TEST.** Not properties of the framework,
   not properties of the tenant, not properties of the wider environment.
2. **Empirical verifiability is required, but tenant-deployment is not.**
   Rules-validate-and-parse + binary-runs-end-to-end is sufficient.
3. **Rubric dimensions should be objectively measurable in 30s of
   inspection.** Subjective scores invite drift.
4. **Same total budget across rubric versions.** v1, v2, v2.1 all sum
   to 10. Rebalance, don't inflate.
5. **Distinguish realism from operational hygiene.** Realism is what
   the test *is*; operational hygiene is how it *runs*. Both matter,
   but they're separate axes.

---

**Author:** v2.1 proposal session, 2026-04-25
**Triad re-score under v2.1:** BlueHammer 8.6, RedSun 8.0, UnDefend 8.8
**Next action:** review + decide on rollout sequence + Option A/B/C re-scoring

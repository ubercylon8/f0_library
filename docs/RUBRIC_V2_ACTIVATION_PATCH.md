# Rubric v2 Activation Patch — Manual Apply Required

**Status:** Pending manual application as of 2026-04-25.
**Reason this is manual:** Claude Code auto-mode refuses edits to files under
`.claude/` (agent and skill prompts) because they directly affect agent
behavior — interactive approval is required and auto-mode cannot grant it.

The other half of the activation slice (template flip, CLAUDE.md, proposal doc
status) has already been committed. Applying the two patches below completes
the rubric switch — after that, every new test scored by `sectest-builder` /
`sectest-documentation` is graded under v2.

---

## Patch 1 — `.claude/agents/sectest-documentation.md`

**Replace the entire `## Scoring Guide (0-10 Scale)` section (lines 34–68 in
the file as of commit `9c54f01`) with the v2 block below.** The replacement is
self-contained — it includes the safety gate, the realism + structure scoring
bands, the final formula, the targets, and a v1-legacy reference appendix.

### Find this block

```markdown
## Scoring Guide (0-10 Scale)

Score every test using these criteria:

### 1. Real-World Accuracy (0-3 points)
- **3.0** = Uses actual production endpoints/APIs, extracts real identifiers
- **2.0** = Simulates realistic patterns based on threat research, uses local system data
- **1.0** = General simulation without real system interaction
- **0** = Basic file drop only

### 2. Technical Sophistication (0-3 points)
- **3.0** = Memory manipulation, cert bypass, network protocols, multi-phase with complex state
- **2.0** = Registry/file manipulation, process injection, multi-stage with dependencies
- **1.0** = Simple file operations, basic process execution
- **0** = File drop only

### 3. Safety Mechanisms (0-2 points)
- **2.0** = Watchdog process, emergency recovery, auto-restoration, multiple safety modes
- **1.0** = Manual recovery documented, cleanup functions
- **0** = No safety mechanisms

### 4. Detection Opportunities (0-1 point)
- **1.0** = 5+ distinct detection points across phases
- **0.5** = 2-4 detection points
- **0** = Single or unclear detection points

### 5. Logging & Observability (0-1 point)
- **1.0** = Full test_logger with JSON/text, phase tracking, system info
- **0.5** = Console output with timestamps
- **0** = Basic console output only

**Target: 7.0+ for all new tests. Multi-stage tests typically +1.0-1.5 points.**

### Score Ranges
- Basic: 4.0-5.0 | Good: 6.0-7.5 | Advanced: 8.0-8.9 | Exceptional: 9.0-10.0
```

### Replace with this block

```markdown
## Scoring Guide (Rubric v2: Tiered, Realism-First)

Quality is scored in three tiers. Tier 1 is a gate; Tiers 2 and 3 form the 10-point score. **Set `RubricVersion: "v2"`** in the test's `TestMetadata` literal whenever you score under this rubric. Background and worked examples: `docs/PROPOSED_RUBRIC_V2_REALISM_FIRST.md`.

### Tier 1 — Safety Gate (pass / fail)

A test **cannot be scored** if any of these are violated. Fix violations, then score. Safety is a prerequisite to being a F0RT1KA test, not a dimension you trade against realism.

- All filesystem writes confined to `LOG_DIR` or `ARTIFACT_DIR`.
- No write/delete/lock/oplock/reparse intent on real system targets. Read-only enumeration of real system state is allowed.
- All kernel objects released in the same function that acquires them, within the stage's budget.
- No COM activation, service creation, driver load, or token/privilege manipulation against production targets. Privilege-enable *attempts* the OS is expected to deny are allowed as telemetry.
- Cleanup function restores `ARTIFACT_DIR` on every exit path, including panic and watchdog timeout.
- No network egress beyond loopback / `127.0.0.1`.
- Watchdog goroutine enforces a per-stage timeout and force-terminates hung stages with a logged `unexpected_hang` bundle.

If any gate fails, return `"score": "DISQUALIFIED"` with the failing gate(s) listed and stop the orchestrator from publishing the test.

### Tier 2 — Emulation Realism (0–7 points) — Dominant Driver

How faithfully the test reproduces the observable primitives of the real adversary. Realism, not structure, is what makes a test valuable as a detection-validation instrument.

**2a. API Fidelity (0–3)** — Same Win32/NT/COM/POSIX API calls, in the same order, with the same flags as the real adversary toolkit. **3.0** = exact API sequence (handle flags, IOCTL codes, CLSIDs match); **2.0** = core chain matches with minor parameter deviations; **1.0** = similar API family but different calls; **0** = mechanism abstracted away (e.g., shells out to `powershell.exe`). Evidence: `info.md` lists, per stage, the PoC API and the test API; deviations justified.

**2b. Identifier Fidelity (0–2)** — Real target paths, registry keys, service names, CLSIDs, file names. **2.0** = real production identifiers extracted at runtime where possible; sandbox artifacts named after real targets (e.g., `mpavbase.vdm`, `lsass.exe.copy`). **1.0** = identifiers hard-coded but accurate; sandbox names generic. **0** = placeholder identifiers.

**2c. Detection-Rule Firing Fidelity (0–2)** — Of the detection rules this repo generates for the test (`*_detections.kql`, `*_sigma_rules.yml`, `*_rules.yar`, `*_dr_rules.yaml`), how many actually fire in a LimaCharlie + Defender + Sysmon lab VM? **2.0** = ≥80% fire (README cross-references firing rule IDs); **1.5** = 50–79%; **1.0** = 20–49%; **0.5** = 1–19% OR rule-to-primitive mapping documented pending lab run; **0** = no lab run, no mapping.

**Hard cap until lab data lands:** without a real lab run, this sub-score is capped at **0.5** regardless of documentation completeness. A test cannot exceed **7.5 total** without lab evidence. Realism is provable empirically, not by inspection. This is a forcing function — tests are drafted, deployed, lab-verified, then finalized.

### Tier 3 — Structure (0–3 points) — Floor

Schema compliance, documentation completeness, telemetry plumbing. Table-stakes for ProjectAchilles ingestion — floor, not ceiling.

**3a. Schema & Metadata (0–1)** — **1.0** = Schema v2.0 `InitLogger` with full `TestMetadata` (incl. `RubricVersion: "v2"`) + `ExecutionContext` (org UUID, not short name); metadata header complete; signed. **0.5** = v2.0 but one required field missing or org short-name used. **0** = pre-v2 logger or unsigned.

**3b. Documentation Completeness (0–1)** — **1.0** = README + `<uuid>_info.md` (with `### Score Breakdown` table) + `<uuid>_references.md`; scores validate with `utils/validate-score-format.sh`; MITRE mapping cites official technique + sub-technique IDs. **0.5** = files present but scorecard missing or score format inconsistent. **0** = missing required doc.

**3c. Logging & Telemetry Plumbing (0–1)** — **1.0** = `test_logger.go` v2.0 + per-stage `bundle_results.json` fan-out + `test_execution_log.json` + pre/post `<uuid>_system_snapshot_{pre,post}.json` (Defender status, AV exclusions, hotfixes). **0.5** = logger + bundle fan-out, no system snapshots. **0** = no bundle fan-out.

### Final Formula

\`\`\`
if any safety_gate violation:
    score = "DISQUALIFIED"
else:
    realism   = api_fidelity + identifier_fidelity + detection_firing  # 0–7
    structure = schema + docs + logging                                # 0–3
    score     = realism + structure                                    # 0–10
\`\`\`

### Targets and Score Ranges

- **Realism ≥ 5.0 / 7.0** and **Structure ≥ 2.5 / 3.0** for ship. Total **≥ 7.5** to ship; **≥ 9.0** for the "exceptional" label.
- Basic: 4.0–5.9 | Good: 6.0–7.9 | Advanced: 8.0–8.9 | Exceptional: 9.0–10.0

**No multi-stage bonus.** v1 added +1.0–1.5 for multi-stage tests as a structural credit. v2 removes this — multi-stage tests naturally earn more on API Fidelity (more primitives) and Detection Firing (more rules). Realism rewards directly.

**Re-scoring policy.** Existing v1-scored tests are not retroactively re-scored under v2 — that would invalidate ES/PA trend lines. They keep their v1 score with `RubricVersion: "v1"`. Apply v2 to all *new* tests and to any test whose source code is materially changed (a "lift PR" is a re-score event; a docs-only PR is not).

### Rubric v1 (legacy — do not use for new tests)

Preserved for reference because tests scored before 2026-04-25 carry `RubricVersion: "v1"`: Real-World Accuracy (0-3) + Technical Sophistication (0-3) + Safety Mechanisms (0-2) + Detection Opportunities (0-1) + Logging & Observability (0-1) = 10. Co-equal weighted dimensions with no safety gate, no realism axis, no lab-firing requirement. Multi-stage tests received a +1.0–1.5 bonus.
```

---

## Patch 2 — `.claude/skills/sectest-source-analysis.md`

**Single-line edit** at line 58:

### Find

```markdown
- **Score estimate** (0-10, using the scoring rubric)
```

### Replace with

```markdown
- **Score estimate** (0-10, using rubric **v2** — see `.claude/agents/sectest-documentation.md`. Estimate Realism (0-7) + Structure (0-3) and confirm Safety gate would pass. **Cap pre-lab estimates at 7.5** since Detection-Rule Firing Fidelity is capped at 0.5 without lab evidence.)
```

---

## Verify after applying

```bash
# Both should print non-empty results
grep -c "RubricVersion" .claude/agents/sectest-documentation.md   # expect 4+
grep -c "Tier 1\|Tier 2\|Tier 3" .claude/agents/sectest-documentation.md   # expect 3+
grep -c "rubric.*v2" .claude/skills/sectest-source-analysis.md   # expect 1
```

## Commit suggestion

```
feat(rubric): activate v2 realism-first scoring in agent + skill prompts

Replaces the v1 co-equal 5-dimension scoring rubric in
sectest-documentation.md with the tiered v2 model: safety pass/fail gate
+ realism (0-7) + structure (0-3). Updates sectest-source-analysis.md to
match.

Companion to commit eb9d9d5 (RubricVersion field) and the 2026-04-25
template flip — once these two prompt files land, the activation is
complete and all new tests built by sectest-builder are scored under v2.

Existing v1-scored tests are not retroactively re-scored.
```

---

## Why this is split out from the main commit

Auto-mode in Claude Code refuses any edit to `.claude/agents/` or
`.claude/skills/` because changes there directly affect agent behavior —
the only safe path is interactive approval. So the rest of the
activation slice (template flip, CLAUDE.md, proposal-doc status) lands
in the main commit, and these two prompt edits are the manual residual.

After applying these two patches and committing them, the v2 rubric is
fully active.

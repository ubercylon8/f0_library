# Rubric v2.1 Activation Patch — Manual Apply Required

**Status:** Pending manual application as of 2026-04-25.
**Reason this is manual:** Claude Code auto-mode refuses edits to files under
`.claude/` (agent and skill prompts) because they directly affect agent
behavior — interactive approval is required and auto-mode cannot grant it.

The other half of the activation slice (template flip, CLAUDE.md, v2.1 doc
status, v2 doc supersession) has already been committed. Applying the two
patches below completes the rubric switch — after that, every new test
scored by `sectest-builder` / `sectest-documentation` is graded under v2.1.

---

## Patch 1 — `.claude/agents/sectest-documentation.md`

**Replace the entire `## Scoring Guide (Rubric v2: ...)` section
(applied via the previous `RUBRIC_V2_ACTIVATION_PATCH.md` patch) with the
v2.1 block below.** The replacement is self-contained — it includes the
safety gate, the realism + structure scoring bands with v2.1's new
sub-dimensions, the final formula, the targets, and a v1/v2-legacy
reference appendix.

### Find this block (the v2 scoring guide currently in place)

```markdown
## Scoring Guide (Rubric v2: Tiered, Realism-First)
... (entire block from line 65 through line 128 of the v2 patch)
```

### Replace with this block

```markdown
## Scoring Guide (Rubric v2.1: Signal Quality + Execution Context + Operational Hygiene)

Quality is scored in three tiers. Tier 1 is a gate; Tiers 2 and 3 form the 10-point score. **Set `RubricVersion: "v2.1"`** in the test's `TestMetadata` literal whenever you score under this rubric. Background and worked examples: `docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`.

### Tier 1 — Safety Gate (pass / fail) — UNCHANGED FROM v2

A test **cannot be scored** if any of these are violated. Fix violations, then score.

- All filesystem writes confined to `LOG_DIR` or `ARTIFACT_DIR`.
- No write/delete/lock/oplock/reparse intent on real system targets. Read-only enumeration is allowed.
- All kernel objects released in the same function that acquires them, within stage budget.
- No COM activation, service creation, driver load, or token/privilege manipulation against production targets. Privilege-enable *attempts* the OS is expected to deny are allowed as telemetry.
- Cleanup function restores `ARTIFACT_DIR` on every exit path, including panic and watchdog timeout.
- No network egress beyond loopback / `127.0.0.1`.
- Watchdog goroutine enforces a per-stage timeout and force-terminates hung stages with a logged `unexpected_hang` bundle.

If any gate fails, return `"score": "DISQUALIFIED"` with the failing gate(s) listed.

### Tier 2 — Emulation Realism (0–7 points) — Dominant Driver

How faithfully the test reproduces the observable primitives of the real adversary.

**2a. API Fidelity (0–2.5)** — Same Win32/NT/COM/POSIX API calls, in the same order, with the same flags as the real adversary toolkit. **2.5** = exact API sequence (handle flags, IOCTL codes, CLSIDs match); **1.7** = core chain matches with minor parameter deviations; **0.8** = similar API family but different calls; **0** = mechanism abstracted away.

**2b. Identifier Fidelity (0–1.5)** — Real target paths, registry keys, service names, CLSIDs, file names. **1.5** = real production identifiers extracted at runtime; sandbox artifacts named after real targets. **0.9** = identifiers hard-coded but accurate. **0** = placeholder identifiers.

**2c. Telemetry Signal Quality (0–2)** — Does the test produce clear, detectable adversary signals? Score the test, NOT any tenant's defense. Four ~0.5-point criteria:

1. **Signal richness**: per primitive, the test emits a named, identifiable signal in the appropriate telemetry surface (kernel events, ETW, registry, process, file system).
2. **Sensor mapping**: `info.md` cross-references each primitive with a specific sensor type and rule pattern that *would* detect it (the "Detection Opportunity Audit" table).
3. **Rule artifact validity**: bundled detection rules (`*_detections.kql`, `*_sigma_rules.yml`, `*_rules.yar`, `*_dr_rules.yaml`) are valid and parseable under their respective schemas.
4. **Lab execution verified — all stages reached**: `test_execution_log.json` exists with `exitReason` set AND every declared stage shows `status: success | failed` (not `skipped`) in `bundle_results.json`. **Exception path**: stages unreachable due to defense intervention earlier in the kill chain are credited IFF info.md contains a Lab-Bound Observability block per the canonical schema (see v2.1 doc §"2c → Lab-Bound Observability"). The author MUST consult the framework owner before invoking this exception.

**Hard cap**: until criterion 4 is met, this sub-score is capped at **1.5** regardless of the other criteria. Tenant rule-firing is explicitly NOT a criterion — that's a separate Tenant Defense Audit.

**2d. Execution-Context Fidelity (0–1)** — Does the test handle user/admin/SYSTEM contexts correctly and produce the right telemetry shape per context?

| Score | Criterion |
|-------|-----------|
| 1.0   | Test detects execution context at runtime, branches behavior to produce realistic adversary signals per context. info.md documents which context the test primarily emulates. |
| 0.5   | Test handles one context well but doesn't branch (acceptable for tests where context-independence is genuinely desirable). |
| 0     | Test crashes, errors, or produces fundamentally unrealistic telemetry under non-SYSTEM contexts. |

### Tier 3 — Structure (0–3 points) — Floor

**3a. Schema & Metadata (0–1)** — Schema v2.0 InitLogger + complete TestMetadata (incl. `RubricVersion: "v2.1"`) + ExecutionContext (org UUID) + signed binary. **0.5** = v2.0 but one field missing or org short-name. **0** = pre-v2.0 or unsigned.

**3b. Documentation Completeness (0–1)** — README + `<uuid>_info.md` (with `### Score Breakdown` table) + `<uuid>_references.md`; `utils/validate-score-format.sh` passes; MITRE mapping cites official technique IDs.

**3c. Logging & Plumbing (0–0.5)** — `test_logger.go` v2.0 + per-stage `bundle_results.json` + pre/post `<uuid>_system_snapshot_{pre,post}.json`. Reduced cap from v2 to make room for 3d.

**3d. Operational Hygiene (0–0.5)** — Five sub-criteria, each ~0.1 points:

| Property | Threshold | Score |
|----------|-----------|-------|
| Orchestrator binary size | < 25 MB | 0.1 |
| Stage binary size (each) | < 5 MB | 0.1 |
| Per-stage execution-time budgets documented in info.md | yes | 0.1 |
| Watchdog goroutine on every plausibly-hanging stage (long syscalls, kernel-object waits, COM activation) | yes | 0.1 |
| `Endpoint.Stop()` exits within 30s of last log entry on every code path | yes | 0.1 |

### Final Formula

\`\`\`
if any safety_gate violation:
    score = "DISQUALIFIED"
else:
    realism   = api_fidelity + identifier_fidelity
              + telemetry_signal_quality + execution_context_fidelity   # 0–7
    structure = schema + docs + logging + operational_hygiene           # 0–3
    score     = realism + structure                                     # 0–10
\`\`\`

### Targets and Score Ranges

- **Realism ≥ 5.0 / 7.0** and **Structure ≥ 2.5 / 3.0** for ship.
- Total **≥ 7.5** to ship; **≥ 9.0** for the "exceptional" label.
- Basic: 4.0–5.9 | Good: 6.0–7.9 | Advanced: 8.0–8.9 | Exceptional: 9.0–10.0

**Re-scoring policy.** Existing v2-scored tests are not retroactively re-scored under v2.1 — that would invalidate ES/PA trend lines. They keep their v2 score with `RubricVersion: "v2"`. The Nightmare-Eclipse triad (5e59dd6a / 6a2351ac / 0d7e7571) is the explicit Option B re-score case and carries `RubricVersion: "v2.1"`. Apply v2.1 to all *new* tests and to any test whose source code is materially changed.

### Rubric v2 (legacy — do not use for new tests)

Preserved for reference because tests scored 2026-04-25 carry `RubricVersion: "v2"`: API Fidelity (0–3) + Identifier Fidelity (0–2) + Detection-Rule Firing (0–2) + Schema (0–1) + Docs (0–1) + Logging (0–1) = 10. Capped at 7.5 without lab-fired detection rules. Conflated test quality with tenant defense — see v2.1 doc §"Issue 1" for the supersession rationale.

### Rubric v1 (legacy — do not use for new tests)

Preserved for reference because tests scored before 2026-04-25 carry `RubricVersion: "v1"`: Real-World Accuracy (0–3) + Technical Sophistication (0–3) + Safety Mechanisms (0–2) + Detection Opportunities (0–1) + Logging & Observability (0–1) = 10. Co-equal weighted dimensions with no safety gate, no realism axis, no lab-firing requirement. Multi-stage tests received a +1.0–1.5 bonus.
```

---

## Patch 2 — `.claude/skills/sectest-source-analysis.md`

**Single-line edit** — find the `Score estimate` line currently citing v2:

### Find

```markdown
- **Score estimate** (0-10, using rubric **v2** — see `.claude/agents/sectest-documentation.md`. Estimate Realism (0-7) + Structure (0-3) and confirm Safety gate would pass. **Cap pre-lab estimates at 7.5** since Detection-Rule Firing Fidelity is capped at 0.5 without lab evidence.)
```

### Replace with

```markdown
- **Score estimate** (0-10, using rubric **v2.1** — see `.claude/agents/sectest-documentation.md`. Estimate Realism (0-7: API 2.5 + Identifier 1.5 + Telemetry Signal Quality 2 + Execution-Context Fidelity 1) + Structure (0-3: Schema 1 + Docs 1 + Logging 0.5 + Operational Hygiene 0.5) and confirm Safety gate would pass. **Pre-lab cap**: 2c Telemetry Signal Quality is capped at 1.5/2 until criterion 4 (all stages reached OR Lab-Bound Observability block in info.md) is met.)
```

---

## Verify after applying

```bash
# All should print non-empty results
grep -c "RubricVersion.*v2.1" .claude/agents/sectest-documentation.md   # expect 4+
grep -c "Telemetry Signal Quality\|Execution-Context Fidelity\|Operational Hygiene" .claude/agents/sectest-documentation.md   # expect 3+ (one per new sub-dim)
grep -c "rubric.*v2.1" .claude/skills/sectest-source-analysis.md   # expect 1
```

## Commit suggestion

```
feat(rubric): activate v2.1 in agent + skill prompts

Replaces the v2 scoring rubric in sectest-documentation.md with v2.1:
reframes 2c as Telemetry Signal Quality (test-property, not tenant-defense),
adds 2d Execution-Context Fidelity (0-1) and 3d Operational Hygiene (0-0.5),
and adjusts 2a/2b/3c maxes to fit the new total. Updates
sectest-source-analysis.md to match.

Companion to the v2.1 activation commit — once these two prompt files
land, the activation is complete and all new tests built by
sectest-builder are scored under v2.1.

Existing v2-scored tests are not retroactively re-scored.
```

---

## Why this is split out from the main commit

Auto-mode in Claude Code refuses any edit to `.claude/agents/` or
`.claude/skills/` because changes there directly affect agent behavior —
the only safe path is interactive approval. So the rest of the
activation slice lands in the main commit, and these two prompt edits
are the manual residual.

After applying these two patches and committing them, the v2.1 rubric is
fully active.

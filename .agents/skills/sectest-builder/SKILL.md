---
name: sectest-builder
description: Build a complete F0RT1KA security test (Go attack simulation, 5-format detection rules, defense guidance, docs, kill chain) from threat intelligence, security articles, incident reports, or CVEs
whenToUse: When the user asks to build, create, or author a security test, attack simulation, detection test, or adversary emulation in the f0_library repo — whether from a URL, PDF, pasted threat intel, a CVE, or a verbal description
type: prompt
arguments:
  - source
---

Orchestrate the F0RT1KA sectest-builder workflow for this threat-intel source: $ARGUMENTS

Step 0 — Load the workflow (read in this order before doing anything else):
1. `AGENTS.md` (repo root) — settled operating defaults (Windows-only, rubric v2.1, worktree branching, F0RT1KA signing, deploy-to-win, no-push, safety escalation).
2. `.claude/agents/sectest-builder.md` — the orchestrator definition you must follow.
3. `CLAUDE.md` — mandatory development rules (bug prevention 1–8, Schema v2.0, metadata header contract, binary size budget).

Step 1 — Set up branching per AGENTS.md: create a git worktree from `main` named `../f0_library-<short-name>` on a new `feat/<short-name>` branch, and symlink `signing-certs/` into it. All subsequent work happens inside the worktree. Never touch the user's current branch or its uncommitted changes.

Step 2 — Execute the four-phase workflow from `.claude/agents/sectest-builder.md`:
- Phase 1 (sequential): apply `.claude/skills/sectest-source-analysis.md`, then `sectest-implementation.md`, then `sectest-build-config.md`. If the source is a URL, fetch it; if it is a local PDF/file, read it first.
- Phase 2 (parallel background subagents): dispatch per `.claude/agents/sectest-documentation.md`, `sectest-detection-rules.md`, `sectest-defense-guidance.md`, plus `kill-chain-diagram-builder.md` for multi-stage attack tests only — each with the full context payload template from sectest-builder.md. Score with rubric v2.1.
- Phase 3: apply `.claude/skills/sectest-validation.md` — file completeness, score-format consistency, detection-rule artifact check, metadata header check, local git commit (never push).
- Phase 3b: apply `.claude/skills/sectest-deploy.md` — deploy to the `win` lab, interpret the exit code, stage logs under `staging/<uuid>/`.

Step 3 — Report: test overview, v2.1 score with breakdown, MITRE mapping, files created, build/sign commands, deploy result with exit-code interpretation, and any PA-propagation checklist items.

Hard rules: LOG_DIR/ARTIFACT_DIR confinement; never hardcode exit codes; ambiguous errors map to 999, never to a block code; escalate borderline realism-vs-safety lifts to the user with a triage table instead of deciding unilaterally.

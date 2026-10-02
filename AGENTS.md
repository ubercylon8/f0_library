# AGENTS.md — F0RT1KA Security Test Framework

Guidance for AI coding agents (Kimi Code, Claude Code, others) working in this repository.

## What this repo is

F0RT1KA security testing framework: Go-based AV/EDR detection-evaluation tests mapped to MITRE ATT&CK. Tests live in `tests_source/{intel-driven,cyber-hygiene,mitre-top10}/<uuid>/`.

## Building a security test (primary workflow)

When the user asks to build/create/author a security test, attack simulation, or adversary emulation — from threat intel, an article, a PDF, a CVE, or a verbal description — run the **sectest-builder workflow**:

1. Read `.claude/agents/sectest-builder.md` (orchestrator) and follow it exactly.
2. Read `CLAUDE.md` — mandatory development rules (bug prevention 1–8, Schema v2.0, metadata header contract, binary size budget). Kimi Code does NOT auto-load CLAUDE.md; read it on demand.
3. Phase skills are in `.claude/skills/sectest-*.md` — read each skill file when entering its phase.
4. Phase-2 sub-agent definitions are in `.claude/agents/sectest-documentation.md`, `sectest-detection-rules.md`, `sectest-defense-guidance.md`, `kill-chain-diagram-builder.md` — dispatch as parallel background subagents using the context-payload template from sectest-builder.md.

## Settled operating defaults (agreed with user 2026-10-01)

- **Platform**: Windows tests only for now (the `debian` and `mac` labs are offline; `win` is the active lab — Windows 11 Pro, Defender ON, SSH alias `win`).
- **Scoring rubric**: **v2.1** (`docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md`). Note: `.claude/agents/sectest-documentation.md` still embeds the older v2 text — v2.1 wins where they differ.
- **Branching — worktree per test, never touch the user's current branch**:
  ```bash
  git worktree add ../f0_library-<short-name> -b feat/<short-name> main
  ln -s ../f0_library/signing-certs ../f0_library-<short-name>/signing-certs
  ```
  `signing-certs/` is gitignored, so it does not exist in a fresh worktree — the symlink is required for `utils/resolve_org.sh` and `utils/codesign` to work. The same applies to any other gitignored local files the build needs.
- **Build/sign**: run `utils/gobuild` + `utils/codesign` from inside the worktree. Sign with the F0RT1KA cert by default; dual-sign with `--org <sb|tpsgl|rga>` only when the user asks. The MCP `build_test`/`deploy_and_run` tools are pinned to the main checkout root (`F0_LIBRARY_ROOT`) — use the underlying shell commands when working in a worktree.
- **Deploy**: Phase 3b auto-deploys to the `win` lab per `.claude/skills/sectest-deploy.md`. On the first deploy of a session, verify F0RT1KA cert trust on the target (`utils/Check-DefenderProtection.ps1` / `utils/Check-F0RT1KA-Certificate.ps1`) so signing issues don't masquerade as detections.
- **Git**: commit locally on the feature branch with conventional-commit messages; **NEVER push** without an explicit user instruction. Stage specific paths, never `git add -A` from the repo root.
- **Safety gate**: realism-vs-safety borderline calls (per sectest-builder.md "Realism vs Safety") are escalated to the user with a triage table — the user makes these decisions (standing instruction). Never silently downgrade realism either.

## Exit-code integrity (non-negotiable)

101 = unprotected, 105/127 = quarantined, 126 = blocked (only with positive evidence of a protection action), 999 = test error, 102 = timeout. Never hardcode exit codes; ambiguous/benign failures map to 999, never to a block code (Bug Prevention Rule 8 in CLAUDE.md).

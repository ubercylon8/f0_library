# Design: `f0_library` MCP Server

- **Component:** `mcp_server/` (new top-level directory)
- **Date:** 2026-08-08
- **Author:** brainstormed with user (james@fortika.io)
- **Status:** Approved design — pending implementation plan

## 1. Purpose

Expose the deterministic, non-judgment operations of the F0RT1KA framework — catalog
query, MITRE coverage analysis, validation, build/sign, and lab detonation — as an MCP
server named `f0_library`, consumable from Claude Code, Claude Desktop, and
ProjectAchilles.

The server is a **data-and-actions layer that agents consume**, not a wrapper around
agents.

## 2. Viability Finding (why this is worth building)

Four findings from repository exploration justified proceeding:

1. **The corpus is real and already structured.** 60 UUID-shaped directories exist under
   `tests_source/`; **58 are real tests** (38 intel-driven, 10 cyber-hygiene,
   10 mitre-top10) and all 58 carry a machine-parseable metadata header
   (`ID/NAME/TECHNIQUES/TACTICS/SEVERITY/TARGET/COMPLEXITY/THREAT_ACTOR/SUBCATEGORY/
   TAGS/AUTHOR`) — 100% coverage. **No queryable index exists over any of it.**
   Answering "which tests cover T1562.001?" requires grepping and reading.

2. **The existing catalog tool has already drifted.** `utils/get_tests.py:28` hardcodes
   `self.categories = ["intel-driven", "phase-aligned"]`. `phase-aligned` no longer
   exists, and the list omits `cyber-hygiene` (10 tests) and `mitre-top10` (10 tests).
   **20 of 58 tests are invisible to the repository's own listing tool**, and it has no
   way to tell a real test from a build-artifact shell. This is evidence that ad-hoc
   scripts carrying hardcoded knowledge rot.

3. **Naive filesystem discovery is not enough — two artifact shells sit in the tree.**
   `tests_source/build/8e2cf534-.../` holds only a stray 10 MB `.exe`, and
   `tests_source/intel-driven/56475cb3-.../` holds only a nested `build/` directory with
   another `.exe`. Both are untracked and gitignored; neither has any source. A discovery
   rule of "UUID-shaped directory" would invent a fourth category (`build`) and report
   two phantom tests. The intrinsic discriminator is that **a test has `<uuid>.go` at its
   top level** — which separates all 58 real tests from both shells exactly, without a
   hardcoded exclusion list.

4. **Wrapping `sectest-builder` in MCP is architecturally impossible, and that is fine.**
   An MCP server is a separate process speaking JSON-RPC over stdio; it has no handle on
   Claude Code's internal `Agent` tool. The only mechanism would be shelling out to
   headless `claude -p`, which from inside Claude Code means Claude spawning Claude —
   full token cost, no shared context, strictly worse than invoking the agent directly.
   Authoring a test from threat intelligence is judgment work (scenario selection,
   realism-vs-safety triage, Go implementation) and correctly remains an agent.

5. **The deterministic layer is what agents currently do by hand.** Catalog query,
   coverage, validation, build/sign, deploy, results parsing are all pure code with
   stable contracts. Moving them into MCP tools makes them cheaper (no file-reading
   tokens), reliable (no drift), and reusable **by the agents themselves** —
   `sectest-validation` calls `f0_library.validate_test` instead of re-deriving checks.

**Verdict: viable and high value — as a data-and-actions server, not an agent wrapper.**

## 3. Scope & Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Primary consumer | **Claude Code + external MCP clients** (Claude Desktop, ProjectAchilles) | Portability is a stated goal; PA is the natural second consumer of the catalog. |
| Capability variance | **One server, capability-gated at startup** | Single codebase; each host advertises only tools it can actually run. No dead tools, no discover-by-failing. |
| Transport | **stdio only** | All consumers are same-machine. Avoids auth/TLS, and keeps the signing key and lab SSH access off any network surface. HTTP is an additive change later — the tool layer is transport-agnostic. |
| Language / runtime | **Python + official `mcp` SDK, run via `uv`** | `utils/validate_test_results.py` exposes importable functions (`validate_test_result`, `perform_additional_checks`, `load_schema`); the server imports them rather than subprocessing and parsing stdout. `uv` is present; repo utils are already Python. |
| Index strategy | **Live parse, memoized on `(path, mtime)`** | 58 small header reads is sub-100ms. A persisted index needs a refresh step and eventually goes stale — the exact failure mode being removed. |
| Category discovery | **Discovered from filesystem** | Directly eliminates the `get_tests.py` drift bug class. |
| Detonation tool | **Included, with `confirm_host` token** | Preserves the create→build→test workflow while making the trigger deliberate; no vague prompt can fire it. |
| Agent workflow reach | **MCP `prompts` surface** | The legitimate way `sectest-builder`'s procedure reaches non-Claude-Code clients without nesting sessions. |

### Explicitly out of scope (YAGNI)

- `search_tests` as a separate tool — folded into `list_tests` as a `query` parameter.
- `sign_test` as a separate tool — folded into `build_test`, mirroring `/build-sign-test`.
- HTTP/SSE transport, auth, multi-tenancy.
- Any tool that authors, edits, or scores test source — that is agent work.
- Persisted catalog index or a `refresh` command.

## 4. Architecture

```
mcp_server/
  pyproject.toml               uv-managed; deps: mcp[cli], jsonschema
  README.md                    install + client-config instructions
  src/f0_library_mcp/
    __init__.py
    server.py                  MCP wiring; conditional registration; entrypoint
    config.py                  repo-root resolution
    probe.py                   host capability detection
    catalog.py                 metadata-header parser + in-memory index
    classify.py                exit-code -> verdict classification
    tools/
      __init__.py
      catalog_tools.py         list_tests, get_test, mitre_coverage
      validate_tools.py        validate_test, validate_results
      build_tools.py           build_test              (Tier B)
      deploy_tools.py          deploy_and_run          (Tier B)
    resources.py               schema, rubric, org registry, per-test files
    prompts.py                 build_sectest, validate_sectest
  tests/
    test_catalog.py
    test_probe.py
    test_classify.py
    test_tools_catalog.py
    test_tools_validate.py
    test_server_contract.py
```

Each module has one purpose and a narrow interface:

- `config.py` — resolves repo root. **Never from `cwd`.** Order: `F0_LIBRARY_ROOT` env
  var, then walk up from the package location looking for `CLAUDE.md` + `tests_source/`.
  Raises a clear startup error if unresolvable. This is what makes the server portable to
  clients that spawn subprocesses from arbitrary directories.
- `catalog.py` — the sole metadata-header parser. Depends only on `config`.
- `probe.py` — pure host inspection, no repo knowledge beyond the PFX path.
- `classify.py` — exit code + evidence -> verdict. No I/O. Independently testable.
- `tools/*` — thin adapters: validate inputs, call the module above, shape the response.

## 5. Components

### 5.1 `catalog.py`

**Responsibility:** produce a `TestRecord` per test directory, and an index over them.

```
TestRecord:
  uuid, category, name, path
  techniques[], tactics[], severity, target[], complexity,
  threat_actor, subcategory, tags[], source_url, author, created
  score            (parsed from README.md '**Test Score**: **X.X/10**'; None if absent)
  architecture     ('multi-stage' if build_all.sh + stage dirs, else 'standard')
  files_present[]  (README.md, *_info.md, *_references.md, test_logger.go, ...)
  header_ok        (bool) + header_missing[] (list of absent required fields)
```

**Discovery — two-stage, no hardcoded knowledge:**

1. Glob `tests_source/*/` for candidate categories, then UUID-regex their subdirectories.
2. A candidate qualifies as a test **iff `<uuid>.go` exists at its top level.**

Stage 2 is load-bearing, not defensive coding. Two artifact shells currently live in the
tree — `tests_source/build/8e2cf534-.../` (a stray `.exe`) and
`tests_source/intel-driven/56475cb3-.../` (a nested `build/` holding another `.exe`).
Stage 1 alone would invent a `build` category and report two phantom tests. The
`<uuid>.go` rule separates all 58 real tests from both shells exactly, and does so by
asking what a test *is* rather than maintaining an exclusion list that would itself
drift. A category with zero qualifying tests is not reported as a category.

**Parsing:** read the leading `/* ... */` block of `<uuid>.go` (tolerating a preceding
`//go:build` line, as in `e5577355-.../e5577355-....go`). Field regexes match the
`MetadataExtractor` contract documented in `CLAUDE.md`.

**Memoization:** module-level dict keyed by `(path, mtime_ns)`. An edited test
invalidates its own entry. No refresh command; no staleness.

**Failure handling:** a test whose header is absent or malformed still yields a
`TestRecord` with `header_ok=False` and populated `header_missing`. It is never dropped
silently — silent omission is precisely the `get_tests.py` failure being corrected.

Directories rejected at discovery stage 2 are recorded in an `anomalies` list rather than
discarded. They are excluded from `list_tests` and `mitre_coverage` (they are not tests),
but `get_test` on such a UUID returns an explicit `artifact_shell` result naming what was
found, rather than a bare "not found" that would leave the caller guessing.

### 5.2 `probe.py`

Runs once at startup, before `initialize` responds. Returns a `Capabilities` record.

| Probe | Method | Enables |
|-------|--------|---------|
| Go toolchain | `go version` exits 0 | `build_test` |
| Signing | `signing-certs/F0RT1KA.pfx` readable **and** `osslsigncode` on PATH | signing step inside `build_test` |
| Lab hosts | `ssh -G <alias>` resolves to a hostname differing from the alias | `deploy_and_run`, recorded per alias |

Probed aliases: `debian`, `win`, `mac`. The set of resolvable aliases becomes the
enum of legal `confirm_host` values.

Probes are best-effort with short timeouts; a probe failure disables a capability, it
never crashes startup.

### 5.3 `classify.py`

Maps a test's exit code and observed evidence to a verdict. Governed by
**CLAUDE.md Bug Prevention Rule 8**.

| Code | Verdict |
|------|---------|
| 0 / 101 | `unprotected` — attack succeeded |
| 105 | `quarantined` |
| 126 | `execution_prevented` |
| 999 | `test_error` — prerequisites not met |
| anything else | **`unknown`** |

**The invariant, and the reason this module exists separately:** an unrecognized or
ambiguous outcome maps to `unknown` — *never* to a block code. A classifier that
defaults ambiguity to "blocked" manufactures false PROTECTED verdicts, telling users
their endpoint stopped an attack when nothing did. `unknown` is a first-class verdict,
not an error.

This module's core function is the one place in the server where domain judgment lives
(transparent-MITM, captive-portal, and timeout edge cases have been litigated by the
user in prior tests). **Implementation of the classification function will be requested
from the user** rather than inferred.

### 5.4 Tool surface

**Tier A — portable, always advertised:**

| Tool | Inputs | Returns |
|------|--------|---------|
| `list_tests` | `category?`, `technique?`, `tactic?`, `actor?`, `platform?` (matches the `TARGET` field), `severity?`, `subcategory?`, `query?` (substring over name + tags + README), `limit?` | Compact rows: uuid, name, category, techniques, severity, score |
| `get_test` | `uuid` | Full `TestRecord` + files present + header validation state |
| `mitre_coverage` | `group_by?` (`technique`\|`tactic`), `category?` | Coverage counts per technique/tactic, plus tests-per-technique and an explicit uncovered list |
| `validate_test` | `uuid` | Structured findings: required files, score-format consistency (README vs info card), metadata-header completeness vs the PA contract |
| `validate_results` | exactly one of `path` or `content` | Schema v2.0 conformance errors + classified verdict from `classify.py`. Supplying both, or neither, is an input error. |

**Tier B — machine-bound, gated:**

| Tool | Inputs | Returns |
|------|--------|---------|
| `build_test` | `uuid`, `org?`, `platform?` | Binary path, SHA1, byte size, **budget tier** (green ≤10MB / yellow 10–25 / red 25–50 / forbidden >50), signing status, build log tail |
| `deploy_and_run` | `uuid`, `host`, `confirm_host` | Exit code, stdout/stderr, parsed results JSON, classified verdict |

`deploy_and_run` requires `confirm_host` to string-match `host`; a mismatch is a hard
input error before any SSH occurs. It reproduces the `sectest-deploy` skill's
preflight, including `sudo mkdir -p /home/fortika-test && sudo chmod 777` on Linux
targets, since skipping it yields a spurious exit 999.

`build_test` reports the size tier but does **not** refuse to build — matching the
documented policy that the budget encodes preference, not impossibility.

### 5.5 Resources

| URI | Content |
|-----|---------|
| `f0://schema/test-results-v2.0` | `test-results-schema-v2.0.json` |
| `f0://rubric/active` | Active v2.1 scoring rubric |
| `f0://registry/organizations` | `signing-certs/organization-registry.json` |
| `f0://test/{uuid}/{filename}` | Any file within a test directory |

Path traversal outside `tests_source/` is rejected.

### 5.6 Prompts

| Prompt | Content |
|--------|---------|
| `build_sectest` | Condensed `sectest-builder` procedure: four-phase workflow, critical development rules, realism-vs-safety triage, rubric pointer. Takes a threat-intel source argument. |
| `validate_sectest` | The `sectest-validation` checklist as a prompt, for clients without the skill. |

Prompts describe the procedure; they do not attempt to invoke agents. Inside Claude
Code the real agent remains the correct entry point.

## 6. Data Flow

```
client --initialize--> server
                         |
                         +-- config.resolve_root()      (fails fast if unresolvable)
                         +-- probe.detect()             (Capabilities)
                         +-- register Tier A tools
                         +-- register Tier B tools  [gated on Capabilities]
                         |
client <--tools/list--   (host-accurate tool list)

client --list_tests--> catalog.index()  --> memoized parse of tests_source/*/<uuid>/
client --validate_test--> catalog + utils.validate_test_results (imported)
client --build_test--> subprocess utils/gobuild -> utils/codesign -> size tier
client --deploy_and_run--> confirm_host check -> ssh preflight -> scp -> ssh exec
                            -> fetch results JSON -> classify.verdict()
```

## 7. Error Handling

- Tools return structured results; tracebacks never reach the client.
- Shelled-out commands return exit code plus captured stdout/stderr verbatim. Output is
  never swallowed or summarized away — a build or deploy failure must be diagnosable
  from the tool response alone.
- `config` failure is fatal at startup with an actionable message naming
  `F0_LIBRARY_ROOT`. A server that silently serves an empty catalog is worse than one
  that refuses to start.
- `probe` failures are non-fatal; they disable capabilities.
- Malformed test headers surface as `header_ok=False`, never as omission.
- `classify` returns `unknown` for anything unrecognized — never a block code.

## 8. Testing Strategy

`pytest`, run against the real corpus.

| Test | Asserts |
|------|---------|
| `test_catalog.py` | Exactly 58 tests discovered and all parse with `header_ok=True` — a drop below 58 fails the suite, so header regressions surface immediately. The two known artifact shells are classified as anomalies, not tests, and no `build` category is invented. Categories discovered, not hardcoded. Memoization invalidates on mtime change. |
| `test_probe.py` | Both directions per capability, with `shutil.which` / `subprocess` monkeypatched. |
| `test_classify.py` | Every known code maps correctly; **every ambiguous/unrecognized input yields `unknown` and never a block code**. |
| `test_tools_catalog.py` | Filters compose; `mitre_coverage` totals reconcile with `list_tests`. |
| `test_tools_validate.py` | Known-good test passes; deliberately broken fixtures produce specific findings. |
| `test_server_contract.py` | Via the MCP in-memory client: Tier A always advertised; Tier B advertised iff capabilities present; `deploy_and_run` rejects a mismatched `confirm_host` before any subprocess. |

Tier B shell-outs are mocked. **No test builds a binary or detonates anything.**

## 9. Targeted Improvement to Existing Code

Rewrite `utils/get_tests.py` as a thin wrapper over `catalog.py`.

This is in scope because it is the mechanism that guarantees one parser rather than two
that drift apart — addressing the bug class, not just the instance. The `/get-tests`
command keeps its current output contract and begins reporting all 58 tests instead of
38.

No other refactoring of existing utilities is in scope.

## 10. Success Criteria

1. `f0_library` loads in Claude Code via `.mcp.json` and advertises 7 tools on the dev box.
2. The same server, spawned from an arbitrary cwd with `F0_LIBRARY_ROOT` set, advertises
   the 5 Tier A tools and no Tier B tools when Go/PFX/SSH are absent.
3. `list_tests` returns exactly 58 tests across 3 categories — no `build` category, no
   phantom entries; `mitre_coverage` totals reconcile with `list_tests`.
4. `utils/get_tests.py` reports the same 58 tests via the shared parser (up from 38).
5. Full pytest suite green, including the classifier's never-default-to-blocked invariant.
6. `deploy_and_run` refuses a mismatched `confirm_host` without contacting any host.

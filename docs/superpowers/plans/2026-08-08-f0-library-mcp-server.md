# f0_library MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an MCP server named `f0_library` exposing F0RT1KA's deterministic operations — catalog query, MITRE coverage, validation, build/sign, lab detonation — over stdio to Claude Code, Claude Desktop, and ProjectAchilles.

**Architecture:** A Python package under `mcp_server/`. A single `MCPServer` instance registers five portable Tier A tools unconditionally and two machine-bound Tier B tools only when a startup host probe confirms the required toolchain. All test knowledge flows through one parser (`catalog.py`), which also replaces the hardcoded category list in `utils/get_tests.py`.

**Tech Stack:** Python 3.12+, `mcp` 2.0.0 (official SDK), `pydantic` v2, `jsonschema`, `pytest` + `pytest-asyncio`, managed by `uv`.

**Spec:** `docs/superpowers/specs/2026-08-08-f0-library-mcp-server-design.md` (commit `e77297a`)

## Global Constraints

Every task's requirements implicitly include this section.

- **SDK import path is `from mcp.server.mcpserver import MCPServer`.** `mcp.server.fastmcp` does **not exist** in mcp 2.0.0. Any code or documentation referencing `FastMCP` is from 1.x and is wrong here. Verified empirically 2026-08-08.
- **Every tool function MUST declare a Pydantic `BaseModel` return type.** A bare `-> dict` silently yields `structured_content = None`; `structured_output=True` on a `dict` raises `mcp.server.mcpserver.exceptions.InvalidSignature`. Verified empirically.
- **mcp 2.0 result attributes are snake_case**: `result.structured_content`, `tool.output_schema`. The 1.x camelCase names raise `AttributeError`.
- **Transport is stdio only.** No HTTP/SSE server code, no auth, no TLS.
- **Repo root MUST NOT be derived from `cwd`.** Resolution order: `F0_LIBRARY_ROOT` env var, then walk up from the package file for a directory containing both `CLAUDE.md` and `tests_source/`.
- **The corpus contains exactly 58 real tests** (38 intel-driven, 10 cyber-hygiene, 10 mitre-top10) and 2 artifact shells. A test is a UUID-named directory containing `<uuid>.go` at its top level.
- **Never map an unrecognized exit code to a block code.** Unknown outcomes classify as `unknown`. This is CLAUDE.md Bug Prevention Rule 8 and is non-negotiable.
- **No test may build a binary or contact a lab host.** Tier B subprocess calls are mocked in all tests.
- Commit after every task. Do not `git push` — surface the hash and stop.

---

### Task 1: Project scaffold and repo-root resolution

**Files:**
- Create: `mcp_server/pyproject.toml`
- Create: `mcp_server/src/f0_library_mcp/__init__.py`
- Create: `mcp_server/src/f0_library_mcp/config.py`
- Test: `mcp_server/tests/test_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `resolve_root(explicit: Path | None = None) -> Path` and `class RootNotFoundError(RuntimeError)`, both in `f0_library_mcp.config`. Every later task imports `resolve_root`.

- [ ] **Step 1: Create the package skeleton**

```bash
mkdir -p mcp_server/src/f0_library_mcp/tools mcp_server/tests
touch mcp_server/src/f0_library_mcp/__init__.py mcp_server/src/f0_library_mcp/tools/__init__.py
```

```toml
# mcp_server/pyproject.toml
[project]
name = "f0-library-mcp"
version = "0.1.0"
description = "MCP server exposing F0RT1KA security-test catalog, validation, build and lab operations"
requires-python = ">=3.12"
dependencies = ["mcp>=2.0.0", "pydantic>=2.0", "jsonschema>=4.0"]

[project.scripts]
f0-library-mcp = "f0_library_mcp.server:main"

[dependency-groups]
dev = ["pytest>=8.0", "pytest-asyncio>=0.24"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/f0_library_mcp"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

- [ ] **Step 2: Write the failing test**

```python
# mcp_server/tests/test_config.py
import pytest
from pathlib import Path
from f0_library_mcp.config import resolve_root, RootNotFoundError


def test_explicit_path_wins(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("x")
    (tmp_path / "tests_source").mkdir()
    assert resolve_root(tmp_path) == tmp_path


def test_env_var_used(tmp_path, monkeypatch):
    (tmp_path / "CLAUDE.md").write_text("x")
    (tmp_path / "tests_source").mkdir()
    monkeypatch.setenv("F0_LIBRARY_ROOT", str(tmp_path))
    assert resolve_root() == tmp_path


def test_walks_up_to_real_repo(monkeypatch):
    """With no env var, resolution walks up from the package file."""
    monkeypatch.delenv("F0_LIBRARY_ROOT", raising=False)
    root = resolve_root()
    assert (root / "CLAUDE.md").is_file()
    assert (root / "tests_source").is_dir()


def test_raises_when_unresolvable(tmp_path, monkeypatch):
    """A directory lacking the markers must fail loudly, not serve an empty catalog."""
    monkeypatch.setenv("F0_LIBRARY_ROOT", str(tmp_path))
    with pytest.raises(RootNotFoundError) as exc:
        resolve_root()
    assert "F0_LIBRARY_ROOT" in str(exc.value)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd mcp_server && uv run pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'f0_library_mcp.config'`

- [ ] **Step 4: Implement config.py**

```python
# mcp_server/src/f0_library_mcp/config.py
"""Repo-root resolution.

Never derives the root from cwd: this server is spawned as a subprocess by
clients (Claude Desktop, ProjectAchilles) whose working directory is arbitrary.
"""
from __future__ import annotations

import os
from pathlib import Path

MARKERS = ("CLAUDE.md", "tests_source")


class RootNotFoundError(RuntimeError):
    """Raised when the f0_library repo root cannot be located."""


def _is_root(path: Path) -> bool:
    return (path / MARKERS[0]).is_file() and (path / MARKERS[1]).is_dir()


def resolve_root(explicit: Path | None = None) -> Path:
    """Locate the f0_library repo root.

    Order: explicit argument, F0_LIBRARY_ROOT env var, then walk up from this
    file. Raises RootNotFoundError rather than returning a wrong root -- a
    server that silently serves an empty catalog is worse than one that
    refuses to start.
    """
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(Path(explicit))
    env = os.environ.get("F0_LIBRARY_ROOT")
    if env:
        candidates.append(Path(env))

    for cand in candidates:
        cand = cand.expanduser().resolve()
        if _is_root(cand):
            return cand
        raise RootNotFoundError(
            f"{cand} is not an f0_library root (needs CLAUDE.md and tests_source/). "
            "Set F0_LIBRARY_ROOT to the repository root."
        )

    for parent in Path(__file__).resolve().parents:
        if _is_root(parent):
            return parent

    raise RootNotFoundError(
        "Could not locate the f0_library repo root. "
        "Set F0_LIBRARY_ROOT to the repository root."
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd mcp_server && uv run pytest tests/test_config.py -v`
Expected: 4 passed

- [ ] **Step 6: Commit**

```bash
git add mcp_server/pyproject.toml mcp_server/src/f0_library_mcp/__init__.py \
        mcp_server/src/f0_library_mcp/tools/__init__.py \
        mcp_server/src/f0_library_mcp/config.py mcp_server/tests/test_config.py
git commit -m "feat(mcp): scaffold f0_library MCP server with repo-root resolution"
```

---

### Task 2: Catalog parser and index

**Files:**
- Create: `mcp_server/src/f0_library_mcp/catalog.py`
- Test: `mcp_server/tests/test_catalog.py`

**Interfaces:**
- Consumes: `f0_library_mcp.config.resolve_root`.
- Produces, all in `f0_library_mcp.catalog`:
  - `class TestRecord(BaseModel)` with fields `uuid, category, path, name, techniques, tactics, severity, target, complexity, threat_actor, subcategory, tags, source_url, author, created, score, architecture, files_present, header_ok, header_missing`
  - `class Anomaly(BaseModel)` with fields `uuid, category, path, reason, contents`
  - `class Index(BaseModel)` with fields `tests: list[TestRecord]`, `anomalies: list[Anomaly]`
  - `def build_index(root: Path) -> Index`
  - `def get_index(root: Path) -> Index` — memoized wrapper
  - `REQUIRED_HEADER_FIELDS: tuple[str, ...]`

- [ ] **Step 1: Write the failing test**

```python
# mcp_server/tests/test_catalog.py
from f0_library_mcp.config import resolve_root
from f0_library_mcp.catalog import build_index, get_index, TestRecord

ROOT = resolve_root()


def test_discovers_exactly_58_tests():
    """A drop below 58 means a test lost its <uuid>.go or its header regressed."""
    idx = build_index(ROOT)
    assert len(idx.tests) == 58, [t.uuid for t in idx.tests]


def test_all_tests_parse_headers():
    idx = build_index(ROOT)
    bad = [(t.uuid, t.header_missing) for t in idx.tests if not t.header_ok]
    assert bad == []


def test_categories_are_discovered_not_hardcoded():
    idx = build_index(ROOT)
    cats = {t.category for t in idx.tests}
    assert cats == {"intel-driven", "cyber-hygiene", "mitre-top10"}
    assert "build" not in cats, "artifact dir must not become a category"


def test_artifact_shells_recorded_as_anomalies():
    idx = build_index(ROOT)
    uuids = {a.uuid for a in idx.anomalies}
    assert "8e2cf534-857b-4d29-a1ac-0f23d248db93" in uuids
    assert "56475cb3-febc-45ac-a0af-39bc5ca1c15f" in uuids
    assert all(a.reason == "missing_source" for a in idx.anomalies)


def test_parses_known_test_fields():
    idx = build_index(ROOT)
    rec = next(t for t in idx.tests if t.uuid == "e5577355-f8e4-4e52-b1b2-f7d1c8b864f1")
    assert rec.name == "SilentButDeadly WFP EDR Network Isolation"
    assert rec.techniques == ["T1562.001"]
    assert rec.tactics == ["defense-evasion"]
    assert rec.severity == "high"
    assert rec.subcategory == "edr-evasion"


def test_header_tolerates_go_build_tag_prefix():
    """e5577355 has //go:build lines before the metadata comment block."""
    idx = build_index(ROOT)
    rec = next(t for t in idx.tests if t.uuid == "e5577355-f8e4-4e52-b1b2-f7d1c8b864f1")
    assert rec.header_ok


def test_memoization_invalidates_on_mtime(tmp_path):
    root = tmp_path
    (root / "CLAUDE.md").write_text("x")
    uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    d = root / "tests_source" / "intel-driven" / uid
    d.mkdir(parents=True)
    go = d / f"{uid}.go"
    go.write_text("/*\nID: %s\nNAME: First\nTECHNIQUES: T1001\n*/\n" % uid)

    assert get_index(root).tests[0].name == "First"
    go.write_text("/*\nID: %s\nNAME: Second\nTECHNIQUES: T1001\n*/\n" % uid)
    import os, time
    os.utime(go, (time.time() + 10, time.time() + 10))
    assert get_index(root).tests[0].name == "Second"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && uv run pytest tests/test_catalog.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'f0_library_mcp.catalog'`

- [ ] **Step 3: Implement catalog.py**

```python
# mcp_server/src/f0_library_mcp/catalog.py
"""The single source of truth for what tests exist and what they contain.

Discovery is two-stage and carries no hardcoded knowledge:
  1. tests_source/*/ are candidate categories; UUID-named subdirs are candidates.
  2. A candidate is a test iff <uuid>.go exists at its top level.

Stage 2 is load-bearing. Two artifact shells live in the tree (a stray build
output under tests_source/build/, and an empty intel-driven shell holding only
a nested build/). Stage 1 alone would invent a "build" category and report two
phantom tests. An exclusion list would drift; asking what a test *is* does not.
"""
from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
_BLOCK_RE = re.compile(r"/\*(.*?)\*/", re.S)
_FIELD_RE = re.compile(r"^([A-Z_]+):[ \t]*(.*)$", re.M)
_SCORE_RE = re.compile(r"\*\*Test Score\*\*:\s*\*\*([0-9]+\.[0-9]+)/10\*\*")

REQUIRED_HEADER_FIELDS: tuple[str, ...] = (
    "ID", "NAME", "TECHNIQUES", "TACTICS", "SEVERITY", "TARGET",
    "COMPLEXITY", "THREAT_ACTOR", "SUBCATEGORY", "TAGS", "AUTHOR",
)
_LIST_FIELDS = {"TECHNIQUES", "TACTICS", "TARGET", "TAGS"}


class TestRecord(BaseModel):
    uuid: str
    category: str
    path: str
    name: str = ""
    techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    severity: str = ""
    target: list[str] = Field(default_factory=list)
    complexity: str = ""
    threat_actor: str = ""
    subcategory: str = ""
    tags: list[str] = Field(default_factory=list)
    source_url: str = ""
    author: str = ""
    created: str = ""
    score: float | None = None
    architecture: str = "standard"
    files_present: list[str] = Field(default_factory=list)
    header_ok: bool = False
    header_missing: list[str] = Field(default_factory=list)


class Anomaly(BaseModel):
    uuid: str
    category: str
    path: str
    reason: str
    contents: list[str] = Field(default_factory=list)


class Index(BaseModel):
    tests: list[TestRecord] = Field(default_factory=list)
    anomalies: list[Anomaly] = Field(default_factory=list)


def _split_list(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]


def _parse_header(source: str) -> dict[str, str]:
    match = _BLOCK_RE.search(source)
    if not match:
        return {}
    return {k: v.strip() for k, v in _FIELD_RE.findall(match.group(1))}


def _read_score(test_dir: Path) -> float | None:
    readme = test_dir / "README.md"
    if not readme.is_file():
        return None
    found = _SCORE_RE.search(readme.read_text(errors="replace"))
    return float(found.group(1)) if found else None


def _build_record(test_dir: Path) -> TestRecord:
    uuid = test_dir.name
    source = (test_dir / f"{uuid}.go").read_text(errors="replace")
    fields = _parse_header(source)

    missing = [f for f in REQUIRED_HEADER_FIELDS if not fields.get(f)]
    files = sorted(p.name for p in test_dir.iterdir() if p.is_file())
    multistage = (test_dir / "build_all.sh").is_file()

    return TestRecord(
        uuid=uuid,
        category=test_dir.parent.name,
        path=str(test_dir),
        name=fields.get("NAME", ""),
        techniques=_split_list(fields.get("TECHNIQUES", "")),
        tactics=_split_list(fields.get("TACTICS", "")),
        severity=fields.get("SEVERITY", ""),
        target=_split_list(fields.get("TARGET", "")),
        complexity=fields.get("COMPLEXITY", ""),
        threat_actor=fields.get("THREAT_ACTOR", ""),
        subcategory=fields.get("SUBCATEGORY", ""),
        tags=_split_list(fields.get("TAGS", "")),
        source_url=fields.get("SOURCE_URL", ""),
        author=fields.get("AUTHOR", ""),
        created=fields.get("CREATED", ""),
        score=_read_score(test_dir),
        architecture="multi-stage" if multistage else "standard",
        files_present=files,
        header_ok=not missing,
        header_missing=missing,
    )


def build_index(root: Path) -> Index:
    """Scan tests_source/ and classify every UUID-named directory."""
    index = Index()
    source_root = Path(root) / "tests_source"
    if not source_root.is_dir():
        return index

    for category in sorted(p for p in source_root.iterdir() if p.is_dir()):
        for cand in sorted(p for p in category.iterdir()
                           if p.is_dir() and UUID_RE.match(p.name)):
            if (cand / f"{cand.name}.go").is_file():
                index.tests.append(_build_record(cand))
            else:
                index.anomalies.append(Anomaly(
                    uuid=cand.name,
                    category=category.name,
                    path=str(cand),
                    reason="missing_source",
                    contents=sorted(p.name for p in cand.iterdir()),
                ))
    return index


_CACHE: dict[Path, tuple[frozenset[tuple[str, int]], Index]] = {}


def _fingerprint(root: Path) -> frozenset[tuple[str, int]]:
    """Cheap signature of the corpus: every candidate dir plus its mtime."""
    out: set[tuple[str, int]] = set()
    source_root = Path(root) / "tests_source"
    if not source_root.is_dir():
        return frozenset()
    for category in source_root.iterdir():
        if not category.is_dir():
            continue
        for cand in category.iterdir():
            if cand.is_dir() and UUID_RE.match(cand.name):
                go = cand / f"{cand.name}.go"
                mtime = go.stat().st_mtime_ns if go.is_file() else 0
                out.add((str(cand), mtime))
    return frozenset(out)


def get_index(root: Path) -> Index:
    """Memoized build_index. Invalidates when any test's source mtime changes."""
    root = Path(root)
    fp = _fingerprint(root)
    cached = _CACHE.get(root)
    if cached is not None and cached[0] == fp:
        return cached[1]
    index = build_index(root)
    _CACHE[root] = (fp, index)
    return index
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd mcp_server && uv run pytest tests/test_catalog.py -v`
Expected: 7 passed. If `test_discovers_exactly_58_tests` fails, print the diff between discovered UUIDs and `git ls-files tests_source | cut -d/ -f3 | sort -u` before changing the assertion — the corpus may legitimately have changed.

- [ ] **Step 5: Commit**

```bash
git add mcp_server/src/f0_library_mcp/catalog.py mcp_server/tests/test_catalog.py
git commit -m "feat(mcp): add catalog parser with intrinsic test discovery"
```

---

### Task 3: Exit-code classifier

**Files:**
- Create: `mcp_server/src/f0_library_mcp/classify.py`
- Test: `mcp_server/tests/test_classify.py`

**Interfaces:**
- Consumes: nothing (pure, no I/O — this is why it is its own module).
- Produces, in `f0_library_mcp.classify`:
  - `class Verdict(BaseModel)` with fields `code: int`, `verdict: str`, `label: str`, `protected: bool | None`, `rationale: str`
  - `def classify(code: int) -> Verdict`
  - `KNOWN_CODES: dict[int, tuple[str, str, bool | None]]`
- `verdict` is one of: `unprotected`, `quarantined`, `execution_prevented`, `test_error`, `unknown`.
- `protected` is tri-state: `True` for a confirmed block, `False` for confirmed non-protection, `None` when undetermined. It is never `True` for `unknown`.

> **This task contains a USER CONTRIBUTION step.** Step 3 asks the repo owner to write the classification body. Do not write it for them; stop and request it.

- [ ] **Step 1: Write the failing test**

```python
# mcp_server/tests/test_classify.py
import pytest
from f0_library_mcp.classify import classify, Verdict


@pytest.mark.parametrize("code,expected", [
    (0,   "unprotected"),
    (101, "unprotected"),
    (105, "quarantined"),
    (126, "execution_prevented"),
    (999, "test_error"),
])
def test_known_codes(code, expected):
    assert classify(code).verdict == expected


@pytest.mark.parametrize("code", [1, 2, 3, 42, 127, 137, 255, -1, 500, 1000])
def test_unknown_codes_never_claim_protection(code):
    """CLAUDE.md Bug Prevention Rule 8: absence of success is not evidence of a block.

    An unrecognized code must never be reported as a block. Doing so
    manufactures a false PROTECTED verdict -- telling a user their endpoint
    stopped an attack when nothing did.
    """
    v = classify(code)
    assert v.verdict == "unknown"
    assert v.protected is not True
    assert v.verdict not in ("quarantined", "execution_prevented")


def test_unknown_carries_actionable_rationale():
    v = classify(42)
    assert v.rationale
    assert "unknown" in v.rationale.lower() or "unrecogni" in v.rationale.lower()


def test_protected_flag_matches_verdict():
    assert classify(126).protected is True
    assert classify(105).protected is True
    assert classify(101).protected is False
    assert classify(999).protected is None
    assert classify(42).protected is None


def test_returns_verdict_model():
    assert isinstance(classify(101), Verdict)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && uv run pytest tests/test_classify.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'f0_library_mcp.classify'`

- [ ] **Step 3: USER CONTRIBUTION — implement the classification body**

Create the file with everything except the function body:

```python
# mcp_server/src/f0_library_mcp/classify.py
"""Exit code -> verdict classification.

Isolated from all I/O so the invariant below is testable in isolation.

THE INVARIANT (CLAUDE.md Bug Prevention Rule 8):
    A block verdict may be returned ONLY on affirmative evidence of a
    protection action. Absence of success is not evidence of a block.
    Ambiguous, unrecognized, or benign-failure outcomes map to `unknown`.
    A catch-all that resolves unknown codes to a block code is a banned
    anti-pattern: it manufactures false PROTECTED verdicts.
"""
from __future__ import annotations

from pydantic import BaseModel

# code -> (verdict, human label, protected tri-state)
KNOWN_CODES: dict[int, tuple[str, str, bool | None]] = {
    0:   ("unprotected",         "Endpoint.Unprotected (clean exit)",        False),
    101: ("unprotected",         "Endpoint.Unprotected",                     False),
    105: ("quarantined",         "Endpoint.FileQuarantinedOnExtraction",     True),
    126: ("execution_prevented", "Endpoint.ExecutionPrevented",              True),
    999: ("test_error",          "Endpoint.UnexpectedTestError",             None),
}


class Verdict(BaseModel):
    code: int
    verdict: str
    label: str
    protected: bool | None
    rationale: str


def classify(code: int) -> Verdict:
    """Map a test exit code to a Verdict.

    Contract:
      - Codes in KNOWN_CODES map to their tuple.
      - EVERY other code maps to verdict "unknown", protected None, and a
        rationale saying the code was not recognized.
      - `protected` is never True for "unknown".
    """
    raise NotImplementedError("USER CONTRIBUTION -- see plan Task 3 Step 3")
```

Then **ask the repo owner to write the `classify` body** (roughly 8 lines). Frame it as:

> The mapping table is filled in and the tests encode the invariant. What is
> yours is the wording and shape of the `unknown` branch — you have litigated
> these edge cases (transparent-MITM, captive-portal, timeout) in the PII-exfil
> classifier and the `sc.exe` empty-output rule, and the rationale text is what
> a user reads when a run is inconclusive. Write the body in
> `mcp_server/src/f0_library_mcp/classify.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd mcp_server && uv run pytest tests/test_classify.py -v`
Expected: 20 passed (5 known-code params + 10 unknown-code params + 5 others)

- [ ] **Step 5: Commit**

```bash
git add mcp_server/src/f0_library_mcp/classify.py mcp_server/tests/test_classify.py
git commit -m "feat(mcp): add exit-code classifier with never-default-to-blocked invariant"
```

---

### Task 4: Host capability probe

**Files:**
- Create: `mcp_server/src/f0_library_mcp/probe.py`
- Test: `mcp_server/tests/test_probe.py`

**Interfaces:**
- Consumes: `f0_library_mcp.config.resolve_root`.
- Produces, in `f0_library_mcp.probe`:
  - `class Capabilities(BaseModel)` with fields `go: bool`, `signing: bool`, `ssh_aliases: list[str]`
  - `def detect(root: Path) -> Capabilities`
  - `LAB_ALIASES: tuple[str, ...] = ("debian", "win", "mac")`
- `Capabilities.go` gates `build_test`; a non-empty `ssh_aliases` gates `deploy_and_run`.

- [ ] **Step 1: Write the failing test**

```python
# mcp_server/tests/test_probe.py
import subprocess
from pathlib import Path

import f0_library_mcp.probe as probe
from f0_library_mcp.probe import detect, Capabilities


def _fake_run(mapping):
    """Build a subprocess.run stand-in driven by a {first_arg: returncode} map."""
    def run(cmd, *a, **kw):
        rc = mapping.get(cmd[0], 1)
        if cmd[0] == "ssh" and rc == 0:
            return subprocess.CompletedProcess(cmd, 0, stdout="hostname realhost\n", stderr="")
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="")
    return run


def test_go_absent_disables_build(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.subprocess, "run", _fake_run({}))
    monkeypatch.setattr(probe.shutil, "which", lambda n: None)
    assert detect(tmp_path).go is False


def test_go_present_enables_build(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.subprocess, "run", _fake_run({"go": 0}))
    monkeypatch.setattr(probe.shutil, "which", lambda n: None)
    assert detect(tmp_path).go is True


def test_signing_requires_both_pfx_and_osslsigncode(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.subprocess, "run", _fake_run({}))
    certs = tmp_path / "signing-certs"
    certs.mkdir()

    # osslsigncode present, PFX missing
    monkeypatch.setattr(probe.shutil, "which", lambda n: "/usr/bin/osslsigncode")
    assert detect(tmp_path).signing is False

    # both present
    (certs / "F0RT1KA.pfx").write_bytes(b"x")
    assert detect(tmp_path).signing is True

    # PFX present, osslsigncode missing
    monkeypatch.setattr(probe.shutil, "which", lambda n: None)
    assert detect(tmp_path).signing is False


def test_ssh_aliases_only_include_resolvable(tmp_path, monkeypatch):
    def run(cmd, *a, **kw):
        if cmd[0] == "ssh" and "debian" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="hostname localhost\n", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")
    monkeypatch.setattr(probe.subprocess, "run", run)
    monkeypatch.setattr(probe.shutil, "which", lambda n: None)
    assert detect(tmp_path).ssh_aliases == ["debian"]


def test_probe_failure_never_raises(tmp_path, monkeypatch):
    """A probe that explodes disables a capability; it must not kill startup."""
    def boom(*a, **kw):
        raise OSError("no such binary")
    monkeypatch.setattr(probe.subprocess, "run", boom)
    monkeypatch.setattr(probe.shutil, "which", lambda n: None)
    caps = detect(tmp_path)
    assert isinstance(caps, Capabilities)
    assert caps.go is False and caps.ssh_aliases == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && uv run pytest tests/test_probe.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'f0_library_mcp.probe'`

- [ ] **Step 3: Implement probe.py**

```python
# mcp_server/src/f0_library_mcp/probe.py
"""Host capability detection.

Runs once at startup, before initialize responds, so the advertised tool list
reflects what this host can actually do. Probes are best-effort: a failure
disables a capability, it never crashes the server.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

LAB_ALIASES: tuple[str, ...] = ("debian", "win", "mac")
_TIMEOUT = 5


class Capabilities(BaseModel):
    go: bool = False
    signing: bool = False
    ssh_aliases: list[str] = Field(default_factory=list)


def _ok(cmd: list[str]) -> bool:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=_TIMEOUT
        ).returncode == 0
    except Exception:
        return False


def _alias_resolves(alias: str) -> bool:
    """ssh -G prints the effective config; exit 0 means the alias is known."""
    try:
        proc = subprocess.run(
            ["ssh", "-G", alias], capture_output=True, text=True, timeout=_TIMEOUT
        )
    except Exception:
        return False
    return proc.returncode == 0 and "hostname" in proc.stdout


def detect(root: Path) -> Capabilities:
    root = Path(root)
    pfx = root / "signing-certs" / "F0RT1KA.pfx"
    try:
        pfx_ok = pfx.is_file()
    except Exception:
        pfx_ok = False

    return Capabilities(
        go=_ok(["go", "version"]),
        signing=pfx_ok and shutil.which("osslsigncode") is not None,
        ssh_aliases=[a for a in LAB_ALIASES if _alias_resolves(a)],
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd mcp_server && uv run pytest tests/test_probe.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add mcp_server/src/f0_library_mcp/probe.py mcp_server/tests/test_probe.py
git commit -m "feat(mcp): add host capability probe for tool gating"
```

---

### Task 5: Server assembly and Tier A catalog tools

**Files:**
- Create: `mcp_server/src/f0_library_mcp/tools/catalog_tools.py`
- Create: `mcp_server/src/f0_library_mcp/server.py`
- Test: `mcp_server/tests/test_tools_catalog.py`

**Interfaces:**
- Consumes: `config.resolve_root`, `catalog.get_index/TestRecord/Anomaly`, `probe.detect/Capabilities`.
- Produces:
  - In `tools.catalog_tools`: `register(server, root)` plus response models `TestRow`, `ListTestsResult`, `GetTestResult`, `CoverageEntry`, `CoverageResult`.
  - In `server.py`: `build_server(root: Path | None = None, caps: Capabilities | None = None) -> MCPServer` and `main() -> None`.
- `build_server` accepts an injected `caps` so tests can simulate hosts without shelling out.

- [ ] **Step 1: Write the failing test**

```python
# mcp_server/tests/test_tools_catalog.py
import pytest
from mcp import Client

from f0_library_mcp.server import build_server
from f0_library_mcp.probe import Capabilities

NO_CAPS = Capabilities(go=False, signing=False, ssh_aliases=[])
FULL_CAPS = Capabilities(go=True, signing=True, ssh_aliases=["debian", "win"])


async def test_tier_a_always_advertised():
    async with Client(build_server(caps=NO_CAPS)) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert {"list_tests", "get_test", "mitre_coverage",
            "validate_test", "validate_results"} <= names


async def test_tier_b_hidden_without_capabilities():
    async with Client(build_server(caps=NO_CAPS)) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert "build_test" not in names
    assert "deploy_and_run" not in names


async def test_tier_b_advertised_with_capabilities():
    async with Client(build_server(caps=FULL_CAPS)) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert "build_test" in names
    assert "deploy_and_run" in names


async def test_list_tests_returns_full_corpus():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool("list_tests", {})
    assert r.structured_content["total"] == 58
    assert set(r.structured_content["categories"]) == {
        "intel-driven", "cyber-hygiene", "mitre-top10"}


async def test_list_tests_filters_by_technique():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool("list_tests", {"technique": "T1562.001"})
    rows = r.structured_content["tests"]
    assert rows
    assert all("T1562.001" in row["techniques"] for row in rows)


async def test_list_tests_query_is_case_insensitive():
    async with Client(build_server(caps=NO_CAPS)) as c:
        lo = await c.call_tool("list_tests", {"query": "ransomware"})
        hi = await c.call_tool("list_tests", {"query": "RANSOMWARE"})
    assert lo.structured_content["total"] == hi.structured_content["total"]


async def test_get_test_returns_record():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool(
            "get_test", {"uuid": "e5577355-f8e4-4e52-b1b2-f7d1c8b864f1"})
    assert r.structured_content["found"] is True
    assert r.structured_content["test"]["techniques"] == ["T1562.001"]


async def test_get_test_names_artifact_shell_explicitly():
    """A shell must not read as 'not found' -- that leaves the caller guessing."""
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool(
            "get_test", {"uuid": "56475cb3-febc-45ac-a0af-39bc5ca1c15f"})
    sc = r.structured_content
    assert sc["found"] is False
    assert sc["reason"] == "artifact_shell"
    assert sc["anomaly"]["contents"] == ["build"]


async def test_get_test_unknown_uuid():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool("get_test", {"uuid": "00000000-0000-0000-0000-000000000000"})
    assert r.structured_content["found"] is False
    assert r.structured_content["reason"] == "not_found"


async def test_mitre_coverage_reconciles_with_list_tests():
    async with Client(build_server(caps=NO_CAPS)) as c:
        cov = (await c.call_tool("mitre_coverage", {})).structured_content
        lst = (await c.call_tool("list_tests", {})).structured_content
    assert cov["total_tests"] == lst["total"]
    for entry in cov["entries"]:
        assert entry["test_count"] == len(entry["test_uuids"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && uv run pytest tests/test_tools_catalog.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'f0_library_mcp.server'`

- [ ] **Step 3: Implement catalog_tools.py**

```python
# mcp_server/src/f0_library_mcp/tools/catalog_tools.py
"""Tier A catalog tools. Portable: pure functions of the repo contents."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from pydantic import BaseModel, Field

from ..catalog import Anomaly, TestRecord, get_index


class TestRow(BaseModel):
    uuid: str
    name: str
    category: str
    techniques: list[str]
    severity: str
    score: float | None


class ListTestsResult(BaseModel):
    total: int
    returned: int
    categories: list[str]
    tests: list[TestRow]


class GetTestResult(BaseModel):
    found: bool
    reason: str = ""
    test: TestRecord | None = None
    anomaly: Anomaly | None = None


class CoverageEntry(BaseModel):
    key: str
    test_count: int
    test_uuids: list[str]


class CoverageResult(BaseModel):
    group_by: str
    total_tests: int
    distinct_keys: int
    entries: list[CoverageEntry]


def _matches(rec: TestRecord, *, technique, tactic, actor, platform,
             severity, subcategory, category, query) -> bool:
    if category and rec.category != category:
        return False
    if technique and technique not in rec.techniques:
        return False
    if tactic and tactic not in rec.tactics:
        return False
    if actor and rec.threat_actor.lower() != actor.lower():
        return False
    if platform and not any(platform.lower() in t.lower() for t in rec.target):
        return False
    if severity and rec.severity.lower() != severity.lower():
        return False
    if subcategory and rec.subcategory.lower() != subcategory.lower():
        return False
    if query:
        hay = " ".join([rec.name, rec.threat_actor, *rec.tags, *rec.techniques]).lower()
        if query.lower() not in hay:
            return False
    return True


def register(server, root: Path) -> None:
    @server.tool(
        description=(
            "List F0RT1KA security tests, optionally filtered. All filters are "
            "AND-combined. `platform` matches the TARGET field; `query` is a "
            "case-insensitive substring over name, actor, tags and techniques."
        )
    )
    def list_tests(
        category: str | None = None,
        technique: str | None = None,
        tactic: str | None = None,
        actor: str | None = None,
        platform: str | None = None,
        severity: str | None = None,
        subcategory: str | None = None,
        query: str | None = None,
        limit: int = 200,
    ) -> ListTestsResult:
        index = get_index(root)
        hits = [r for r in index.tests if _matches(
            r, technique=technique, tactic=tactic, actor=actor, platform=platform,
            severity=severity, subcategory=subcategory, category=category, query=query)]
        rows = [TestRow(uuid=r.uuid, name=r.name, category=r.category,
                        techniques=r.techniques, severity=r.severity, score=r.score)
                for r in hits[:limit]]
        return ListTestsResult(
            total=len(hits),
            returned=len(rows),
            categories=sorted({r.category for r in index.tests}),
            tests=rows,
        )

    @server.tool(
        description=(
            "Full detail for one test by UUID. If the UUID names a directory "
            "that exists but holds no source, returns found=false with "
            "reason='artifact_shell' and the directory contents."
        )
    )
    def get_test(uuid: str) -> GetTestResult:
        index = get_index(root)
        for rec in index.tests:
            if rec.uuid == uuid:
                return GetTestResult(found=True, test=rec)
        for anom in index.anomalies:
            if anom.uuid == uuid:
                return GetTestResult(found=False, reason="artifact_shell", anomaly=anom)
        return GetTestResult(found=False, reason="not_found")

    @server.tool(
        description=(
            "MITRE ATT&CK coverage across the corpus, grouped by technique or "
            "tactic. Artifact shells are excluded -- they are not tests."
        )
    )
    def mitre_coverage(
        group_by: str = "technique",
        category: str | None = None,
    ) -> CoverageResult:
        if group_by not in ("technique", "tactic"):
            raise ValueError("group_by must be 'technique' or 'tactic'")
        index = get_index(root)
        tests = [r for r in index.tests if not category or r.category == category]
        buckets: dict[str, list[str]] = defaultdict(list)
        for rec in tests:
            for key in (rec.techniques if group_by == "technique" else rec.tactics):
                buckets[key].append(rec.uuid)
        entries = [CoverageEntry(key=k, test_count=len(v), test_uuids=sorted(v))
                   for k, v in sorted(buckets.items(),
                                      key=lambda kv: (-len(kv[1]), kv[0]))]
        return CoverageResult(
            group_by=group_by,
            total_tests=len(tests),
            distinct_keys=len(entries),
            entries=entries,
        )
```

- [ ] **Step 4: Implement server.py**

```python
# mcp_server/src/f0_library_mcp/server.py
"""MCPServer assembly.

Tier B tools are registered conditionally, so tools/list reflects what this
host can actually do rather than advertising tools that fail on invocation.
"""
from __future__ import annotations

import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from .config import RootNotFoundError, resolve_root
from .probe import Capabilities, detect
from .tools import catalog_tools

INSTRUCTIONS = """\
F0RT1KA security-test library. Query the test catalog, inspect MITRE ATT&CK
coverage, and validate tests against Schema v2.0 and the ProjectAchilles
metadata contract. On a configured build host, also compile/sign tests and
execute them on lab endpoints.

This server does not author tests -- that is the sectest-builder agent's job.
See the `build_sectest` prompt for the authoring workflow.
"""


def build_server(root: Path | None = None,
                 caps: Capabilities | None = None) -> MCPServer:
    root = resolve_root(root)
    if caps is None:
        caps = detect(root)

    server = MCPServer(
        name="f0_library",
        version="0.1.0",
        instructions=INSTRUCTIONS,
    )

    catalog_tools.register(server, root)

    from .tools import validate_tools
    validate_tools.register(server, root)

    if caps.go:
        from .tools import build_tools
        build_tools.register(server, root, caps)

    if caps.ssh_aliases:
        from .tools import deploy_tools
        deploy_tools.register(server, root, caps)

    from . import resources, prompts
    resources.register(server, root)
    prompts.register(server, root)

    return server


def main() -> None:
    try:
        server = build_server()
    except RootNotFoundError as exc:
        print(f"f0_library MCP server failed to start: {exc}", file=sys.stderr)
        raise SystemExit(1)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
```

Note: `validate_tools`, `build_tools`, `deploy_tools`, `resources`, and
`prompts` are created in Tasks 6-9. Until then, create empty stubs so the
import succeeds:

```python
# each of tools/validate_tools.py, tools/build_tools.py, tools/deploy_tools.py
def register(server, root, caps=None) -> None:  # pragma: no cover - replaced in later task
    pass
```

```python
# each of resources.py, prompts.py
def register(server, root) -> None:  # pragma: no cover - replaced in later task
    pass
```

Task 5's test asserts `validate_test`/`validate_results` are advertised, so
those two are implemented in Task 6; run Task 5's suite with those two
assertions xfailed until Task 6 lands, or implement Tasks 5 and 6 back to back.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd mcp_server && uv run pytest tests/test_tools_catalog.py -v`
Expected: all pass except the two Tier A validate assertions, which pass after Task 6.

- [ ] **Step 6: Commit**

```bash
git add mcp_server/src/f0_library_mcp/server.py \
        mcp_server/src/f0_library_mcp/tools/catalog_tools.py \
        mcp_server/tests/test_tools_catalog.py
git commit -m "feat(mcp): add server assembly and Tier A catalog tools"
```

---

### Task 6: Validation tools

**Files:**
- Create: `mcp_server/src/f0_library_mcp/tools/validate_tools.py` (replaces the Task 5 stub)
- Test: `mcp_server/tests/test_tools_validate.py`

**Interfaces:**
- Consumes: `catalog.get_index`, `catalog.REQUIRED_HEADER_FIELDS`, `classify.classify`.
- Produces: `register(server, root)` plus models `Finding`, `ValidateTestResult`, `ValidateResultsResult`.
- Reuses the repo's own validator by importing it, not by subprocessing:
  `utils/validate_test_results.py` exposes `load_schema()`, `validate_test_result(result, schema)`, `perform_additional_checks(result)`.

- [ ] **Step 1: Write the failing test**

```python
# mcp_server/tests/test_tools_validate.py
import json
import pytest
from mcp import Client

from f0_library_mcp.server import build_server
from f0_library_mcp.probe import Capabilities

NO_CAPS = Capabilities(go=False, signing=False, ssh_aliases=[])


async def test_validate_test_passes_on_known_good():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool(
            "validate_test", {"uuid": "e5577355-f8e4-4e52-b1b2-f7d1c8b864f1"})
    sc = r.structured_content
    assert sc["found"] is True
    assert [f for f in sc["findings"] if f["severity"] == "error"] == []


async def test_validate_test_reports_missing_uuid():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool("validate_test", {"uuid": "00000000-0000-0000-0000-000000000000"})
    assert r.structured_content["found"] is False


async def test_validate_results_rejects_both_inputs():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool("validate_results", {"path": "/x", "content": "{}"})
    assert r.structured_content["ok"] is False
    assert "exactly one" in r.structured_content["error"].lower()


async def test_validate_results_rejects_neither_input():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool("validate_results", {})
    assert r.structured_content["ok"] is False
    assert "exactly one" in r.structured_content["error"].lower()


async def test_validate_results_classifies_exit_code():
    payload = json.dumps({"exitCode": 126})
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool("validate_results", {"content": payload})
    assert r.structured_content["verdict"]["verdict"] == "execution_prevented"


async def test_validate_results_unknown_code_is_not_a_block():
    payload = json.dumps({"exitCode": 42})
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool("validate_results", {"content": payload})
    v = r.structured_content["verdict"]
    assert v["verdict"] == "unknown"
    assert v["protected"] is not True


async def test_validate_results_reports_malformed_json():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool("validate_results", {"content": "{not json"})
    assert r.structured_content["ok"] is False
    assert "json" in r.structured_content["error"].lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && uv run pytest tests/test_tools_validate.py -v`
Expected: FAIL — tools `validate_test` / `validate_results` not found (stub registers nothing)

- [ ] **Step 3: Implement validate_tools.py**

```python
# mcp_server/src/f0_library_mcp/tools/validate_tools.py
"""Tier A validation tools.

Imports the repo's own validator rather than subprocessing it, so schema
changes in utils/validate_test_results.py propagate here automatically.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

from pydantic import BaseModel, Field

from ..catalog import REQUIRED_HEADER_FIELDS, get_index
from ..classify import Verdict, classify

_README_SCORE = re.compile(r"^\*\*Test Score\*\*:\s*\*\*([0-9]+\.[0-9]+)/10\*\*", re.M)
_INFO_SCORE = re.compile(r"^## Test Score:\s*([0-9]+\.[0-9]+)/10", re.M)

_BASE_REQUIRED = ("README.md", "test_logger.go", "org_resolver.go", "go.mod")


class Finding(BaseModel):
    severity: str          # "error" | "warning"
    check: str
    message: str


class ValidateTestResult(BaseModel):
    found: bool
    uuid: str
    findings: list[Finding] = Field(default_factory=list)


class ValidateResultsResult(BaseModel):
    ok: bool
    error: str = ""
    schema_errors: list[str] = Field(default_factory=list)
    check_errors: list[str] = Field(default_factory=list)
    verdict: Verdict | None = None


def _load_repo_validator(root: Path):
    """Import utils/validate_test_results.py by path (it is not a package)."""
    path = root / "utils" / "validate_test_results.py"
    spec = importlib.util.spec_from_file_location("f0_repo_validator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def register(server, root: Path, caps=None) -> None:
    @server.tool(
        description=(
            "Validate one test's package: required files, README/info-card score "
            "agreement, and metadata-header completeness against the "
            "ProjectAchilles ingestion contract."
        )
    )
    def validate_test(uuid: str) -> ValidateTestResult:
        index = get_index(root)
        rec = next((r for r in index.tests if r.uuid == uuid), None)
        if rec is None:
            return ValidateTestResult(found=False, uuid=uuid)

        findings: list[Finding] = []
        test_dir = Path(rec.path)

        for required in _BASE_REQUIRED:
            if not (test_dir / required).is_file():
                findings.append(Finding(severity="error", check="required_files",
                                        message=f"missing {required}"))
        info_cards = list(test_dir.glob("*_info.md"))
        if not info_cards:
            findings.append(Finding(severity="error", check="required_files",
                                    message="missing <uuid>_info.md"))

        for field in REQUIRED_HEADER_FIELDS:
            if field in rec.header_missing:
                findings.append(Finding(severity="error", check="metadata_header",
                                        message=f"header field {field} missing or empty"))

        readme = test_dir / "README.md"
        readme_score = None
        if readme.is_file():
            m = _README_SCORE.search(readme.read_text(errors="replace"))
            if m:
                readme_score = m.group(1)
            else:
                findings.append(Finding(severity="error", check="score_format",
                                        message="README.md lacks '**Test Score**: **X.X/10**'"))
        info_score = None
        if info_cards:
            m = _INFO_SCORE.search(info_cards[0].read_text(errors="replace"))
            if m:
                info_score = m.group(1)
            else:
                findings.append(Finding(severity="error", check="score_format",
                                        message="info card lacks '## Test Score: X.X/10'"))
        if readme_score and info_score and readme_score != info_score:
            findings.append(Finding(
                severity="error", check="score_consistency",
                message=f"score mismatch: README {readme_score} vs info card {info_score}"))

        return ValidateTestResult(found=True, uuid=uuid, findings=findings)

    @server.tool(
        description=(
            "Validate a test-results JSON against Schema v2.0 and classify its "
            "exit code. Supply exactly one of `path` or `content`."
        )
    )
    def validate_results(path: str | None = None,
                         content: str | None = None) -> ValidateResultsResult:
        if (path is None) == (content is None):
            return ValidateResultsResult(
                ok=False, error="Supply exactly one of `path` or `content`.")

        raw = content
        if path is not None:
            target = Path(path)
            if not target.is_file():
                return ValidateResultsResult(ok=False, error=f"no such file: {path}")
            raw = target.read_text(errors="replace")

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            return ValidateResultsResult(ok=False, error=f"invalid JSON: {exc}")

        validator = _load_repo_validator(root)
        schema = validator.load_schema()
        schema_ok, schema_errors = validator.validate_test_result(payload, schema)
        checks_ok, check_errors = validator.perform_additional_checks(payload)

        code = payload.get("exitCode", payload.get("exit_code"))
        verdict = classify(int(code)) if isinstance(code, (int, str)) and str(code).lstrip("-").isdigit() else None

        return ValidateResultsResult(
            ok=bool(schema_ok and checks_ok),
            schema_errors=list(schema_errors),
            check_errors=list(check_errors),
            verdict=verdict,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd mcp_server && uv run pytest tests/ -v`
Expected: all green, including the two Task 5 assertions that were pending.

- [ ] **Step 5: Commit**

```bash
git add mcp_server/src/f0_library_mcp/tools/validate_tools.py \
        mcp_server/tests/test_tools_validate.py
git commit -m "feat(mcp): add validate_test and validate_results tools"
```

---

### Task 7: Tier B build tool

**Files:**
- Create: `mcp_server/src/f0_library_mcp/tools/build_tools.py` (replaces the Task 5 stub)
- Test: `mcp_server/tests/test_tools_build.py`

**Interfaces:**
- Consumes: `catalog.get_index`, `probe.Capabilities`.
- Produces: `register(server, root, caps)`, models `BuildResult`, and `size_tier(nbytes: int) -> str`.
- Wraps `utils/gobuild`, whose CLI is: `gobuild [--org <id>] [--os <os>] [--arch <arch>] build|build-sign <test-path>`. Output lands at `build/<uuid>/<uuid>[.exe]`.

- [ ] **Step 1: Write the failing test**

```python
# mcp_server/tests/test_tools_build.py
import subprocess
import pytest
from mcp import Client

import f0_library_mcp.tools.build_tools as bt
from f0_library_mcp.server import build_server
from f0_library_mcp.probe import Capabilities

GO_CAPS = Capabilities(go=True, signing=True, ssh_aliases=[])
NO_SIGN_CAPS = Capabilities(go=True, signing=False, ssh_aliases=[])
UUID = "e5577355-f8e4-4e52-b1b2-f7d1c8b864f1"


@pytest.mark.parametrize("mb,tier", [
    (1, "green"), (10, "green"), (11, "yellow"), (25, "yellow"),
    (26, "red"), (50, "red"), (51, "forbidden"), (80, "forbidden"),
])
def test_size_tier_boundaries(mb, tier):
    assert bt.size_tier(mb * 1024 * 1024) == tier


async def test_build_test_invokes_gobuild(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="built ok", stderr="")

    monkeypatch.setattr(bt.subprocess, "run", fake_run)
    monkeypatch.setattr(bt, "_locate_artifact", lambda root, uuid: None)

    async with Client(build_server(caps=GO_CAPS)) as c:
        r = await c.call_tool("build_test", {"uuid": UUID})

    assert r.structured_content["ok"] is True
    assert calls, "gobuild was never invoked"
    assert "build" in calls[0]
    assert any(UUID in part for part in calls[0])


async def test_build_test_signs_when_org_given(monkeypatch):
    calls = []
    monkeypatch.setattr(bt.subprocess, "run",
                        lambda cmd, *a, **kw: (calls.append(cmd),
                                               subprocess.CompletedProcess(cmd, 0, "", ""))[1])
    monkeypatch.setattr(bt, "_locate_artifact", lambda root, uuid: None)

    async with Client(build_server(caps=GO_CAPS)) as c:
        await c.call_tool("build_test", {"uuid": UUID, "org": "sb"})

    assert "build-sign" in calls[0]
    assert "--org" in calls[0] and "sb" in calls[0]


async def test_build_test_surfaces_failure_output(monkeypatch):
    """A failed build must be diagnosable from the tool response alone."""
    monkeypatch.setattr(bt.subprocess, "run",
                        lambda cmd, *a, **kw: subprocess.CompletedProcess(
                            cmd, 2, stdout="", stderr="undefined: fooBar"))
    monkeypatch.setattr(bt, "_locate_artifact", lambda root, uuid: None)

    async with Client(build_server(caps=GO_CAPS)) as c:
        r = await c.call_tool("build_test", {"uuid": UUID})

    sc = r.structured_content
    assert sc["ok"] is False
    assert sc["exit_code"] == 2
    assert "undefined: fooBar" in sc["stderr"]


async def test_build_test_refuses_signing_without_capability(monkeypatch):
    """Requesting `org` on a host with no PFX/osslsigncode must fail fast, not shell out."""
    monkeypatch.setattr(bt.subprocess, "run",
                        lambda *a, **kw: pytest.fail("must not shell out"))
    async with Client(build_server(caps=NO_SIGN_CAPS)) as c:
        r = await c.call_tool("build_test", {"uuid": UUID, "org": "sb"})
    assert r.structured_content["ok"] is False
    assert "signing" in r.structured_content["error"].lower()


async def test_build_test_rejects_unknown_uuid(monkeypatch):
    monkeypatch.setattr(bt.subprocess, "run",
                        lambda *a, **kw: pytest.fail("must not shell out"))
    async with Client(build_server(caps=GO_CAPS)) as c:
        r = await c.call_tool("build_test", {"uuid": "00000000-0000-0000-0000-000000000000"})
    assert r.structured_content["ok"] is False
    assert "not found" in r.structured_content["error"].lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && uv run pytest tests/test_tools_build.py -v`
Expected: FAIL — `AttributeError: module has no attribute 'size_tier'`

- [ ] **Step 3: Implement build_tools.py**

```python
# mcp_server/src/f0_library_mcp/tools/build_tools.py
"""Tier B build tool. Registered only when `go` is on PATH.

Reports the binary size tier but never refuses to build: per CLAUDE.md the
size budget encodes preference, not impossibility.
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from pydantic import BaseModel

from ..catalog import get_index

MB = 1024 * 1024
_TIERS = ((10 * MB, "green"), (25 * MB, "yellow"), (50 * MB, "red"))
_TIMEOUT = 900


class BuildResult(BaseModel):
    ok: bool
    error: str = ""
    uuid: str = ""
    command: list[str] = []
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    artifact_path: str = ""
    size_bytes: int | None = None
    size_tier: str = ""
    sha1: str = ""
    signed: bool = False


def size_tier(nbytes: int) -> str:
    """Budget tier per CLAUDE.md: <=10MB green, <=25 yellow, <=50 red, else forbidden."""
    for limit, name in _TIERS:
        if nbytes <= limit:
            return name
    return "forbidden"


def _locate_artifact(root: Path, uuid: str) -> Path | None:
    out_dir = Path(root) / "build" / uuid
    if not out_dir.is_dir():
        return None
    candidates = [p for p in out_dir.iterdir() if p.is_file() and p.stem == uuid]
    return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None


def register(server, root: Path, caps=None) -> None:
    can_sign = bool(caps and caps.signing)

    @server.tool(
        description=(
            "Build (and optionally sign) a test via utils/gobuild. Returns the "
            "artifact path, SHA1, byte size and budget tier. Supplying `org` "
            "(sb|tpsgl|rga) switches to build-sign, which additionally requires "
            "the signing capability (F0RT1KA.pfx readable, osslsigncode present)."
        )
    )
    def build_test(uuid: str,
                   org: str | None = None,
                   os_target: str = "windows",
                   arch: str = "amd64") -> BuildResult:
        rec = next((r for r in get_index(root).tests if r.uuid == uuid), None)
        if rec is None:
            return BuildResult(ok=False, uuid=uuid,
                               error=f"test not found in catalog: {uuid}")
        if org and not can_sign:
            return BuildResult(
                ok=False, uuid=uuid,
                error=("signing requested but this host lacks the signing "
                       "capability (needs signing-certs/F0RT1KA.pfx and "
                       "osslsigncode); re-run without `org` to build unsigned"))

        cmd = [str(Path(root) / "utils" / "gobuild")]
        if org:
            cmd += ["--org", org]
        cmd += ["--os", os_target, "--arch", arch,
                "build-sign" if org else "build", rec.path]

        try:
            proc = subprocess.run(cmd, cwd=str(root), capture_output=True,
                                  text=True, timeout=_TIMEOUT)
        except subprocess.TimeoutExpired:
            return BuildResult(ok=False, uuid=uuid, command=cmd,
                               error=f"gobuild exceeded {_TIMEOUT}s")

        result = BuildResult(
            ok=proc.returncode == 0,
            uuid=uuid,
            command=cmd,
            exit_code=proc.returncode,
            stdout=proc.stdout[-8000:],
            stderr=proc.stderr[-8000:],
            signed=bool(org),
        )
        artifact = _locate_artifact(root, uuid)
        if artifact is not None:
            data = artifact.read_bytes()
            result.artifact_path = str(artifact)
            result.size_bytes = len(data)
            result.size_tier = size_tier(len(data))
            result.sha1 = hashlib.sha1(data).hexdigest()
        return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd mcp_server && uv run pytest tests/test_tools_build.py -v`
Expected: 13 passed (8 tier params + 5 behaviours). No real build runs.

- [ ] **Step 5: Commit**

```bash
git add mcp_server/src/f0_library_mcp/tools/build_tools.py mcp_server/tests/test_tools_build.py
git commit -m "feat(mcp): add gated build_test tool with size-budget tiering"
```

---

### Task 8: Tier B deploy tool

**Files:**
- Create: `mcp_server/src/f0_library_mcp/tools/deploy_tools.py` (replaces the Task 5 stub)
- Test: `mcp_server/tests/test_tools_deploy.py`

**Interfaces:**
- Consumes: `catalog.get_index`, `classify.classify`, `probe.Capabilities`.
- Produces: `register(server, root, caps)`, model `DeployResult`, and `PLATFORMS: dict[str, PlatformSpec]`.
- Reproduces the `sectest-deploy` skill's procedure: clean remote dir, provision `ARTIFACT_DIR` with `chmod 777` on Linux/macOS, scp, `chmod +x`, execute, capture exit code.

- [ ] **Step 1: Write the failing test**

```python
# mcp_server/tests/test_tools_deploy.py
import subprocess
import pytest
from mcp import Client

import f0_library_mcp.tools.deploy_tools as dt
from f0_library_mcp.server import build_server
from f0_library_mcp.probe import Capabilities

CAPS = Capabilities(go=False, signing=False, ssh_aliases=["debian", "win"])
UUID = "e5577355-f8e4-4e52-b1b2-f7d1c8b864f1"


async def test_confirm_host_mismatch_blocks_before_any_subprocess(monkeypatch):
    """The guard must fire before anything touches the network."""
    monkeypatch.setattr(dt.subprocess, "run",
                        lambda *a, **kw: pytest.fail("subprocess ran despite mismatch"))
    async with Client(build_server(caps=CAPS)) as c:
        r = await c.call_tool("deploy_and_run",
                              {"uuid": UUID, "host": "win", "confirm_host": "debian"})
    sc = r.structured_content
    assert sc["ok"] is False
    assert "confirm_host" in sc["error"]


async def test_unresolvable_host_rejected(monkeypatch):
    monkeypatch.setattr(dt.subprocess, "run",
                        lambda *a, **kw: pytest.fail("subprocess ran for unknown host"))
    async with Client(build_server(caps=CAPS)) as c:
        r = await c.call_tool("deploy_and_run",
                              {"uuid": UUID, "host": "mac", "confirm_host": "mac"})
    assert r.structured_content["ok"] is False
    assert "not available" in r.structured_content["error"].lower()


async def test_linux_deploy_provisions_artifact_dir(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, *a, **kw):
        calls.append(" ".join(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="EXIT_CODE: 101\n", stderr="")

    monkeypatch.setattr(dt.subprocess, "run", fake_run)
    artifact = tmp_path / UUID
    artifact.write_bytes(b"binary")
    monkeypatch.setattr(dt, "_find_binary", lambda root, uuid, plat: artifact)

    async with Client(build_server(caps=CAPS)) as c:
        r = await c.call_tool("deploy_and_run",
                              {"uuid": UUID, "host": "debian", "confirm_host": "debian"})

    joined = "\n".join(calls)
    assert "/home/fortika-test" in joined
    assert "chmod 777" in joined
    assert r.structured_content["exit_code"] == 101
    assert r.structured_content["verdict"]["verdict"] == "unprotected"


async def test_unknown_remote_exit_code_is_not_a_block(monkeypatch, tmp_path):
    def fake_run(cmd, *a, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout="EXIT_CODE: 42\n", stderr="")
    monkeypatch.setattr(dt.subprocess, "run", fake_run)
    artifact = tmp_path / UUID
    artifact.write_bytes(b"binary")
    monkeypatch.setattr(dt, "_find_binary", lambda root, uuid, plat: artifact)

    async with Client(build_server(caps=CAPS)) as c:
        r = await c.call_tool("deploy_and_run",
                              {"uuid": UUID, "host": "debian", "confirm_host": "debian"})
    v = r.structured_content["verdict"]
    assert v["verdict"] == "unknown"
    assert v["protected"] is not True


async def test_missing_binary_reported_not_deployed(monkeypatch):
    monkeypatch.setattr(dt, "_find_binary", lambda root, uuid, plat: None)
    monkeypatch.setattr(dt.subprocess, "run",
                        lambda *a, **kw: pytest.fail("deployed without a binary"))
    async with Client(build_server(caps=CAPS)) as c:
        r = await c.call_tool("deploy_and_run",
                              {"uuid": UUID, "host": "debian", "confirm_host": "debian"})
    assert r.structured_content["ok"] is False
    assert "build" in r.structured_content["error"].lower()


def test_exit_code_parser():
    assert dt._parse_exit_code("noise\nEXIT_CODE: 126\n") == 126
    assert dt._parse_exit_code("EXIT_CODE: 0") == 0
    assert dt._parse_exit_code("no marker here") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && uv run pytest tests/test_tools_deploy.py -v`
Expected: FAIL — `AttributeError: module has no attribute '_parse_exit_code'`

- [ ] **Step 3: Implement deploy_tools.py**

```python
# mcp_server/src/f0_library_mcp/tools/deploy_tools.py
"""Tier B deploy tool. Registered only when at least one lab alias resolves.

Mirrors the sectest-deploy skill. The ARTIFACT_DIR chmod on Linux/macOS is
mandatory: the test runs as a normal user but writes decoys into a root-owned
directory, and skipping it yields exit 999 -- a lab-setup failure that would
otherwise be misread as a prerequisite problem in the test itself.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

from ..catalog import get_index
from ..classify import Verdict, classify

_EXIT_RE = re.compile(r"EXIT_CODE:\s*(-?\d+)")
_TIMEOUT = 600


class PlatformSpec(BaseModel):
    name: str
    remote_dir: str
    artifact_dir: str
    binary_suffix: str
    posix: bool


PLATFORMS: dict[str, PlatformSpec] = {
    "debian": PlatformSpec(name="linux", remote_dir="/opt/f0",
                           artifact_dir="/home/fortika-test",
                           binary_suffix="", posix=True),
    "mac": PlatformSpec(name="darwin", remote_dir="/opt/f0",
                        artifact_dir="/Users/fortika-test",
                        binary_suffix="", posix=True),
    "win": PlatformSpec(name="windows", remote_dir=r"c:\F0",
                        artifact_dir=r"c:\Users\fortika-test",
                        binary_suffix=".exe", posix=False),
}


class DeployResult(BaseModel):
    ok: bool
    error: str = ""
    uuid: str = ""
    host: str = ""
    steps: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    verdict: Verdict | None = None


def _parse_exit_code(stdout: str) -> int | None:
    matches = _EXIT_RE.findall(stdout or "")
    return int(matches[-1]) if matches else None


def _find_binary(root: Path, uuid: str, plat: PlatformSpec) -> Path | None:
    candidate = Path(root) / "build" / uuid / f"{uuid}{plat.binary_suffix}"
    return candidate if candidate.is_file() else None


def register(server, root: Path, caps=None) -> None:
    available = list(caps.ssh_aliases) if caps else []

    @server.tool(
        description=(
            "Deploy a built test to a lab endpoint and execute it. THIS DETONATES "
            "A REAL ATTACK SIMULATION on the target host. `confirm_host` must "
            f"exactly match `host`. Available hosts on this machine: {available}."
        )
    )
    def deploy_and_run(uuid: str, host: str, confirm_host: str) -> DeployResult:
        if host != confirm_host:
            return DeployResult(
                ok=False, uuid=uuid, host=host,
                error=(f"confirm_host {confirm_host!r} does not match host {host!r}; "
                       "refusing to deploy."))
        if host not in available:
            return DeployResult(
                ok=False, uuid=uuid, host=host,
                error=f"host {host!r} is not available on this machine; have {available}")
        if not any(r.uuid == uuid for r in get_index(root).tests):
            return DeployResult(ok=False, uuid=uuid, host=host,
                                error=f"test not found in catalog: {uuid}")

        plat = PLATFORMS[host]
        binary = _find_binary(root, uuid, plat)
        if binary is None:
            return DeployResult(
                ok=False, uuid=uuid, host=host,
                error=f"no binary at build/{uuid}/ -- run build_test first")

        steps: list[str] = []

        def sh(cmd: list[str]) -> subprocess.CompletedProcess:
            steps.append(" ".join(cmd))
            return subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)

        if plat.posix:
            sh(["ssh", host, f"sudo rm -rf {plat.remote_dir} && "
                             f"sudo mkdir -p {plat.remote_dir} && "
                             f"sudo chmod 777 {plat.remote_dir}"])
            sh(["ssh", host, f"sudo mkdir -p {plat.artifact_dir} && "
                             f"sudo chmod 777 {plat.artifact_dir}"])
            sh(["scp", str(binary), f"{host}:{plat.remote_dir}/"])
            sh(["ssh", host, f"chmod +x {plat.remote_dir}/{uuid}"])
            run = sh(["ssh", host, f"{plat.remote_dir}/{uuid}; echo EXIT_CODE: $?"])
        else:
            sh(["ssh", host, r"rmdir /s /q c:\F0 2>nul & mkdir c:\F0"])
            sh(["scp", str(binary), f"{host}:{plat.remote_dir}\\"])
            run = sh(["ssh", host,
                      f"{plat.remote_dir}\\{uuid}.exe & echo EXIT_CODE: %ERRORLEVEL%"])

        code = _parse_exit_code(run.stdout)
        return DeployResult(
            ok=code is not None,
            error="" if code is not None else "could not parse EXIT_CODE from remote output",
            uuid=uuid, host=host, steps=steps,
            exit_code=code,
            stdout=run.stdout[-16000:],
            stderr=run.stderr[-8000:],
            verdict=classify(code) if code is not None else None,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd mcp_server && uv run pytest tests/test_tools_deploy.py -v`
Expected: 6 passed. No SSH connection is made.

- [ ] **Step 5: Commit**

```bash
git add mcp_server/src/f0_library_mcp/tools/deploy_tools.py mcp_server/tests/test_tools_deploy.py
git commit -m "feat(mcp): add gated deploy_and_run tool with confirm_host guard"
```

---

### Task 9: Resources and prompts

**Files:**
- Create: `mcp_server/src/f0_library_mcp/resources.py` (replaces the Task 5 stub)
- Create: `mcp_server/src/f0_library_mcp/prompts.py` (replaces the Task 5 stub)
- Test: `mcp_server/tests/test_resources_prompts.py`

**Interfaces:**
- Consumes: `config.resolve_root`, `catalog.get_index`.
- Produces: `resources.register(server, root)` and `prompts.register(server, root)`.
- Resource URIs: `f0://schema/test-results-v2.0`, `f0://rubric/active`, `f0://registry/organizations`, `f0://test/{uuid}/{filename}`.

- [ ] **Step 1: Write the failing test**

```python
# mcp_server/tests/test_resources_prompts.py
import json
import pytest
from mcp import Client

from f0_library_mcp.server import build_server
from f0_library_mcp.probe import Capabilities

NO_CAPS = Capabilities(go=False, signing=False, ssh_aliases=[])
UUID = "e5577355-f8e4-4e52-b1b2-f7d1c8b864f1"


async def test_schema_resource_is_valid_json():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.read_resource("f0://schema/test-results-v2.0")
    assert json.loads(r.contents[0].text)


async def test_org_registry_resource_lists_known_orgs():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.read_resource("f0://registry/organizations")
    data = json.loads(r.contents[0].text)
    assert {o["shortName"] for o in data["organizations"]} >= {"sb", "tpsgl", "rga"}


async def test_test_file_resource_reads_readme():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.read_resource(f"f0://test/{UUID}/README.md")
    assert "Test Score" in r.contents[0].text


async def test_test_file_resource_rejects_traversal():
    async with Client(build_server(caps=NO_CAPS), raise_exceptions=False) as c:
        with pytest.raises(Exception):
            await c.read_resource(f"f0://test/{UUID}/../../../etc/passwd")


async def test_prompts_are_listed():
    async with Client(build_server(caps=NO_CAPS)) as c:
        names = {p.name for p in (await c.list_prompts()).prompts}
    assert {"build_sectest", "validate_sectest"} <= names


async def test_build_sectest_prompt_includes_source_and_rules():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.get_prompt("build_sectest", {"source": "https://example.com/apt-report"})
    text = " ".join(m.content.text for m in r.messages)
    assert "https://example.com/apt-report" in text
    assert "LOG_DIR" in text
    assert "sectest-builder" in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && uv run pytest tests/test_resources_prompts.py -v`
Expected: FAIL — unknown resource `f0://schema/test-results-v2.0`

- [ ] **Step 3: Implement resources.py**

```python
# mcp_server/src/f0_library_mcp/resources.py
"""Readable contracts: schema, rubric, org registry, and per-test files."""
from __future__ import annotations

from pathlib import Path

from .catalog import get_index

_RUBRIC = "docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md"


def register(server, root: Path) -> None:
    root = Path(root)

    @server.resource("f0://schema/test-results-v2.0",
                     name="Test Results Schema v2.0", mime_type="application/json")
    def schema() -> str:
        return (root / "test-results-schema-v2.0.json").read_text(errors="replace")

    @server.resource("f0://rubric/active",
                     name="Active scoring rubric (v2.1)", mime_type="text/markdown")
    def rubric() -> str:
        return (root / _RUBRIC).read_text(errors="replace")

    @server.resource("f0://registry/organizations",
                     name="Organization registry", mime_type="application/json")
    def organizations() -> str:
        return (root / "signing-certs" / "organization-registry.json").read_text(
            errors="replace")

    @server.resource("f0://test/{uuid}/{filename}",
                     name="Test file", mime_type="text/plain")
    def test_file(uuid: str, filename: str) -> str:
        rec = next((r for r in get_index(root).tests if r.uuid == uuid), None)
        if rec is None:
            raise ValueError(f"unknown test: {uuid}")
        base = Path(rec.path).resolve()
        target = (base / filename).resolve()
        if not target.is_relative_to(base):
            raise ValueError("path escapes the test directory")
        if not target.is_file():
            raise ValueError(f"no such file: {filename}")
        return target.read_text(errors="replace")
```

- [ ] **Step 4: Implement prompts.py**

```python
# mcp_server/src/f0_library_mcp/prompts.py
"""Workflow prompts.

These carry the sectest-builder and sectest-validation procedures to clients
that have no access to Claude Code agents. They describe the procedure; they
never attempt to invoke an agent. Inside Claude Code, the real agent remains
the correct entry point.
"""
from __future__ import annotations

from pathlib import Path

_BUILD = """\
You are building an F0RT1KA security test from threat intelligence.

SOURCE: {source}

Follow the sectest-builder four-phase workflow:

PHASE 1 (sequential)
  1. Source analysis   -- extract TTPs, assign UUID, pick platform and architecture
                          (1-2 techniques -> standard; 3+ -> multi-stage).
  2. Implementation    -- write Go source.
  3. Build & sign      -- compile, sign, verify.

PHASE 2 (parallel)
  documentation | detection rules (KQL, YARA, Sigma, EQL, LC D&R) |
  defense guidance | kill-chain diagram (multi-stage only)

PHASE 3  validation -> git commit
PHASE 3b deploy to a lab endpoint and interpret results

NON-NEGOTIABLE RULES
  - Binaries drop to LOG_DIR only: C:\\F0 (Windows) or /tmp/F0 (Linux/macOS).
  - Simulation artifacts go to ARTIFACT_DIR: c:\\Users\\fortika-test,
    /home/fortika-test, or /Users/fortika-test.
  - Single-binary deployment; embed dependencies with //go:embed.
  - Schema v2.0 InitLogger(testID, testName, metadata, executionContext).
  - Include the metadata comment header -- ProjectAchilles parses it at
    ingestion and silently drops fields that are missing.
  - Never hardcode exit codes. Evaluate actual results.
  - Never claim a block without positive evidence. Ambiguous outcomes are
    errors (999), never 126 or 105.

Use the `list_tests` tool first to check whether this technique is already
covered, and `f0://rubric/active` for the scoring rubric.
"""

_VALIDATE = """\
Validate the F0RT1KA test {uuid} before commit.

  1. Call validate_test with uuid={uuid} and resolve every "error" finding.
  2. Confirm required files exist for the test's TARGET platform.
  3. Confirm detection rules key on technique behaviour, not test artifacts
     (no test UUIDs, no /tmp/F0 or C:\\F0 paths in rule logic).
  4. Confirm the metadata header carries every field ProjectAchilles parses.
  5. Confirm README and info-card scores agree.

Report findings; do not silently fix scoring.
"""


def register(server, root: Path) -> None:
    @server.prompt(description="Workflow for building an F0RT1KA test from threat intel")
    def build_sectest(source: str) -> str:
        return _BUILD.format(source=source)

    @server.prompt(description="Pre-commit validation checklist for an F0RT1KA test")
    def validate_sectest(uuid: str) -> str:
        return _VALIDATE.format(uuid=uuid)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd mcp_server && uv run pytest tests/test_resources_prompts.py -v`
Expected: 6 passed

- [ ] **Step 6: Commit**

```bash
git add mcp_server/src/f0_library_mcp/resources.py \
        mcp_server/src/f0_library_mcp/prompts.py \
        mcp_server/tests/test_resources_prompts.py
git commit -m "feat(mcp): add contract resources and workflow prompts"
```

---

### Task 10: Wire-up — shared parser for get_tests.py, client registration, docs

**Files:**
- Modify: `utils/get_tests.py:28` and its `scan_tests`/`get_test_name` methods
- Modify: `.mcp.json`
- Create: `mcp_server/README.md`
- Test: `mcp_server/tests/test_get_tests_integration.py`

**Interfaces:**
- Consumes: `catalog.build_index`.
- Produces: no new Python API. `utils/get_tests.py` keeps its CLI contract (`python3 utils/get_tests.py [page]`).

- [ ] **Step 1: Write the failing test**

```python
# mcp_server/tests/test_get_tests_integration.py
import subprocess
import sys
from f0_library_mcp.config import resolve_root
from f0_library_mcp.catalog import build_index

ROOT = resolve_root()


def test_get_tests_reports_full_corpus():
    """utils/get_tests.py must agree with the shared parser -- one parser, no drift."""
    proc = subprocess.run(
        [sys.executable, "utils/get_tests.py", "--count"],
        cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == str(len(build_index(ROOT).tests))


def test_get_tests_covers_all_three_categories():
    proc = subprocess.run(
        [sys.executable, "utils/get_tests.py", "--json"],
        cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    import json
    cats = {row["category"] for row in json.loads(proc.stdout)}
    assert cats == {"intel-driven", "cyber-hygiene", "mitre-top10"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd mcp_server && uv run pytest tests/test_get_tests_integration.py -v`
Expected: FAIL — `get_tests.py` has no `--count` flag and reports 38 tests

- [ ] **Step 3: Rewrite get_tests.py over the shared parser**

Replace the whole file. It keeps the paged table output and gains `--count` / `--json`:

```python
#!/usr/bin/env python3
"""F0RT1KA Get Tests Utility.

Thin presentation layer over the MCP server's catalog parser. Categories are
discovered from the filesystem, so this cannot drift out of sync with the
corpus the way the previous hardcoded category list did.
"""
import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "mcp_server" / "src"))

from f0_library_mcp.catalog import build_index  # noqa: E402

TESTS_PER_PAGE = 10


def rows():
    index = build_index(REPO_ROOT)
    return [
        {
            "uuid": t.uuid,
            "category": t.category,
            "name": t.name or "(no name in header)",
            "techniques": ",".join(t.techniques),
            "severity": t.severity,
            "score": t.score,
        }
        for t in sorted(index.tests, key=lambda t: (t.category, t.name))
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="List F0RT1KA security tests")
    parser.add_argument("page", nargs="?", type=int, default=1)
    parser.add_argument("--count", action="store_true", help="print the test count only")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    data = rows()

    if args.count:
        print(len(data))
        return 0
    if args.json:
        print(json.dumps(data, indent=2))
        return 0

    total_pages = max(1, (len(data) + TESTS_PER_PAGE - 1) // TESTS_PER_PAGE)
    page = min(max(args.page, 1), total_pages)
    start = (page - 1) * TESTS_PER_PAGE
    chunk = data[start:start + TESTS_PER_PAGE]

    print(f"{'UUID':<38} {'CATEGORY':<15} {'SEV':<9} {'SCORE':<6} NAME")
    print("-" * 110)
    for row in chunk:
        score = f"{row['score']:.1f}" if row["score"] is not None else "-"
        print(f"{row['uuid']:<38} {row['category']:<15} "
              f"{row['severity']:<9} {score:<6} {row['name'][:44]}")
    print(f"\nPage {page}/{total_pages} — {len(data)} tests total")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd mcp_server && uv run pytest tests/test_get_tests_integration.py -v`
Expected: 2 passed

Also verify manually:
```bash
python3 utils/get_tests.py --count     # expect 58 (was 38)
python3 utils/get_tests.py 1           # table renders
```

- [ ] **Step 5: Register the server in .mcp.json**

Add the `f0_library` entry alongside the existing `MCP_DOCKER` entry (leave that one untouched):

```json
{
  "mcpServers": {
    "MCP_DOCKER": {
      "command": "powershell.exe",
      "args": ["-Command", "docker mcp gateway run"],
      "type": "stdio"
    },
    "f0_library": {
      "command": "uv",
      "args": ["run", "--directory", "${workspaceFolder}/mcp_server", "f0-library-mcp"],
      "type": "stdio",
      "env": { "F0_LIBRARY_ROOT": "${workspaceFolder}" }
    }
  }
}
```

If `${workspaceFolder}` does not expand in this client, substitute the
absolute path `/home/jimx/F0RT1KA/f0_library`.

- [ ] **Step 6: Write mcp_server/README.md**

Cover: what the server is, the Tier A/Tier B split and why, how capability
gating changes the advertised tool list per host, install (`uv sync`), client
configuration for Claude Code / Claude Desktop / ProjectAchilles, the
`F0_LIBRARY_ROOT` requirement, and an explicit note that this server does not
author tests — `sectest-builder` does, and the `build_sectest` prompt carries
that workflow to non-Claude-Code clients.

- [ ] **Step 7: Run the full suite**

Run: `cd mcp_server && uv run pytest -v`
Expected: all tests pass.

- [ ] **Step 8: Verify the server starts over real stdio**

```bash
cd mcp_server && uv run f0-library-mcp < /dev/null
```
Expected: exits without traceback (no stdin means no session; a clean exit
proves imports, root resolution and probe all succeed).

- [ ] **Step 9: Commit**

```bash
git add utils/get_tests.py .mcp.json mcp_server/README.md \
        mcp_server/tests/test_get_tests_integration.py
git commit -m "feat(mcp): route get_tests.py through shared parser; register f0_library server"
```

---

## Verification

After all tasks, confirm each spec success criterion:

| # | Criterion | Command |
|---|-----------|---------|
| 1 | 7 tools advertised on the dev box | `cd mcp_server && uv run pytest tests/test_tools_catalog.py::test_tier_b_advertised_with_capabilities -v`, then confirm in Claude Code with `/mcp` |
| 2 | 5 tools when capabilities absent | `uv run pytest tests/test_tools_catalog.py::test_tier_b_hidden_without_capabilities` |
| 3 | 58 tests, 3 categories, coverage reconciles | `uv run pytest tests/test_tools_catalog.py -k "corpus or reconciles"` |
| 4 | `get_tests.py` reports 58 | `python3 utils/get_tests.py --count` |
| 5 | Full suite green incl. classifier invariant | `cd mcp_server && uv run pytest -v` |
| 6 | `confirm_host` mismatch blocks pre-network | `uv run pytest tests/test_tools_deploy.py -k confirm_host` |

Report the final commit hash. **Do not push** — the repo owner pushes.

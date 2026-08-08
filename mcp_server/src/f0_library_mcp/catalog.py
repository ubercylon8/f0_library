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


class TestRecord(BaseModel):
    # Not a pytest test class despite the ``Test`` prefix -- this is a
    # pydantic model. Tell pytest to skip collecting it.
    __test__ = False

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


_Fingerprint = frozenset[tuple[str, int, tuple[tuple[str, int], ...]]]
_CACHE: dict[Path, tuple[_Fingerprint, Index]] = {}


def _fingerprint(root: Path) -> _Fingerprint:
    """Cheap, stat-only signature of the corpus for cache invalidation.

    A ``TestRecord`` is derived from more than ``<uuid>.go``: ``score`` comes
    from ``README.md``, ``architecture`` from the presence of ``build_all.sh``,
    and ``files_present`` from the directory listing. Fingerprinting only the
    ``.go`` mtime would let a long-lived server serve stale records whenever any
    of those other inputs changed. So for every candidate dir we capture:

      * the directory path,
      * the directory's own ``st_mtime_ns`` (catches files added/removed, i.e.
        changes to ``files_present`` and to ``architecture``), and
      * every top-level file's ``(name, st_mtime_ns)`` (catches in-place edits
        to ``README.md`` -> ``score``, ``build_all.sh``, and header fields in
        ``<uuid>.go``).

    Stat-only by design: it never reads file contents, so it stays cheap. The
    result is a frozenset of ``(path, dir_mtime, sorted_files)`` tuples, which
    is hashable and order-independent. Per-entry stat calls are wrapped so a
    file vanishing mid-scan (a race) is treated as absent, not fatal.
    """
    out: set[tuple[str, int, tuple[tuple[str, int], ...]]] = set()
    source_root = Path(root) / "tests_source"
    if not source_root.is_dir():
        return frozenset()
    for category in source_root.iterdir():
        if not category.is_dir():
            continue
        for cand in category.iterdir():
            if not (cand.is_dir() and UUID_RE.match(cand.name)):
                continue
            try:
                dir_mtime = cand.stat().st_mtime_ns
            except OSError:
                dir_mtime = 0
            try:
                entries = sorted(cand.iterdir())
            except OSError:
                entries = []
            files: list[tuple[str, int]] = []
            for entry in entries:
                try:
                    if entry.is_file():
                        files.append((entry.name, entry.stat().st_mtime_ns))
                except OSError:
                    continue
            out.add((str(cand), dir_mtime, tuple(files)))
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

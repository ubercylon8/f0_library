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

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


def test_memoization_invalidates_on_readme_change(tmp_path):
    root = tmp_path
    (root / "CLAUDE.md").write_text("x")
    uid = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
    d = root / "tests_source" / "intel-driven" / uid
    d.mkdir(parents=True)
    go = d / f"{uid}.go"
    go.write_text("/*\nID: %s\nNAME: First\nTECHNIQUES: T1001\n*/\n" % uid)
    readme = d / "README.md"
    readme.write_text("**Test Score**: **7.0/10**\n")

    assert get_index(root).tests[0].score == 7.0
    readme.write_text("**Test Score**: **9.5/10**\n")
    import os, time
    os.utime(readme, (time.time() + 10, time.time() + 10))
    assert get_index(root).tests[0].score == 9.5

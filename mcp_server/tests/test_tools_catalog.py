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


@pytest.mark.xfail(reason="build_test lands in Task 7, deploy_and_run in Task 8", strict=True)
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

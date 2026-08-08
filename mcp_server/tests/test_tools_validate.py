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


async def test_validate_results_rejects_explicit_empty_strings():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool("validate_results", {"path": "", "content": ""})
    assert r.structured_content is not None
    assert r.structured_content["ok"] is False
    assert "exactly one" in r.structured_content["error"].lower()

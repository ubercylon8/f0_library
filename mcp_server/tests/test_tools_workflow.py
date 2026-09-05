"""Tests for the workflow-text tool.

Hermes, Pi and OpenCode consume MCP *tools* but not MCP *prompts*, so the
sectest-builder procedure is unreachable in those runtimes via `build_sectest`.
This tool exposes the same text through the tools surface.
"""
import pytest
from mcp import Client

from f0_library_mcp.server import build_server
from f0_library_mcp.probe import Capabilities

NO_CAPS = Capabilities(go=False, signing=False, ssh_aliases=[])
SRC = "https://example.com/apt-report"


async def test_get_build_workflow_is_tier_a():
    """Must be advertised even on a host with no build/deploy capability."""
    async with Client(build_server(caps=NO_CAPS)) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert "get_build_workflow" in names


async def test_interpolates_the_source():
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool("get_build_workflow", {"source": SRC})
    assert r.structured_content is not None
    assert SRC in r.structured_content["workflow"]


async def test_carries_the_non_negotiable_rules():
    """The rules are the reason the procedure is worth shipping at all."""
    async with Client(build_server(caps=NO_CAPS)) as c:
        text = (await c.call_tool("get_build_workflow", {"source": SRC})).structured_content["workflow"]
    for needle in ("LOG_DIR", "ARTIFACT_DIR", "InitLogger", "metadata comment header",
                   "Never hardcode exit codes", "positive evidence"):
        assert needle in text, f"missing rule text: {needle!r}"


async def test_source_is_optional_and_defaults_to_empty_string():
    """mcp 2.0 pre-parses string args whose annotation is not exactly `str`,
    so the param must be `str = ""` -- calling with no args must still work."""
    async with Client(build_server(caps=NO_CAPS)) as c:
        r = await c.call_tool("get_build_workflow", {})
    assert r.structured_content is not None
    assert "PHASE 1" in r.structured_content["workflow"]


async def test_tool_text_is_identical_to_the_prompt():
    """Single source of truth: if these ever diverge, one surface is stale."""
    async with Client(build_server(caps=NO_CAPS)) as c:
        tool_text = (await c.call_tool(
            "get_build_workflow", {"source": SRC})).structured_content["workflow"]
        prompt = await c.get_prompt("build_sectest", {"source": SRC})
    prompt_text = "".join(m.content.text for m in prompt.messages)
    assert tool_text == prompt_text

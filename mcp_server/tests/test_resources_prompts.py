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
    # The outcome that matters: the traversal target is NOT returned. Depending
    # on how the SDK's resource_security handles the URI, this surfaces either
    # as a client/protocol error or as the handler's own ValueError -- both are
    # acceptable so long as /etc/passwd never comes back.
    async with Client(build_server(caps=NO_CAPS), raise_exceptions=False) as c:
        leaked = False
        try:
            r = await c.read_resource(f"f0://test/{UUID}/../../../etc/passwd")
            text = "".join(
                getattr(cont, "text", "") or "" for cont in (r.contents or [])
            )
            leaked = "root:" in text
        except Exception:
            leaked = False
        assert not leaked


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

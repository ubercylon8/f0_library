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

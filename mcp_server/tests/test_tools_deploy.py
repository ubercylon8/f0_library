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

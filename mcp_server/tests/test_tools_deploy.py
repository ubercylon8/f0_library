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


async def test_windows_execute_uses_delayed_expansion(monkeypatch, tmp_path):
    """Item 1: the Windows execute line must use !ERRORLEVEL! (delayed
    expansion), never %ERRORLEVEL% -- cmd expands the latter at parse time,
    before the .exe runs, echoing the inherited 0 instead of the real code."""
    calls = []

    def fake_run(cmd, *a, **kw):
        calls.append(" ".join(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="EXIT_CODE: 126\n", stderr="")

    monkeypatch.setattr(dt.subprocess, "run", fake_run)
    artifact = tmp_path / f"{UUID}.exe"
    artifact.write_bytes(b"binary")
    monkeypatch.setattr(dt, "_find_binary", lambda root, uuid, plat: artifact)

    async with Client(build_server(caps=CAPS)) as c:
        r = await c.call_tool("deploy_and_run",
                              {"uuid": UUID, "host": "win", "confirm_host": "win"})

    execute = calls[-1]
    assert "!ERRORLEVEL!" in execute
    assert "%ERRORLEVEL%" not in execute
    assert "cmd /v:on" in execute
    # exit 126 must survive as a block verdict, not be flattened to 0/unprotected
    assert r.structured_content["exit_code"] == 126
    assert r.structured_content["verdict"]["verdict"] == "execution_prevented"


async def test_windows_provisions_artifact_dir(monkeypatch, tmp_path):
    """Item 2: the Windows branch must provision c:\\Users\\fortika-test, not
    just recreate LOG_DIR."""
    calls = []

    def fake_run(cmd, *a, **kw):
        calls.append(" ".join(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="EXIT_CODE: 101\n", stderr="")

    monkeypatch.setattr(dt.subprocess, "run", fake_run)
    artifact = tmp_path / f"{UUID}.exe"
    artifact.write_bytes(b"binary")
    monkeypatch.setattr(dt, "_find_binary", lambda root, uuid, plat: artifact)

    async with Client(build_server(caps=CAPS)) as c:
        await c.call_tool("deploy_and_run",
                          {"uuid": UUID, "host": "win", "confirm_host": "win"})

    joined = "\n".join(calls)
    assert r"c:\Users\fortika-test" in joined
    assert "icacls" in joined


async def test_timeout_returns_structured_result_not_exception(monkeypatch, tmp_path):
    """Item 3: a hung host (TimeoutExpired) must yield ok=False, not raise."""
    def fake_run(cmd, *a, **kw):
        raise subprocess.TimeoutExpired(cmd, dt._TIMEOUT)

    monkeypatch.setattr(dt.subprocess, "run", fake_run)
    artifact = tmp_path / UUID
    artifact.write_bytes(b"binary")
    monkeypatch.setattr(dt, "_find_binary", lambda root, uuid, plat: artifact)

    async with Client(build_server(caps=CAPS)) as c:
        r = await c.call_tool("deploy_and_run",
                              {"uuid": UUID, "host": "debian", "confirm_host": "debian"})
    sc = r.structured_content
    assert sc["ok"] is False
    assert "timed out" in sc["error"].lower()


async def test_scp_failure_aborts_before_execute(monkeypatch, tmp_path):
    """Item 4: a failed scp must abort with the real cause and never issue the
    execute command."""
    calls = []

    def fake_run(cmd, *a, **kw):
        calls.append(" ".join(cmd))
        if cmd[0] == "scp":
            return subprocess.CompletedProcess(cmd, 1, stdout="",
                                               stderr="scp: No space left on device")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(dt.subprocess, "run", fake_run)
    artifact = tmp_path / UUID
    artifact.write_bytes(b"binary")
    monkeypatch.setattr(dt, "_find_binary", lambda root, uuid, plat: artifact)

    async with Client(build_server(caps=CAPS)) as c:
        r = await c.call_tool("deploy_and_run",
                              {"uuid": UUID, "host": "debian", "confirm_host": "debian"})
    sc = r.structured_content
    assert sc["ok"] is False
    assert "copy" in sc["error"].lower()
    assert "No space left on device" in sc["stderr"]
    # the execute command (which runs the test binary) must NOT have been issued
    assert not any(f"{UUID}; echo EXIT_CODE" in call for call in calls)

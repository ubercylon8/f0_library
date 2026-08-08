# mcp_server/tests/test_probe.py
import subprocess
from pathlib import Path

import f0_library_mcp.probe as probe
from f0_library_mcp.probe import detect, Capabilities


def _fake_run(mapping):
    """Build a subprocess.run stand-in driven by a {first_arg: returncode} map."""
    def run(cmd, *a, **kw):
        rc = mapping.get(cmd[0], 1)
        if cmd[0] == "ssh" and rc == 0:
            return subprocess.CompletedProcess(cmd, 0, stdout="hostname realhost\n", stderr="")
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="")
    return run


def test_go_absent_disables_build(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.subprocess, "run", _fake_run({}))
    monkeypatch.setattr(probe.shutil, "which", lambda n: None)
    assert detect(tmp_path).go is False


def test_go_present_enables_build(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.subprocess, "run", _fake_run({"go": 0}))
    monkeypatch.setattr(probe.shutil, "which", lambda n: None)
    assert detect(tmp_path).go is True


def test_signing_requires_both_pfx_and_osslsigncode(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.subprocess, "run", _fake_run({}))
    certs = tmp_path / "signing-certs"
    certs.mkdir()

    # osslsigncode present, PFX missing
    monkeypatch.setattr(probe.shutil, "which", lambda n: "/usr/bin/osslsigncode")
    assert detect(tmp_path).signing is False

    # both present
    (certs / "F0RT1KA.pfx").write_bytes(b"x")
    assert detect(tmp_path).signing is True

    # PFX present, osslsigncode missing
    monkeypatch.setattr(probe.shutil, "which", lambda n: None)
    assert detect(tmp_path).signing is False


def test_ssh_aliases_only_include_resolvable(tmp_path, monkeypatch):
    # Mirror real `ssh -G`: every alias exits 0. An unconfigured alias renders
    # its hostname back to the alias itself; only a configured alias (debian)
    # renders a different hostname.
    def run(cmd, *a, **kw):
        if cmd[0] == "ssh":
            alias = cmd[-1]
            host = "localhost" if alias == "debian" else alias
            return subprocess.CompletedProcess(cmd, 0, stdout=f"hostname {host}\n", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")
    monkeypatch.setattr(probe.subprocess, "run", run)
    monkeypatch.setattr(probe.shutil, "which", lambda n: None)
    assert detect(tmp_path).ssh_aliases == ["debian"]


def test_unconfigured_alias_excluded_despite_exit_zero(tmp_path, monkeypatch):
    # All aliases exit 0 with hostname == alias (ssh -G's default for an unknown
    # name). None are genuinely configured, so none should be reported.
    def run(cmd, *a, **kw):
        if cmd[0] == "ssh":
            alias = cmd[-1]
            return subprocess.CompletedProcess(cmd, 0, stdout=f"hostname {alias}\n", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")
    monkeypatch.setattr(probe.subprocess, "run", run)
    monkeypatch.setattr(probe.shutil, "which", lambda n: None)
    assert detect(tmp_path).ssh_aliases == []


def test_probe_failure_never_raises(tmp_path, monkeypatch):
    """A probe that explodes disables a capability; it must not kill startup."""
    def boom(*a, **kw):
        raise OSError("no such binary")
    monkeypatch.setattr(probe.subprocess, "run", boom)
    monkeypatch.setattr(probe.shutil, "which", lambda n: None)
    caps = detect(tmp_path)
    assert isinstance(caps, Capabilities)
    assert caps.go is False and caps.ssh_aliases == []

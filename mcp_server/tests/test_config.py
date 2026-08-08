import pytest
from pathlib import Path
from f0_library_mcp.config import resolve_root, RootNotFoundError


def test_explicit_path_wins(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("x")
    (tmp_path / "tests_source").mkdir()
    assert resolve_root(tmp_path) == tmp_path


def test_env_var_used(tmp_path, monkeypatch):
    (tmp_path / "CLAUDE.md").write_text("x")
    (tmp_path / "tests_source").mkdir()
    monkeypatch.setenv("F0_LIBRARY_ROOT", str(tmp_path))
    assert resolve_root() == tmp_path


def test_walks_up_to_real_repo(monkeypatch):
    """With no env var, resolution walks up from the package file."""
    monkeypatch.delenv("F0_LIBRARY_ROOT", raising=False)
    root = resolve_root()
    assert (root / "CLAUDE.md").is_file()
    assert (root / "tests_source").is_dir()


def test_raises_when_unresolvable(tmp_path, monkeypatch):
    """A directory lacking the markers must fail loudly, not serve an empty catalog."""
    monkeypatch.setenv("F0_LIBRARY_ROOT", str(tmp_path))
    with pytest.raises(RootNotFoundError) as exc:
        resolve_root()
    assert "F0_LIBRARY_ROOT" in str(exc.value)

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


def _make_valid_root(path):
    (path / "CLAUDE.md").write_text("x")
    (path / "tests_source").mkdir()
    return path


def test_invalid_explicit_does_not_fall_back_to_env(tmp_path_factory, monkeypatch):
    """An invalid explicit root is authoritative: it must NOT fall back to a valid env var."""
    invalid = tmp_path_factory.mktemp("invalid_explicit")
    valid_env = _make_valid_root(tmp_path_factory.mktemp("valid_env"))
    monkeypatch.setenv("F0_LIBRARY_ROOT", str(valid_env))
    with pytest.raises(RootNotFoundError):
        resolve_root(invalid)


def test_invalid_env_does_not_fall_back_to_walkup(tmp_path, monkeypatch):
    """An invalid env var is authoritative: it must NOT fall back to walk-up from the package file."""
    monkeypatch.setenv("F0_LIBRARY_ROOT", str(tmp_path))
    with pytest.raises(RootNotFoundError):
        resolve_root()


def test_explicit_takes_precedence_over_valid_env(tmp_path_factory, monkeypatch):
    """With explicit and env both valid but different, explicit wins."""
    valid_explicit = _make_valid_root(tmp_path_factory.mktemp("valid_explicit"))
    valid_env = _make_valid_root(tmp_path_factory.mktemp("valid_env"))
    monkeypatch.setenv("F0_LIBRARY_ROOT", str(valid_env))
    assert resolve_root(valid_explicit) == valid_explicit

# mcp_server/src/f0_library_mcp/resources.py
"""Readable contracts: schema, rubric, org registry, and per-test files."""
from __future__ import annotations

from pathlib import Path

from .catalog import get_index

_RUBRIC = "docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md"


def _read_contract(root: Path, rel: str, purpose: str) -> str:
    """Read a repo-invariant contract file with a descriptive error on miss.

    ``schema``/``rubric``/``organizations`` all read a file that is supposed to
    always exist. A bare ``.read_text()`` would surface a moved or renamed file
    as an opaque ``FileNotFoundError`` at the MCP layer. This wrapper names the
    expected path and what it is for, so a 2am debugger reads a sentence instead
    of a stack trace. It should never fire -- these are repo invariants.
    """
    path = root / rel
    if not path.is_file():
        raise ValueError(
            f"contract file missing: expected {purpose} at {path} "
            f"(relative to repo root {root}) -- repo layout may have changed"
        )
    return path.read_text(errors="replace")


def _resolve_test_file(root: Path, uuid: str, filename: str) -> Path:
    """Resolve ``filename`` inside test ``uuid``'s directory, refusing escapes.

    The guard is independent of the MCP SDK's ``ResourceSecurity`` traversal
    rejection (which acts at URI template-match time, before the handler runs).
    Keeping the check here means the file is still protected if that SDK default
    ever changes. Both ends are ``resolve()``d and compared with
    ``is_relative_to`` -- no string matching.
    """
    rec = next((r for r in get_index(root).tests if r.uuid == uuid), None)
    if rec is None:
        raise ValueError(f"unknown test: {uuid}")
    base = Path(rec.path).resolve()
    target = (base / filename).resolve()
    if not target.is_relative_to(base):
        raise ValueError(
            f"path escapes the test directory: {filename!r} resolves outside {base}"
        )
    if not target.is_file():
        raise ValueError(f"no such file: {filename}")
    return target


def register(server, root: Path) -> None:
    root = Path(root)

    @server.resource("f0://schema/test-results-v2.0",
                     name="Test Results Schema v2.0", mime_type="application/json")
    def schema() -> str:
        return _read_contract(
            root, "test-results-schema-v2.0.json", "the Test Results Schema v2.0")

    @server.resource("f0://rubric/active",
                     name="Active scoring rubric (v2.1)", mime_type="text/markdown")
    def rubric() -> str:
        return _read_contract(root, _RUBRIC, "the active scoring rubric (v2.1)")

    @server.resource("f0://registry/organizations",
                     name="Organization registry", mime_type="application/json")
    def organizations() -> str:
        return _read_contract(
            root, "signing-certs/organization-registry.json",
            "the organization registry")

    @server.resource("f0://test/{uuid}/{filename}",
                     name="Test file", mime_type="text/plain")
    def test_file(uuid: str, filename: str) -> str:
        return _resolve_test_file(root, uuid, filename).read_text(errors="replace")

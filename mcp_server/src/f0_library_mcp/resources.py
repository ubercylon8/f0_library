# mcp_server/src/f0_library_mcp/resources.py
"""Readable contracts: schema, rubric, org registry, and per-test files."""
from __future__ import annotations

from pathlib import Path

from .catalog import get_index

_RUBRIC = "docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md"


def register(server, root: Path) -> None:
    root = Path(root)

    @server.resource("f0://schema/test-results-v2.0",
                     name="Test Results Schema v2.0", mime_type="application/json")
    def schema() -> str:
        return (root / "test-results-schema-v2.0.json").read_text(errors="replace")

    @server.resource("f0://rubric/active",
                     name="Active scoring rubric (v2.1)", mime_type="text/markdown")
    def rubric() -> str:
        return (root / _RUBRIC).read_text(errors="replace")

    @server.resource("f0://registry/organizations",
                     name="Organization registry", mime_type="application/json")
    def organizations() -> str:
        return (root / "signing-certs" / "organization-registry.json").read_text(
            errors="replace")

    @server.resource("f0://test/{uuid}/{filename}",
                     name="Test file", mime_type="text/plain")
    def test_file(uuid: str, filename: str) -> str:
        rec = next((r for r in get_index(root).tests if r.uuid == uuid), None)
        if rec is None:
            raise ValueError(f"unknown test: {uuid}")
        base = Path(rec.path).resolve()
        target = (base / filename).resolve()
        if not target.is_relative_to(base):
            raise ValueError("path escapes the test directory")
        if not target.is_file():
            raise ValueError(f"no such file: {filename}")
        return target.read_text(errors="replace")

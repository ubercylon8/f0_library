# mcp_server/src/f0_library_mcp/prompts.py
"""Workflow prompts.

These carry the sectest-builder and sectest-validation procedures to clients
that have no access to Claude Code agents. They describe the procedure; they
never attempt to invoke an agent. Inside Claude Code, the real agent remains
the correct entry point.
"""
from __future__ import annotations

from pathlib import Path

from .workflows import BUILD_WORKFLOW, VALIDATE_WORKFLOW


def register(server, root: Path) -> None:
    @server.prompt(description="Workflow for building an F0RT1KA test from threat intel")
    def build_sectest(source: str) -> str:
        return BUILD_WORKFLOW.format(source=source)

    @server.prompt(description="Pre-commit validation checklist for an F0RT1KA test")
    def validate_sectest(uuid: str) -> str:
        return VALIDATE_WORKFLOW.format(uuid=uuid)

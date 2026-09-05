"""Tier A workflow tool.

The `build_sectest` MCP *prompt* already carries this procedure, but Hermes,
Pi and OpenCode consume the tools surface only -- their MCP clients never call
`prompts/list` -- so in those runtimes the procedure is otherwise unreachable.
Exposing the same text as a tool closes that gap.

The text comes from `workflows.py` rather than being restated here, so the
prompt and the tool cannot drift; a test asserts they are byte-identical.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from ..workflows import BUILD_WORKFLOW


class WorkflowText(BaseModel):
    workflow: str
    source: str


def register(server, root: Path, caps=None) -> None:
    @server.tool(
        description=(
            "Return the F0RT1KA test-authoring procedure -- the sectest-builder "
            "four-phase workflow plus the non-negotiable rules (LOG_DIR / "
            "ARTIFACT_DIR confinement, Schema v2.0 InitLogger, the metadata "
            "header contract, never hardcode exit codes, never claim a block "
            "without positive evidence). This tool does NOT author a test; it "
            "returns the procedure for you to follow. Optionally pass `source` "
            "to embed the threat-intel source being worked from."
        )
    )
    def get_build_workflow(source: str = "") -> WorkflowText:
        # `source: str = ""` and not `str | None`: mcp 2.0's func_metadata
        # JSON-parses any string argument whose annotation is not exactly `str`.
        return WorkflowText(
            workflow=BUILD_WORKFLOW.format(source=source),
            source=source,
        )

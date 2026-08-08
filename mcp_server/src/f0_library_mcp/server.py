# mcp_server/src/f0_library_mcp/server.py
"""MCPServer assembly.

Tier B tools are registered conditionally, so tools/list reflects what this
host can actually do rather than advertising tools that fail on invocation.
"""
from __future__ import annotations

import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from .config import RootNotFoundError, resolve_root
from .probe import Capabilities, detect
from .tools import catalog_tools

INSTRUCTIONS = """\
F0RT1KA security-test library. Query the test catalog, inspect MITRE ATT&CK
coverage, and validate tests against Schema v2.0 and the ProjectAchilles
metadata contract. On a configured build host, also compile/sign tests and
execute them on lab endpoints.

This server does not author tests -- that is the sectest-builder agent's job.
See the `build_sectest` prompt for the authoring workflow.
"""


def build_server(root: Path | None = None,
                 caps: Capabilities | None = None) -> MCPServer:
    root = resolve_root(root)
    if caps is None:
        caps = detect(root)

    server = MCPServer(
        name="f0_library",
        version="0.1.0",
        instructions=INSTRUCTIONS,
    )

    catalog_tools.register(server, root)

    from .tools import validate_tools
    validate_tools.register(server, root)

    if caps.go:
        from .tools import build_tools
        build_tools.register(server, root, caps)

    if caps.ssh_aliases:
        from .tools import deploy_tools
        deploy_tools.register(server, root, caps)

    from . import resources, prompts
    resources.register(server, root)
    prompts.register(server, root)

    return server


def main() -> None:
    try:
        server = build_server()
    except RootNotFoundError as exc:
        print(f"f0_library MCP server failed to start: {exc}", file=sys.stderr)
        raise SystemExit(1)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()

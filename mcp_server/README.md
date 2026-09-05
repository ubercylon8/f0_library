# f0_library MCP Server

An [MCP](https://modelcontextprotocol.io) server that exposes the F0RT1KA
security-test library to MCP clients (Claude Code, Claude Desktop,
ProjectAchilles, and any other MCP-capable host). It lets a client query the
test catalog, inspect MITRE ATT&CK coverage, validate tests against Schema v2.0
and the ProjectAchilles metadata contract, and — on a properly configured build
host — compile, sign, and detonate tests on lab endpoints.

The package installs the console entry point `f0-library-mcp`, declared in
`pyproject.toml` under `[project.scripts]`.

## What this server is not

**This server does not author tests.** Writing a new F0RT1KA test — turning a
threat-intel report into a Schema v2.0-compliant Go test with the metadata
header, logger, org resolver, detection rules, and documentation — is the
`sectest-builder` agent's job, and it runs inside Claude Code.

For clients that have no access to that agent (Claude Desktop, ProjectAchilles),
the server carries the authoring workflow to the client as guided instructions
through two equivalent surfaces:

- the `build_sectest` **prompt**, for clients that implement `prompts/list`
  (Claude Code, Claude Desktop);
- the `get_build_workflow` **tool**, for clients that consume tools but not
  prompts — Hermes, Pi and OpenCode all fall in this group, so without the tool
  the procedure is unreachable there.

Both render the same text from `workflows.py`, and a test asserts they stay
byte-identical. Either way it describes the workflow; it does not run the
agent. Use it as a starting scaffold, not a substitute for the agent.

## Tool tiers and capability gating

Tools are split into two tiers, and the advertised tool list is computed **per
host** at startup by probing the machine's capabilities. A client only ever
sees tools that can actually run where the server is hosted — `tools/list`
never advertises a tool that would fail on invocation.

### Tier A — always advertised (read-only / analysis)

These need nothing beyond the repository on disk, so they are registered
unconditionally:

| Tool | Purpose |
|------|---------|
| `list_tests` | List every test in the corpus with metadata. |
| `get_test` | Fetch full detail for one test by UUID. |
| `mitre_coverage` | Aggregate MITRE ATT&CK technique/tactic coverage. |
| `validate_test` | Validate a test's source, metadata header, and file layout. |
| `validate_results` | Validate a results document against Schema v2.0. |
| `get_build_workflow` | Return the test-authoring procedure as text, for runtimes that cannot consume MCP prompts. Does not author anything. |

### Tier B — capability-gated (mutating / host-dependent)

These are registered only when the host has the prerequisite capability, which
the server detects at startup (`probe.py`):

| Tool | Gated on | Purpose |
|------|----------|---------|
| `build_test` | Go toolchain present (and signing cert, for signing) | Compile and sign a test binary. |
| `deploy_and_run` | At least one configured SSH lab alias | Deploy a built test to a lab endpoint and execute it. |

### What each host advertises

- A **read-only host** (no Go, no signing cert, no configured SSH aliases) sees
  **6 tools** — Tier A only.
- A **full build host** (Go toolchain, signing cert, configured SSH aliases like
  `debian` / `win`) sees **8 tools** — Tier A plus `build_test` and
  `deploy_and_run`.

Because the gating happens before `initialize` responds, the tool list is
honest about the host, not aspirational. Confirm what your host advertises in
Claude Code with `/mcp`.

## Installation

```bash
cd mcp_server
uv sync
```

`uv sync` creates the project venv and installs the pinned dependencies from
`uv.lock`. The entry point is then runnable with `uv run f0-library-mcp`.

## The `F0_LIBRARY_ROOT` requirement

The server never derives the repository root from the current working
directory. Clients spawn it as a subprocess with an arbitrary cwd, so cwd is not
a reliable signal and using it risks serving a different repo's catalog.

Root resolution is tiered and authoritative (see `config.py`):

1. An explicit root passed in code (used by tests) — authoritative.
2. The **`F0_LIBRARY_ROOT`** environment variable — authoritative when set. A
   wrong value fails loudly rather than silently resolving elsewhere.
3. Only when neither is supplied does it walk up from the package file looking
   for the `CLAUDE.md` + `tests_source/` markers.

For any client that launches the server from outside the repo, **set
`F0_LIBRARY_ROOT` to the repository root.** On this machine that is
`/home/jimx/F0RT1KA/f0_library`.

## Client configuration

### Claude Code

Registered in the repo's `.mcp.json` (the entry sits alongside the existing
`MCP_DOCKER` server):

```json
{
  "mcpServers": {
    "f0_library": {
      "command": "uv",
      "args": ["run", "--directory", "/home/jimx/F0RT1KA/f0_library/mcp_server", "f0-library-mcp"],
      "type": "stdio",
      "env": { "F0_LIBRARY_ROOT": "/home/jimx/F0RT1KA/f0_library" }
    }
  }
}
```

If your client expands `${workspaceFolder}`, you may use that in place of the
absolute paths; Claude Code does not define that variable, so this repo uses the
absolute path. Verify the server with `/mcp`.

### Claude Desktop

Add the server to `claude_desktop_config.json` (Settings → Developer → Edit
Config):

```json
{
  "mcpServers": {
    "f0_library": {
      "command": "uv",
      "args": ["run", "--directory", "/home/jimx/F0RT1KA/f0_library/mcp_server", "f0-library-mcp"],
      "env": { "F0_LIBRARY_ROOT": "/home/jimx/F0RT1KA/f0_library" }
    }
  }
}
```

Restart Claude Desktop after editing. Claude Desktop launches the process from
its own working directory, so `F0_LIBRARY_ROOT` is required here.

### ProjectAchilles

ProjectAchilles connects over stdio the same way. Point it at the entry point
and set `F0_LIBRARY_ROOT` explicitly — PA's working directory is its own repo,
not this one:

```json
{
  "command": "uv",
  "args": ["run", "--directory", "/home/jimx/F0RT1KA/f0_library/mcp_server", "f0-library-mcp"],
  "env": { "F0_LIBRARY_ROOT": "/home/jimx/F0RT1KA/f0_library" }
}
```

PA has no access to the `sectest-builder` agent, so for authoring workflows it
relies on the server's `build_sectest` prompt — or, if its MCP client does not
implement prompts, the `get_build_workflow` tool, which returns the same text.

## Known caveats

- **`deploy_and_run` advertises configured hosts, not reachable ones.** The SSH
  capability probe (`ssh -G <alias>`) inspects the *local SSH config* offline; it
  proves an alias is configured, not that the host is powered on or reachable.
  A lab endpoint can be advertised and still be down at invocation time.
- **The Windows `!ERRORLEVEL!` delayed-expansion path is not yet smoke-tested
  against the live `win` host.** The deploy path builds a Windows command that
  reads the child exit code via delayed `!ERRORLEVEL!` expansion; that branch has
  been exercised in unit tests but not yet end-to-end against the real `win`
  endpoint.

## Development

Run the test suite from the package directory:

```bash
cd mcp_server
uv run pytest -v
```

The repo's `utils/get_tests.py` is a thin CLI over this package's catalog
parser (`f0_library_mcp.catalog.build_index`) — one parser, so the listing tool
and the server can never drift out of sync.

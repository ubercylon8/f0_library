# mcp_server/src/f0_library_mcp/prompts.py
"""Workflow prompts.

These carry the sectest-builder and sectest-validation procedures to clients
that have no access to Claude Code agents. They describe the procedure; they
never attempt to invoke an agent. Inside Claude Code, the real agent remains
the correct entry point.
"""
from __future__ import annotations

from pathlib import Path

_BUILD = """\
You are building an F0RT1KA security test from threat intelligence.

SOURCE: {source}

Follow the sectest-builder four-phase workflow:

PHASE 1 (sequential)
  1. Source analysis   -- extract TTPs, assign UUID, pick platform and architecture
                          (1-2 techniques -> standard; 3+ -> multi-stage).
  2. Implementation    -- write Go source.
  3. Build & sign      -- compile, sign, verify.

PHASE 2 (parallel)
  documentation | detection rules (KQL, YARA, Sigma, EQL, LC D&R) |
  defense guidance | kill-chain diagram (multi-stage only)

PHASE 3  validation -> git commit
PHASE 3b deploy to a lab endpoint and interpret results

NON-NEGOTIABLE RULES
  - Binaries drop to LOG_DIR only: C:\\F0 (Windows) or /tmp/F0 (Linux/macOS).
  - Simulation artifacts go to ARTIFACT_DIR: c:\\Users\\fortika-test,
    /home/fortika-test, or /Users/fortika-test.
  - Single-binary deployment; embed dependencies with //go:embed.
  - Schema v2.0 InitLogger(testID, testName, metadata, executionContext).
  - Include the metadata comment header -- ProjectAchilles parses it at
    ingestion and silently drops fields that are missing.
  - Never hardcode exit codes. Evaluate actual results.
  - Never claim a block without positive evidence. Ambiguous outcomes are
    errors (999), never 126 or 105.

Use the `list_tests` tool first to check whether this technique is already
covered, and `f0://rubric/active` for the scoring rubric.
"""

_VALIDATE = """\
Validate the F0RT1KA test {uuid} before commit.

  1. Call validate_test with uuid={uuid} and resolve every "error" finding.
  2. Confirm required files exist for the test's TARGET platform.
  3. Confirm detection rules key on technique behaviour, not test artifacts
     (no test UUIDs, no /tmp/F0 or C:\\F0 paths in rule logic).
  4. Confirm the metadata header carries every field ProjectAchilles parses.
  5. Confirm README and info-card scores agree.

Report findings; do not silently fix scoring.
"""


def register(server, root: Path) -> None:
    @server.prompt(description="Workflow for building an F0RT1KA test from threat intel")
    def build_sectest(source: str) -> str:
        return _BUILD.format(source=source)

    @server.prompt(description="Pre-commit validation checklist for an F0RT1KA test")
    def validate_sectest(uuid: str) -> str:
        return _VALIDATE.format(uuid=uuid)

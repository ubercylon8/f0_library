"""Repo-root resolution.

Never derives the root from cwd: this server is spawned as a subprocess by
clients (Claude Desktop, ProjectAchilles) whose working directory is arbitrary.
"""
from __future__ import annotations

import os
from pathlib import Path

MARKERS = ("CLAUDE.md", "tests_source")


class RootNotFoundError(RuntimeError):
    """Raised when the f0_library repo root cannot be located."""


def _is_root(path: Path) -> bool:
    return (path / MARKERS[0]).is_file() and (path / MARKERS[1]).is_dir()


def resolve_root(explicit: Path | None = None) -> Path:
    """Locate the f0_library repo root.

    These tiers are authoritative, not a fallback chain -- the first tier that
    applies decides the outcome, including failure:

    - If ``explicit`` is supplied it is authoritative: valid -> returned;
      invalid -> ``RootNotFoundError``. The env var is NOT consulted.
    - Else if ``F0_LIBRARY_ROOT`` is set it is authoritative, same valid/invalid
      rule. Walk-up is NOT attempted.
    - Only when neither is supplied does resolution walk up from this package
      file.

    A supplied-but-wrong root fails loudly rather than silently resolving to a
    different repository, which would serve another repo's catalog under this
    caller's assertion of correctness.
    """
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(Path(explicit))
    env = os.environ.get("F0_LIBRARY_ROOT")
    if env:
        candidates.append(Path(env))

    for cand in candidates:
        cand = cand.expanduser().resolve()
        if _is_root(cand):
            return cand
        raise RootNotFoundError(
            f"{cand} is not an f0_library root (needs CLAUDE.md and tests_source/). "
            "Set F0_LIBRARY_ROOT to the repository root."
        )

    for parent in Path(__file__).resolve().parents:
        if _is_root(parent):
            return parent

    raise RootNotFoundError(
        "Could not locate the f0_library repo root. "
        "Set F0_LIBRARY_ROOT to the repository root."
    )

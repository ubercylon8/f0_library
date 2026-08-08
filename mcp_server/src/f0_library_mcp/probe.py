# mcp_server/src/f0_library_mcp/probe.py
"""Host capability detection.

Runs once at startup, before initialize responds, so the advertised tool list
reflects what this host can actually do. Probes are best-effort: a failure
disables a capability, it never crashes the server.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

LAB_ALIASES: tuple[str, ...] = ("debian", "win", "mac")
_TIMEOUT = 5


class Capabilities(BaseModel):
    go: bool = False
    signing: bool = False
    ssh_aliases: list[str] = Field(default_factory=list)


def _ok(cmd: list[str]) -> bool:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=_TIMEOUT
        ).returncode == 0
    except Exception:
        return False


def _alias_resolves(alias: str) -> bool:
    """Report whether ``alias`` is configured in the local SSH config.

    ``ssh -G <alias>`` renders the effective config offline and exits 0 even for
    an unknown name, defaulting the ``hostname`` value to the alias itself. So
    exit 0 alone proves nothing; the alias is only genuinely configured when the
    rendered ``hostname`` differs from the alias. This checks *configuration*, not
    reachability — it never connects to the host.
    """
    try:
        proc = subprocess.run(
            ["ssh", "-G", alias], capture_output=True, text=True, timeout=_TIMEOUT
        )
    except Exception:
        return False
    if proc.returncode != 0:
        return False
    for line in proc.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "hostname":
            return parts[1].strip().lower() != alias.strip().lower()
    return False


def detect(root: Path) -> Capabilities:
    root = Path(root)
    pfx = root / "signing-certs" / "F0RT1KA.pfx"
    try:
        pfx_ok = pfx.is_file()
    except Exception:
        pfx_ok = False

    return Capabilities(
        go=_ok(["go", "version"]),
        signing=pfx_ok and shutil.which("osslsigncode") is not None,
        ssh_aliases=[a for a in LAB_ALIASES if _alias_resolves(a)],
    )

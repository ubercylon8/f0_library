# mcp_server/src/f0_library_mcp/tools/build_tools.py
"""Tier B build tool. Registered only when `go` is on PATH.

Reports the binary size tier but never refuses to build: per CLAUDE.md the
size budget encodes preference, not impossibility.
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

from ..catalog import get_index

MB = 1024 * 1024
_TIERS = ((10 * MB, "green"), (25 * MB, "yellow"), (50 * MB, "red"))
_TIMEOUT = 900


class BuildResult(BaseModel):
    ok: bool
    error: str = ""
    uuid: str = ""
    command: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    artifact_path: str = ""
    size_bytes: int | None = None
    size_tier: str = ""
    sha1: str = ""
    # Records what was ASKED FOR, not what was achieved: True whenever an `org`
    # was supplied (build-sign was requested). It does NOT assert the signature
    # succeeded -- a build-sign that fails still returns signing_requested=True
    # alongside ok=False. `ok` is the field that tells you whether the
    # build-sign actually succeeded.
    signing_requested: bool = False
    # True when a binary already sits at build/<uuid>/ but was NOT produced by
    # this invocation (build failed, or the on-disk file did not change). The
    # artifact_* / sha1 fields are left empty in that case so a stale hash can
    # never masquerade as this build's output (CLAUDE.md Bug Prevention Rule 8).
    stale_artifact_present: bool = False


_CLIP_MAX = 8000
_CLIP_HALF = 4000


def _clip(text: str) -> str:
    """Preserve head+tail of long captured output.

    A tail-only slice can drop the *first* compiler error, which for Go builds
    is usually the root cause (an error cascade pushes it out of the window,
    leaving only "too many errors"). Keep the first and last 4000 chars with a
    marked elision line between. ``text=True`` output is already-decoded ``str``,
    so slicing cuts characters, not multibyte sequences.
    """
    if len(text) <= _CLIP_MAX:
        return text
    dropped = len(text) - 2 * _CLIP_HALF
    return (text[:_CLIP_HALF]
            + f"\n... [{dropped} characters elided] ...\n"
            + text[-_CLIP_HALF:])


def size_tier(nbytes: int) -> str:
    """Budget tier per CLAUDE.md: <=10MB green, <=25 yellow, <=50 red, else forbidden."""
    for limit, name in _TIERS:
        if nbytes <= limit:
            return name
    return "forbidden"


def _locate_artifact(root: Path, uuid: str) -> Path | None:
    out_dir = Path(root) / "build" / uuid
    if not out_dir.is_dir():
        return None
    candidates = [p for p in out_dir.iterdir() if p.is_file() and p.stem == uuid]
    return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None


def _mtime_ns(path: Path | None) -> int | None:
    """Nanosecond mtime of ``path``, or ``None`` if absent/unstattable.

    Wrapped so a race between locate and stat cannot raise into the tool body.
    """
    if path is None:
        return None
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return None


def register(server, root: Path, caps=None) -> None:
    can_sign = bool(caps and caps.signing)

    @server.tool(
        description=(
            "Build (and optionally sign) a test via utils/gobuild. Returns the "
            "artifact path, SHA1, byte size and budget tier. Supplying `org` "
            "(sb|tpsgl|rga) switches to build-sign, which additionally requires "
            "the signing capability (F0RT1KA.pfx readable, osslsigncode present)."
        )
    )
    # NOTE: `org` is annotated as a plain `str` defaulting to `""`, NOT
    # `str | None = None`. mcp 2.0.0's func_metadata.pre_parse_json JSON-parses
    # any string argument whose annotation `is not str`, so a Union annotation
    # would silently coerce a JSON-shaped org value before it reached this body
    # (the same bug that governs validate_results' `path`/`content`). An unset
    # org is expressed as empty string and guarded by truthiness below.
    def build_test(uuid: str,
                   org: str = "",
                   os_target: str = "windows",
                   arch: str = "amd64") -> BuildResult:
        rec = next((r for r in get_index(root).tests if r.uuid == uuid), None)
        if rec is None:
            return BuildResult(ok=False, uuid=uuid,
                               error=f"test not found in catalog: {uuid}")
        if org and not can_sign:
            return BuildResult(
                ok=False, uuid=uuid,
                error=("signing requested but this host lacks the signing "
                       "capability (needs signing-certs/F0RT1KA.pfx and "
                       "osslsigncode); re-run without `org` to build unsigned"))

        cmd = [str(Path(root) / "utils" / "gobuild")]
        if org:
            cmd += ["--org", org]
        cmd += ["--os", os_target, "--arch", arch,
                "build-sign" if org else "build", rec.path]

        # Record any pre-existing artifact's mtime BEFORE building, so we can
        # tell a freshly produced binary from a leftover of a prior build.
        pre_mtime = _mtime_ns(_locate_artifact(root, uuid))

        try:
            proc = subprocess.run(cmd, cwd=str(root), capture_output=True,
                                  text=True, timeout=_TIMEOUT)
        except subprocess.TimeoutExpired:
            return BuildResult(ok=False, uuid=uuid, command=cmd,
                               error=f"gobuild exceeded {_TIMEOUT}s")

        result = BuildResult(
            ok=proc.returncode == 0,
            uuid=uuid,
            command=cmd,
            exit_code=proc.returncode,
            stdout=_clip(proc.stdout),
            stderr=_clip(proc.stderr),
            signing_requested=bool(org),
        )

        artifact = _locate_artifact(root, uuid)
        post_mtime = _mtime_ns(artifact)
        # An artifact counts as *this build's* output only if the build
        # succeeded AND a file exists AND it is genuinely new (no prior artifact,
        # or its mtime advanced). Anything else that leaves a file on disk is a
        # stale leftover -- report its presence, but never its hash/size.
        is_fresh = (proc.returncode == 0 and post_mtime is not None
                    and (pre_mtime is None or post_mtime > pre_mtime))
        if is_fresh:
            data = artifact.read_bytes()
            result.artifact_path = str(artifact)
            result.size_bytes = len(data)
            result.size_tier = size_tier(len(data))
            result.sha1 = hashlib.sha1(data).hexdigest()
        elif post_mtime is not None:
            result.stale_artifact_present = True
        return result

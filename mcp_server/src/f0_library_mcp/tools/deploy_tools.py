# mcp_server/src/f0_library_mcp/tools/deploy_tools.py
"""Tier B deploy tool. Registered only when at least one lab alias resolves.

Mirrors the sectest-deploy skill. The ARTIFACT_DIR chmod on Linux/macOS is
mandatory: the test runs as a normal user but writes decoys into a root-owned
directory, and skipping it yields exit 999 -- a lab-setup failure that would
otherwise be misread as a prerequisite problem in the test itself.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

from ..catalog import get_index
from ..classify import Verdict, classify

_EXIT_RE = re.compile(r"EXIT_CODE:\s*(-?\d+)")
_TIMEOUT = 600


class PlatformSpec(BaseModel):
    name: str
    remote_dir: str
    artifact_dir: str
    binary_suffix: str
    posix: bool


PLATFORMS: dict[str, PlatformSpec] = {
    "debian": PlatformSpec(name="linux", remote_dir="/opt/f0",
                           artifact_dir="/home/fortika-test",
                           binary_suffix="", posix=True),
    "mac": PlatformSpec(name="darwin", remote_dir="/opt/f0",
                        artifact_dir="/Users/fortika-test",
                        binary_suffix="", posix=True),
    "win": PlatformSpec(name="windows", remote_dir=r"c:\F0",
                        artifact_dir=r"c:\Users\fortika-test",
                        binary_suffix=".exe", posix=False),
}


class DeployResult(BaseModel):
    ok: bool
    error: str = ""
    uuid: str = ""
    host: str = ""
    steps: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    verdict: Verdict | None = None


def _parse_exit_code(stdout: str) -> int | None:
    matches = _EXIT_RE.findall(stdout or "")
    return int(matches[-1]) if matches else None


def _find_binary(root: Path, uuid: str, plat: PlatformSpec) -> Path | None:
    candidate = Path(root) / "build" / uuid / f"{uuid}{plat.binary_suffix}"
    return candidate if candidate.is_file() else None


def register(server, root: Path, caps=None) -> None:
    available = list(caps.ssh_aliases) if caps else []

    @server.tool(
        description=(
            "Deploy a built test to a lab endpoint and execute it. THIS DETONATES "
            "A REAL ATTACK SIMULATION on the target host. `confirm_host` must "
            "exactly match `host`. Available hosts reflect the local SSH config on "
            "this machine (parsed offline), NOT live reachability -- a deploy may "
            f"still fail at connect time. Available hosts: {available}."
        )
    )
    def deploy_and_run(uuid: str, host: str, confirm_host: str) -> DeployResult:
        if host != confirm_host:
            return DeployResult(
                ok=False, uuid=uuid, host=host,
                error=(f"confirm_host {confirm_host!r} does not match host {host!r}; "
                       "refusing to deploy."))
        if host not in available:
            return DeployResult(
                ok=False, uuid=uuid, host=host,
                error=f"host {host!r} is not available on this machine; have {available}")
        if not any(r.uuid == uuid for r in get_index(root).tests):
            return DeployResult(ok=False, uuid=uuid, host=host,
                                error=f"test not found in catalog: {uuid}")

        plat = PLATFORMS[host]
        binary = _find_binary(root, uuid, plat)
        if binary is None:
            return DeployResult(
                ok=False, uuid=uuid, host=host,
                error=f"no binary at build/{uuid}/ -- run build_test first")

        steps: list[str] = []

        def sh(cmd: list[str]) -> subprocess.CompletedProcess:
            steps.append(" ".join(cmd))
            return subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)

        if plat.posix:
            sh(["ssh", host, f"sudo rm -rf {plat.remote_dir} && "
                             f"sudo mkdir -p {plat.remote_dir} && "
                             f"sudo chmod 777 {plat.remote_dir}"])
            sh(["ssh", host, f"sudo mkdir -p {plat.artifact_dir} && "
                             f"sudo chmod 777 {plat.artifact_dir}"])
            sh(["scp", str(binary), f"{host}:{plat.remote_dir}/"])
            sh(["ssh", host, f"chmod +x {plat.remote_dir}/{uuid}"])
            run = sh(["ssh", host, f"{plat.remote_dir}/{uuid}; echo EXIT_CODE: $?"])
        else:
            sh(["ssh", host, r"rmdir /s /q c:\F0 2>nul & mkdir c:\F0"])
            sh(["scp", str(binary), f"{host}:{plat.remote_dir}\\"])
            run = sh(["ssh", host,
                      f"{plat.remote_dir}\\{uuid}.exe & echo EXIT_CODE: %ERRORLEVEL%"])

        code = _parse_exit_code(run.stdout)
        return DeployResult(
            ok=code is not None,
            error="" if code is not None else "could not parse EXIT_CODE from remote output",
            uuid=uuid, host=host, steps=steps,
            exit_code=code,
            stdout=run.stdout[-16000:],
            stderr=run.stderr[-8000:],
            verdict=classify(code) if code is not None else None,
        )

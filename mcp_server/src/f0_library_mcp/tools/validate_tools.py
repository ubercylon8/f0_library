# mcp_server/src/f0_library_mcp/tools/validate_tools.py
"""Tier A validation tools.

Imports the repo's own validator rather than subprocessing it, so schema
changes in utils/validate_test_results.py propagate here automatically.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

from pydantic import BaseModel, Field

from ..catalog import REQUIRED_HEADER_FIELDS, get_index
from ..classify import Verdict, classify

_README_SCORE = re.compile(r"^\*\*Test Score\*\*:\s*\*\*([0-9]+\.[0-9]+)/10\*\*", re.M)
_INFO_SCORE = re.compile(r"^## Test Score:\s*([0-9]+\.[0-9]+)/10", re.M)

_BASE_REQUIRED = ("README.md", "test_logger.go", "org_resolver.go", "go.mod")


class Finding(BaseModel):
    severity: str          # "error" | "warning"
    check: str
    message: str


class ValidateTestResult(BaseModel):
    found: bool
    uuid: str
    findings: list[Finding] = Field(default_factory=list)


class ValidateResultsResult(BaseModel):
    ok: bool
    error: str = ""
    schema_errors: list[str] = Field(default_factory=list)
    check_errors: list[str] = Field(default_factory=list)
    verdict: Verdict | None = None


def _load_repo_validator(root: Path):
    """Import utils/validate_test_results.py by path (it is not a package)."""
    path = root / "utils" / "validate_test_results.py"
    spec = importlib.util.spec_from_file_location("f0_repo_validator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def register(server, root: Path, caps=None) -> None:
    @server.tool(
        description=(
            "Validate one test's package: required files, README/info-card score "
            "agreement, and metadata-header completeness against the "
            "ProjectAchilles ingestion contract."
        )
    )
    def validate_test(uuid: str) -> ValidateTestResult:
        index = get_index(root)
        rec = next((r for r in index.tests if r.uuid == uuid), None)
        if rec is None:
            return ValidateTestResult(found=False, uuid=uuid)

        findings: list[Finding] = []
        test_dir = Path(rec.path)

        for required in _BASE_REQUIRED:
            if not (test_dir / required).is_file():
                findings.append(Finding(severity="error", check="required_files",
                                        message=f"missing {required}"))
        info_cards = list(test_dir.glob("*_info.md"))
        if not info_cards:
            findings.append(Finding(severity="error", check="required_files",
                                    message="missing <uuid>_info.md"))

        for field in REQUIRED_HEADER_FIELDS:
            if field in rec.header_missing:
                findings.append(Finding(severity="error", check="metadata_header",
                                        message=f"header field {field} missing or empty"))

        readme = test_dir / "README.md"
        readme_score = None
        if readme.is_file():
            m = _README_SCORE.search(readme.read_text(errors="replace"))
            if m:
                readme_score = m.group(1)
            else:
                findings.append(Finding(severity="error", check="score_format",
                                        message="README.md lacks '**Test Score**: **X.X/10**'"))
        info_score = None
        if info_cards:
            m = _INFO_SCORE.search(info_cards[0].read_text(errors="replace"))
            if m:
                info_score = m.group(1)
            else:
                findings.append(Finding(severity="error", check="score_format",
                                        message="info card lacks '## Test Score: X.X/10'"))
        if readme_score and info_score and readme_score != info_score:
            findings.append(Finding(
                severity="error", check="score_consistency",
                message=f"score mismatch: README {readme_score} vs info card {info_score}"))

        return ValidateTestResult(found=True, uuid=uuid, findings=findings)

    @server.tool(
        description=(
            "Validate a test-results JSON against Schema v2.0 and classify its "
            "exit code. Supply exactly one of `path` or `content`."
        )
    )
    # NOTE: `path`/`content` are annotated as plain `str` (not `str | None`)
    # deliberately. mcp 2.0.0's func_metadata.pre_parse_json JSON-parses any
    # string argument whose annotation `is not str` -- so a `str | None`
    # annotation would silently turn a valid-JSON `content` (e.g. '{"exitCode":
    # 126}') into a dict before it reaches this body, breaking the "supply a raw
    # results JSON string" contract. Plain `str` with a None default keeps the
    # params optional while opting out of that pre-parse.
    def validate_results(path: str = None,
                         content: str = None) -> ValidateResultsResult:
        if (path is None) == (content is None):
            return ValidateResultsResult(
                ok=False, error="Supply exactly one of `path` or `content`.")

        raw = content
        if path is not None:
            target = Path(path)
            if not target.is_file():
                return ValidateResultsResult(ok=False, error=f"no such file: {path}")
            raw = target.read_text(errors="replace")

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            return ValidateResultsResult(ok=False, error=f"invalid JSON: {exc}")

        validator = _load_repo_validator(root)
        schema = validator.load_schema()
        schema_ok, schema_errors = validator.validate_test_result(payload, schema)
        checks_ok, check_errors = validator.perform_additional_checks(payload)

        code = payload.get("exitCode", payload.get("exit_code"))
        verdict = classify(int(code)) if isinstance(code, (int, str)) and str(code).lstrip("-").isdigit() else None

        return ValidateResultsResult(
            ok=bool(schema_ok and checks_ok),
            schema_errors=list(schema_errors),
            check_errors=list(check_errors),
            verdict=verdict,
        )

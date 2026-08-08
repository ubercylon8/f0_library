"""Exit code -> verdict classification.

Isolated from all I/O so the invariant below is testable in isolation.

THE INVARIANT (CLAUDE.md Bug Prevention Rule 8):
    A block verdict may be returned ONLY on affirmative evidence of a
    protection action. Absence of success is not evidence of a block.
    Ambiguous, unrecognized, or benign-failure outcomes map to `unknown`.
    A catch-all that resolves unknown codes to a block code is a banned
    anti-pattern: it manufactures false PROTECTED verdicts.
"""
from __future__ import annotations

from pydantic import BaseModel

# code -> (verdict, human label, protected tri-state)
KNOWN_CODES: dict[int, tuple[str, str, bool | None]] = {
    0:   ("unprotected",         "Endpoint.Unprotected (clean exit)",        False),
    101: ("unprotected",         "Endpoint.Unprotected",                     False),
    105: ("quarantined",         "Endpoint.FileQuarantinedOnExtraction",     True),
    126: ("execution_prevented", "Endpoint.ExecutionPrevented",              True),
    999: ("test_error",          "Endpoint.UnexpectedTestError",             None),
}


class Verdict(BaseModel):
    code: int
    verdict: str
    label: str
    protected: bool | None
    rationale: str


# NOTE: body drafted by the implementation agent at the repo owner's request
# (owner elected "draft it, I'll edit"). The `unknown` rationale wording is
# provisional and the owner intends to revise it. The INVARIANT below is not
# provisional: unknown codes must never map to a block code.
def classify(code: int) -> Verdict:
    """Map a test exit code to a Verdict.

    Contract:
      - Codes in KNOWN_CODES map to their tuple.
      - EVERY other code maps to verdict "unknown", protected None, and a
        rationale saying the code was not recognized.
      - `protected` is never True for "unknown".
    """
    known = KNOWN_CODES.get(code)
    if known is not None:
        verdict, label, protected = known
        return Verdict(
            code=code,
            verdict=verdict,
            label=label,
            protected=protected,
            rationale=f"Exit code {code} maps to {label}.",
        )
    return Verdict(
        code=code,
        verdict="unknown",
        label=f"Unrecognized exit code {code}",
        protected=None,
        rationale=(
            f"Exit code {code} is not a recognized F0RT1KA result code, so its "
            "verdict is unknown. "
            "Treat this run as inconclusive: absence of success is not evidence "
            "of a block. Check the test's stdout capture in LOG_DIR before "
            "drawing any protection conclusion."
        ),
    )

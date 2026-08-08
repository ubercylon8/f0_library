import pytest
from f0_library_mcp.classify import classify, Verdict


@pytest.mark.parametrize("code,expected", [
    (0,   "unprotected"),
    (101, "unprotected"),
    (105, "quarantined"),
    (126, "execution_prevented"),
    (999, "test_error"),
])
def test_known_codes(code, expected):
    assert classify(code).verdict == expected


@pytest.mark.parametrize("code", [1, 2, 3, 42, 127, 137, 255, -1, 500, 1000])
def test_unknown_codes_never_claim_protection(code):
    """CLAUDE.md Bug Prevention Rule 8: absence of success is not evidence of a block.

    An unrecognized code must never be reported as a block. Doing so
    manufactures a false PROTECTED verdict -- telling a user their endpoint
    stopped an attack when nothing did.
    """
    v = classify(code)
    assert v.verdict == "unknown"
    assert v.protected is not True
    assert v.verdict not in ("quarantined", "execution_prevented")


def test_unknown_carries_actionable_rationale():
    v = classify(42)
    assert v.rationale
    assert "unknown" in v.rationale.lower() or "unrecogni" in v.rationale.lower()


def test_protected_flag_matches_verdict():
    assert classify(126).protected is True
    assert classify(105).protected is True
    assert classify(101).protected is False
    assert classify(999).protected is None
    assert classify(42).protected is None


def test_returns_verdict_model():
    assert isinstance(classify(101), Verdict)

from mcp_guard.models import Severity


def test_parse_cisco_values():
    assert Severity.parse("HIGH") == Severity.HIGH
    assert Severity.parse("safe") == Severity.SAFE
    assert Severity.parse("UNKNOWN") == Severity.MEDIUM


def test_threshold_comparison():
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.MEDIUM < Severity.HIGH
    assert Severity.LOW >= Severity.LOW

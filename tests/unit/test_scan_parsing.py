import pytest

from mcp_guard.models import Severity
from mcp_guard.runners.cisco_mcp import CiscoScanError, parse_scan_payload

SAFE = {"tool_name": "add", "is_safe": True,
        "findings": {"yara_analyzer": {"severity": "SAFE", "threat_names": [], "threat_summary": "No threats"}}}
UNSAFE = {"tool_name": "weather", "is_safe": False,
          "findings": {"yara_analyzer": {"severity": "HIGH",
                                          "threat_names": ["PROMPT INJECTION"],
                                          "threat_summary": "Detected 1 threat"}}}


def test_valid_payload():
    findings = parse_scan_payload({"scan_results": [SAFE, UNSAFE]}, "srv")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_id == "cisco-yara/prompt-injection"
    assert findings[0].tool == "weather"


def test_all_safe_is_clean():
    assert parse_scan_payload({"scan_results": [SAFE]}, "srv") == []


def test_empty_object_rejected():
    with pytest.raises(CiscoScanError, match="scan_results"):
        parse_scan_payload({}, "srv")


def test_scan_results_not_a_list_rejected():
    with pytest.raises(CiscoScanError, match="scan_results"):
        parse_scan_payload({"scan_results": "oops"}, "srv")


def test_missing_is_safe_rejected():
    bad = {"tool_name": "x", "findings": {}}
    with pytest.raises(CiscoScanError, match="is_safe"):
        parse_scan_payload({"scan_results": [bad]}, "srv")


def test_unsafe_without_findings_rejected():
    bad = {"tool_name": "x", "is_safe": False}
    with pytest.raises(CiscoScanError, match="yara_analyzer"):
        parse_scan_payload({"scan_results": [bad]}, "srv")


def test_unsafe_without_severity_rejected():
    bad = {"tool_name": "x", "is_safe": False, "findings": {"yara_analyzer": {"threat_names": ["T"]}}}
    with pytest.raises(CiscoScanError, match="severity"):
        parse_scan_payload({"scan_results": [bad]}, "srv")


def test_unknown_severity_rejected():
    bad = {"tool_name": "x", "is_safe": False,
           "findings": {"yara_analyzer": {"severity": "EXPLOSIVE", "threat_names": ["T"]}}}
    with pytest.raises(CiscoScanError, match="EXPLOSIVE"):
        parse_scan_payload({"scan_results": [bad]}, "srv")


def test_unsafe_with_empty_threats_rejected():
    bad = {"tool_name": "x", "is_safe": False,
           "findings": {"yara_analyzer": {"severity": "HIGH", "threat_names": []}}}
    with pytest.raises(CiscoScanError, match="threats"):
        parse_scan_payload({"scan_results": [bad]}, "srv")


def test_non_dict_result_rejected():
    with pytest.raises(CiscoScanError):
        parse_scan_payload({"scan_results": ["nope"]}, "srv")

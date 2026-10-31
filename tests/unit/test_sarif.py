from mcp_guard.models import Finding, Severity
from mcp_guard.report.sarif import build_sarif


def _finding(**kw):
    base = dict(rule_id="cisco-yara/prompt-injection", severity=Severity.HIGH,
                title="t", message="m", source="cisco-yara", server="s1", tool="weather")
    base.update(kw)
    return Finding(**base)


def test_sarif_structure():
    sarif = build_sarif([_finding()])
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-guard-ci"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rule_ids == ["cisco-yara/prompt-injection"]
    result = run["results"][0]
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "mcp://s1/tools/weather"


def test_severity_levels():
    sarif = build_sarif([
        _finding(severity=Severity.HIGH),
        _finding(rule_id="r/med", severity=Severity.MEDIUM),
        _finding(rule_id="r/low", severity=Severity.LOW),
    ])
    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels == {"cisco-yara/prompt-injection": "error", "r/med": "warning", "r/low": "note"}


def test_rules_deduplicated():
    sarif = build_sarif([_finding(tool="a"), _finding(tool="b")])
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(sarif["runs"][0]["results"]) == 2


def test_empty_findings_valid():
    sarif = build_sarif([])
    assert sarif["runs"][0]["results"] == []


def test_file_bound_finding_uses_path():
    sarif = build_sarif([_finding(path="skills/evil/SKILL.md", server=None, tool=None)])
    loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert loc["uri"] == "skills/evil/SKILL.md"
    assert loc["uriBaseId"] == "SRCROOT"


def test_no_null_uribaseid_on_mcp_locations():
    sarif = build_sarif([_finding()])
    loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert "uriBaseId" not in loc or loc["uriBaseId"] is not None

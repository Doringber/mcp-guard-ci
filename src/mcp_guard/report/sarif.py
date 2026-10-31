"""Merge all findings into one SARIF 2.1.0 report for the GitHub Security tab."""
from __future__ import annotations

from .. import __version__
from ..models import Finding, Severity

_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.SAFE: "none"}
_DEFAULT_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.SAFE: "none"}


def build_sarif(findings: list[Finding]) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("/", "-").replace("_", "-"),
                "shortDescription": {"text": f.title[:120]},
                "defaultConfiguration": {"level": _DEFAULT_LEVEL[f.severity]},
            }
        location_uri = f.path or (f"mcp://{f.server}" + (f"/tools/{f.tool}" if f.tool else ""))
        results.append({
            "ruleId": f.rule_id,
            "level": _LEVEL[f.severity],
            "message": {"text": f"{f.title}\n{f.message}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": location_uri, "uriBaseId": "SRCROOT" if f.path else None},
                },
            }],
        })
    # SARIF forbids null members in artifactLocation
    for r in results:
        loc = r["locations"][0]["physicalLocation"]["artifactLocation"]
        if loc.get("uriBaseId") is None:
            loc.pop("uriBaseId", None)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcp-guard-ci",
                    "version": __version__,
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }

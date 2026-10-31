"""End-to-end: real Inspector CLI + real Cisco mcp-scanner against fixtures."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
requires_integration = pytest.mark.skipif(
    shutil.which("mcp-scanner") is None or shutil.which("npx") is None,
    reason="needs mcp-scanner and npx on PATH",
)

UV = shutil.which("uv") or "uv"


def _guard(*extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [UV, "run", "mcp-guard", "run", *extra],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
    )


@requires_integration
@pytest.mark.integration
def test_clean_fixture_passes(tmp_path):
    sarif_path = tmp_path / "out.sarif"
    proc = _guard("--config", "mcp-guard.yml", "--sarif", str(sarif_path))
    assert proc.returncode == 0, proc.stderr + proc.stdout
    sarif = json.loads(sarif_path.read_text())
    assert sarif["runs"][0]["results"] == []
    assert "clean-fixture" in proc.stdout


@requires_integration
@pytest.mark.integration
def test_poisoned_fixture_fails_with_high_sarif(tmp_path):
    sarif_path = tmp_path / "out.sarif"
    proc = _guard("--config", "mcp-guard-poisoned.yml", "--sarif", str(sarif_path))
    assert proc.returncode == 1, proc.stderr + proc.stdout
    results = json.loads(sarif_path.read_text())["runs"][0]["results"]
    high = [r for r in results if r["level"] == "error"]
    assert high, "expected at least one HIGH finding"
    uris = " ".join(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in high)
    assert "poisoned-fixture" in uris and "weather" in uris


@requires_integration
@pytest.mark.integration
def test_broken_server_is_high_finding(tmp_path):
    cfg = tmp_path / "broken.yml"
    cfg.write_text(
        'servers:\n  - name: ghost\n    command: ["python3", "/nonexistent/server.py"]\nfail_on: high\ndiscover: false\n'
    )
    sarif_path = tmp_path / "out.sarif"
    proc = _guard("--config", str(cfg), "--sarif", str(sarif_path))
    assert proc.returncode == 1, proc.stderr + proc.stdout
    rule_ids = {r["ruleId"] for r in json.loads(sarif_path.read_text())["runs"][0]["results"]}
    assert "mcp-guard/functional-server-start" in rule_ids


def test_no_servers_is_usage_error(tmp_path):
    cfg = tmp_path / "empty.yml"
    cfg.write_text("servers: []\ndiscover: false\n")
    proc = _guard("--config", str(cfg), "--sarif", str(tmp_path / "o.sarif"))
    assert proc.returncode == 2

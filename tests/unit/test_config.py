import pytest

from mcp_guard.config import ConfigError, load_config
from mcp_guard.models import Severity


def test_load_full_config(tmp_path):
    p = tmp_path / "mcp-guard.yml"
    p.write_text(
        """
servers:
  - name: s1
    command: "python server.py"
    smoke:
      - tool: ping
        args: {n: 1}
        expect_contains: pong
fail_on: medium
discover: false
skills_glob: "custom/**/SKILL.md"
"""
    )
    cfg = load_config(p)
    assert cfg.servers[0].command == ["python", "server.py"]
    assert cfg.servers[0].smoke[0].expect_contains == "pong"
    assert cfg.fail_on == Severity.MEDIUM
    assert cfg.discover is False
    assert cfg.skills_glob == "custom/**/SKILL.md"


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.yml")


def test_server_without_command_rejected(tmp_path):
    p = tmp_path / "c.yml"
    p.write_text("servers:\n  - name: broken\n")
    with pytest.raises(ConfigError, match="command"):
        load_config(p)


def test_bad_fail_on_rejected(tmp_path):
    p = tmp_path / "c.yml"
    p.write_text("fail_on: extreme\n")
    with pytest.raises(ConfigError, match="fail_on"):
        load_config(p)


def test_defaults(tmp_path):
    p = tmp_path / "c.yml"
    p.write_text("servers: []\n")
    cfg = load_config(p)
    assert cfg.fail_on == Severity.HIGH
    assert cfg.discover is True
    assert cfg.inspector_enabled and cfg.cisco_enabled

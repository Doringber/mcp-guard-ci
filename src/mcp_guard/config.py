"""Load and validate mcp-guard.yml."""
from __future__ import annotations

from pathlib import Path

import yaml

from .models import GuardConfig, ServerSpec, Severity, SmokeCall


class ConfigError(Exception):
    pass


def _as_command(value: object, where: str) -> list[str]:
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list) and all(isinstance(x, (str, int, float)) for x in value):
        return [str(x) for x in value]
    raise ConfigError(f"{where}: 'command' must be a string or a list of strings, got {value!r}")


def _parse_server(raw: dict, where: str) -> ServerSpec:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: server entry must be a mapping, got {raw!r}")
    name = raw.get("name")
    if not name:
        raise ConfigError(f"{where}: server entry is missing 'name'")
    if "command" not in raw:
        raise ConfigError(f"{where}: server '{name}' is missing 'command'")
    smoke = [
        SmokeCall(tool=s["tool"], args=s.get("args", {}), expect_contains=s.get("expect_contains"))
        for s in raw.get("smoke", [])
    ]
    return ServerSpec(
        name=str(name),
        command=_as_command(raw["command"], where),
        cwd=raw.get("cwd"),
        env={str(k): str(v) for k, v in (raw.get("env") or {}).items()},
        smoke=smoke,
    )


def load_config(path: str | Path) -> GuardConfig:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"config file not found: {p}")
    data = yaml.safe_load(p.read_text()) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{p}: top level must be a mapping")

    cfg = GuardConfig()
    cfg.servers = [_parse_server(s, str(p)) for s in data.get("servers", [])]
    cfg.discover = bool(data.get("discover", True))
    cfg.skills_glob = data.get("skills_glob", cfg.skills_glob)
    try:
        cfg.fail_on = Severity.parse(str(data.get("fail_on", "high")))
    except KeyError:
        raise ConfigError(f"{p}: fail_on must be one of low|medium|high")
    scanners = data.get("scanners") or {}
    cfg.inspector_enabled = bool(scanners.get("inspector", {}).get("enabled", True))
    cfg.cisco_enabled = bool(scanners.get("cisco", {}).get("enabled", True))
    cfg.inspector_command = data.get("inspector_command", cfg.inspector_command)
    cfg.cisco_command = data.get("cisco_command", cfg.cisco_command)
    cfg.smoke_timeout = int(data.get("smoke_timeout", cfg.smoke_timeout))
    cfg.scan_timeout = int(data.get("scan_timeout", cfg.scan_timeout))
    return cfg

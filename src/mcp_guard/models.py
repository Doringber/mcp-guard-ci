"""Shared data model for mcp-guard findings and configuration."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, value: str) -> "Severity":
        v = value.strip().upper()
        # Cisco's scanner emits UNKNOWN for unclassifiable results; treat it as
        # MEDIUM so it is visible without failing a default `fail_on: high` run.
        if v == "UNKNOWN":
            return cls.MEDIUM
        return cls[v.lower().upper()]


@dataclass
class SmokeCall:
    tool: str
    args: dict = field(default_factory=dict)
    expect_contains: str | None = None


@dataclass
class ServerSpec:
    name: str
    command: list[str]
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    smoke: list[SmokeCall] = field(default_factory=list)
    source: str = "config"  # "config" | path of the discovered config file


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    source: str  # "inspector" | "cisco-yara" | ...
    server: str | None = None
    tool: str | None = None
    path: str | None = None  # repo-relative file path, when the finding is file-bound


@dataclass
class GuardConfig:
    servers: list[ServerSpec] = field(default_factory=list)
    discover: bool = True
    skills_glob: str = "skills/**/SKILL.md"
    fail_on: Severity = Severity.HIGH
    inspector_enabled: bool = True
    cisco_enabled: bool = True
    inspector_command: str = "npx -y @modelcontextprotocol/inspector"
    cisco_command: str = "mcp-scanner"
    smoke_timeout: int = 120
    scan_timeout: int = 240

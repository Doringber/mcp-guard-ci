"""Find MCP server configs and SKILL.md files in a repository."""
from __future__ import annotations

import json
from pathlib import Path

from .models import ServerSpec

# Well-known MCP client config locations, relative to the repo root.
WELL_KNOWN_CONFIGS = [
    "mcp.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".windsurf/mcp_config.json",
    ".codeium/windsurf/mcp_config.json",
    "claude_desktop_config.json",
]


def discover_servers(root: str | Path) -> list[ServerSpec]:
    """Read well-known MCP config files under `root` into ServerSpecs.

    Files use the standard {"mcpServers": {name: {command, args, env}}} shape.
    Later files do not override a name that was already discovered.
    """
    root = Path(root)
    servers: list[ServerSpec] = []
    seen: set[str] = set()
    for rel in WELL_KNOWN_CONFIGS:
        path = root / rel
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        for name, spec in (data.get("mcpServers") or {}).items():
            if name in seen or not isinstance(spec, dict) or "command" not in spec:
                continue
            seen.add(name)
            command = [str(spec["command"])] + [str(a) for a in spec.get("args", [])]
            servers.append(
                ServerSpec(
                    name=name,
                    command=command,
                    cwd=spec.get("cwd"),
                    env={str(k): str(v) for k, v in (spec.get("env") or {}).items()},
                    source=str(path),
                )
            )
    return servers


def discover_skills(root: str | Path, skills_glob: str = "skills/**/SKILL.md") -> list[Path]:
    """Return SKILL.md files under `root` matching the configured glob."""
    root = Path(root)
    return sorted(p for p in root.glob(skills_glob) if p.is_file())

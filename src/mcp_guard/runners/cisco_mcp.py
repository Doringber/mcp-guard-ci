"""Security scan via Cisco's mcp-scanner (YARA engine, fully local, no API key).

Verified against cisco-ai-mcp-scanner: `mcp-scanner --analyzers yara --format
raw stdio --stdio-command <cmd> --stdio-arg <arg>...` prints one JSON object
with a `scan_results` list on stdout and exits 0 even when findings exist,
so pass/fail must come from the parsed severities. It exits non-zero (with no
JSON on stdout) when the server cannot be scanned at all.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess

from ..models import Finding, ServerSpec, Severity


class CiscoScannerUnavailable(RuntimeError):
    pass


def scan_server(server: ServerSpec, *, cisco_command: str, timeout: int) -> list[Finding]:
    cmd = shlex.split(cisco_command) + [
        "--log-level", "error",
        "--analyzers", "yara",
        "--format", "raw",
        "stdio",
        "--stdio-command", server.command[0],
    ]
    for arg in server.command[1:]:
        cmd += ["--stdio-arg", arg]

    env = os.environ.copy()
    env.update(server.env)
    try:
        proc = subprocess.run(
            cmd, cwd=server.cwd, env=env, capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise CiscoScannerUnavailable(
            f"could not run Cisco mcp-scanner ({cisco_command!r}): {exc}. "
            "Install it with: uv tool install cisco-ai-mcp-scanner"
        ) from exc
    except subprocess.TimeoutExpired:
        return [Finding(
            rule_id="mcp-guard/scanner-error",
            severity=Severity.MEDIUM,
            title=f"Security scan timed out: {server.name}",
            message=f"mcp-scanner did not finish within {timeout}s.",
            source="cisco-yara",
            server=server.name,
        )]

    if proc.returncode != 0 or not proc.stdout.strip():
        detail = (proc.stderr or proc.stdout).strip()[:2000] or f"mcp-scanner exited {proc.returncode}"
        return [Finding(
            rule_id="mcp-guard/scanner-error",
            severity=Severity.MEDIUM,
            title=f"Security scan failed: {server.name}",
            message=detail,
            source="cisco-yara",
            server=server.name,
        )]

    try:
        payload = json.loads(proc.stdout)
        results = payload.get("scan_results", [])
    except (json.JSONDecodeError, TypeError, AttributeError) as exc:
        return [Finding(
            rule_id="mcp-guard/scanner-error",
            severity=Severity.MEDIUM,
            title=f"Security scan output unparseable: {server.name}",
            message=f"mcp-scanner raw output was not the expected JSON: {exc}",
            source="cisco-yara",
            server=server.name,
        )]

    findings: list[Finding] = []
    for result in results:
        if result.get("is_safe", True):
            continue
        yara = (result.get("findings") or {}).get("yara_analyzer") or {}
        severity = Severity.parse(str(yara.get("severity", "UNKNOWN")))
        threats = yara.get("threat_names") or ["unknown threat"]
        for threat in threats:
            rule = "cisco-yara/" + str(threat).lower().replace(" ", "-").replace("/", "-")
            findings.append(Finding(
                rule_id=rule,
                severity=severity,
                title=f"{threat} in tool '{result.get('tool_name', '?')}'",
                message=yara.get("threat_summary") or f"YARA flagged {threat}",
                source="cisco-yara",
                server=server.name,
                tool=result.get("tool_name"),
            ))
    return findings

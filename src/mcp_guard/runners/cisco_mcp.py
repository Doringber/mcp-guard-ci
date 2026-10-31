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
    """The mcp-scanner executable itself is missing."""


class CiscoScanError(RuntimeError):
    """The scan could not complete (server unreachable, timeout, bad output).

    Fail closed: an unscanned server is not a safe server, so the CLI turns
    this into a nonzero infrastructure exit instead of a finding that might
    sit below the configured severity gate.
    """


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
        raise CiscoScanError(
            f"security scan of '{server.name}' timed out after {timeout}s"
        )

    if proc.returncode != 0 or not proc.stdout.strip():
        detail = (proc.stderr or proc.stdout).strip()[:2000] or f"mcp-scanner exited {proc.returncode}"
        raise CiscoScanError(f"security scan of '{server.name}' failed: {detail}")

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise CiscoScanError(
            f"security scan of '{server.name}' returned unparseable output: {exc}"
        )
    return parse_scan_payload(payload, server.name)


def parse_scan_payload(payload: object, server_name: str) -> list[Finding]:
    """Validate mcp-scanner raw JSON strictly and convert unsafe results.

    Fail closed: anything malformed or incomplete raises CiscoScanError
    instead of risking a silent 'clean' verdict. Shape verified against
    cisco-ai-mcp-scanner 4.8.7: {"scan_results": [{"tool_name", "is_safe",
    "findings": {"yara_analyzer": {"severity", "threat_names",
    "threat_summary"}}}]}.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("scan_results"), list):
        raise CiscoScanError(
            f"security scan of '{server_name}' returned malformed output: "
            "expected an object with a 'scan_results' list"
        )
    findings: list[Finding] = []
    for i, result in enumerate(payload["scan_results"]):
        where = f"scan_results[{i}] for '{server_name}'"
        if not isinstance(result, dict) or not isinstance(result.get("is_safe"), bool):
            raise CiscoScanError(f"{where} is malformed: missing boolean 'is_safe'")
        if result["is_safe"]:
            continue
        f = result.get("findings")
        if not isinstance(f, dict) or not isinstance(f.get("yara_analyzer"), dict):
            raise CiscoScanError(f"{where} is unsafe but has no yara_analyzer findings object")
        yara = f["yara_analyzer"]
        severity_raw = yara.get("severity")
        if not isinstance(severity_raw, str):
            raise CiscoScanError(f"{where} is missing a string severity")
        try:
            severity = Severity.parse(severity_raw)
        except KeyError:
            raise CiscoScanError(f"{where} has unknown severity {severity_raw!r}")
        threats = yara.get("threat_names")
        if not isinstance(threats, list) or not threats or not all(isinstance(t, str) for t in threats):
            raise CiscoScanError(f"{where} is unsafe but names no threats")
        summary = yara.get("threat_summary")
        tool = result.get("tool_name")
        for threat in threats:
            rule = "cisco-yara/" + threat.lower().replace(" ", "-").replace("/", "-")
            findings.append(Finding(
                rule_id=rule,
                severity=severity,
                title=f"{threat} in tool '{tool or '?'}'",
                message=summary if isinstance(summary, str) else f"YARA flagged {threat}",
                source="cisco-yara",
                server=server_name,
                tool=tool if isinstance(tool, str) else None,
            ))
    return findings

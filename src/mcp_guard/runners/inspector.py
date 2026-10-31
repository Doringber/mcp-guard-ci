"""Functional smoke tests via the MCP Inspector CLI (npx @modelcontextprotocol/inspector).

Verified against Inspector v2: `--cli <target...> --method <m> --format json`
prints one JSON object `{"result": ...}` on stdout and uses exit code 0 on
success. A server that will not start exits non-zero.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

from ..models import Finding, ServerSpec, Severity, SmokeCall


class InspectorUnavailable(RuntimeError):
    pass


def _run(args: list[str], *, cwd: str | None, env_extra: dict[str, str], timeout: int) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update(env_extra)
    return subprocess.run(
        args,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _cli_base(inspector_command: str) -> list[str]:
    return shlex.split(inspector_command) + ["--cli"]


def list_tools(server: ServerSpec, *, inspector_command: str, timeout: int) -> tuple[list[dict], Finding | None]:
    """Return (tools, error_finding). error_finding is set when the server
    cannot be started or queried."""
    args = _cli_base(inspector_command) + server.command + [
        "--method", "tools/list", "--format", "json",
    ]
    try:
        proc = _run(args, cwd=server.cwd, env_extra=server.env, timeout=timeout)
    except FileNotFoundError as exc:
        raise InspectorUnavailable(
            f"could not run the MCP Inspector ({inspector_command!r}): {exc}. "
            "Install Node.js >= 22 and make sure npx is on PATH."
        ) from exc
    except subprocess.TimeoutExpired:
        return [], Finding(
            rule_id="mcp-guard/functional-server-start",
            severity=Severity.HIGH,
            title=f"Server '{server.name}' timed out",
            message=f"tools/list did not finish within {timeout}s.",
            source="inspector",
            server=server.name,
        )
    if proc.returncode != 0:
        return [], Finding(
            rule_id="mcp-guard/functional-server-start",
            severity=Severity.HIGH,
            title=f"Server '{server.name}' failed to start or list tools",
            message=(proc.stderr or proc.stdout).strip()[:2000] or f"inspector exited {proc.returncode}",
            source="inspector",
            server=server.name,
        )
    try:
        payload = json.loads(proc.stdout)
        tools = payload["result"]["tools"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        return [], Finding(
            rule_id="mcp-guard/functional-server-start",
            severity=Severity.HIGH,
            title=f"Server '{server.name}' returned an unparseable tool list",
            message=f"inspector output was not the expected JSON: {exc}",
            source="inspector",
            server=server.name,
        )
    return tools, None


def _needs_no_args(tool: dict) -> bool:
    schema = tool.get("inputSchema") or {}
    return not schema.get("required")


def call_tool(server: ServerSpec, tool: str, args: dict, *, inspector_command: str, timeout: int) -> tuple[bool, str]:
    """Call one tool. Returns (ok, detail)."""
    cmd = _cli_base(inspector_command) + server.command + [
        "--method", "tools/call", "--tool-name", tool,
        "--tool-args-json", json.dumps(args), "--format", "json",
    ]
    try:
        proc = _run(cmd, cwd=server.cwd, env_extra=server.env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"tools/call {tool} timed out after {timeout}s"
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()[:1000] or f"inspector exited {proc.returncode}"
    try:
        result = json.loads(proc.stdout)["result"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        return False, f"unparseable tools/call result: {exc}"
    if result.get("isError"):
        text = " ".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict))
        return False, f"tool returned isError: {text[:1000]}"
    text = " ".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict))
    if result.get("structuredContent") is not None:
        text += " " + json.dumps(result["structuredContent"])
    return True, text


def planned_calls(tools: list[dict], server: ServerSpec, auto_smoke: bool) -> list[SmokeCall]:
    """Smoke calls to run for a server.

    Default is deliberately conservative: only explicitly configured calls.
    A tool that takes no arguments can still mutate or delete state, so
    auto-calling every no-required-args tool requires auto_smoke=True.
    """
    calls = list(server.smoke)
    if auto_smoke:
        configured = {c.tool for c in server.smoke}
        calls += [SmokeCall(tool=t["name"]) for t in tools if _needs_no_args(t) and t["name"] not in configured]
    return calls


def smoke_server(server: ServerSpec, *, inspector_command: str, timeout: int, auto_smoke: bool = False) -> tuple[list[dict], list[Finding]]:
    """List tools, then run the planned smoke calls. Returns (tools, findings)."""
    tools, err = list_tools(server, inspector_command=inspector_command, timeout=timeout)
    if err is not None:
        return [], [err]

    findings: list[Finding] = []
    calls = planned_calls(tools, server, auto_smoke)
    seen: set[str] = set()
    for call in calls:
        key = f"{call.tool}:{json.dumps(call.args, sort_keys=True)}"
        if key in seen:
            continue
        seen.add(key)
        ok, detail = call_tool(server, call.tool, call.args, inspector_command=inspector_command, timeout=timeout)
        if not ok:
            findings.append(Finding(
                rule_id="mcp-guard/functional-smoke-call",
                severity=Severity.HIGH,
                title=f"Smoke call failed: {server.name}/{call.tool}",
                message=detail,
                source="inspector",
                server=server.name,
                tool=call.tool,
            ))
        elif call.expect_contains and call.expect_contains not in detail:
            findings.append(Finding(
                rule_id="mcp-guard/functional-smoke-call",
                severity=Severity.HIGH,
                title=f"Smoke call mismatch: {server.name}/{call.tool}",
                message=f"expected output to contain {call.expect_contains!r}, got {detail[:500]!r}",
                source="inspector",
                server=server.name,
                tool=call.tool,
            ))
    return tools, findings

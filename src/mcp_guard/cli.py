"""mcp-guard CLI: `mcp-guard run --config mcp-guard.yml`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config
from .discover import discover_servers, discover_skills
from .models import Finding, Severity
from .report.sarif import build_sarif
from .runners.cisco_mcp import CiscoScannerUnavailable, scan_server
from .runners.inspector import InspectorUnavailable, smoke_server


def _summary(findings: list[Finding], server_tools: dict[str, list[dict]], skill_files: list[Path], fail_on: Severity) -> str:
    lines = ["## mcp-guard-ci report", ""]
    for name, tools in server_tools.items():
        lines.append(f"- **{name}**: {len(tools)} tool(s): {', '.join(t['name'] for t in tools) or '(none)'}")
    if skill_files:
        lines.append(f"- **skills discovered**: {len(skill_files)} SKILL.md file(s) (skill scanning lands in milestone 2)")
    lines.append("")
    if not findings:
        lines.append("No findings. All checks passed.")
    else:
        lines.append(f"**{len(findings)} finding(s):**")
        lines.append("")
        for f in findings:
            where = f.server or f.path or "?"
            if f.tool:
                where += f"/{f.tool}"
            lines.append(f"- [{f.severity.name}] `{f.rule_id}` in **{where}** ({f.source}): {f.title}")
    gate = [f for f in findings if f.severity >= fail_on]
    lines.append("")
    lines.append(f"**Verdict:** {'FAIL' if gate else 'PASS'} (fail_on={fail_on.name.lower()}, {len(gate)} finding(s) at or above threshold)")
    return "\n".join(lines)


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-guard", description="Functional + security CI guard for MCP servers and skills")
    parser.add_argument("--version", action="version", version=f"mcp-guard-ci {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run", help="run all checks and write a SARIF report")
    run_p.add_argument("--config", default="mcp-guard.yml")
    run_p.add_argument("--root", default=".", help="repository root used for discovery")
    run_p.add_argument("--sarif", default="mcp-guard-results.sarif", help="SARIF output path")
    run_p.add_argument("--fail-on", choices=["low", "medium", "high"], default=None, help="override config fail_on")
    run_p.add_argument("--skip-smoke", action="store_true", help="skip Inspector functional smoke tests")
    run_p.add_argument("--skip-scan", action="store_true", help="skip Cisco security scan")
    args = parser.parse_args(argv)

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"mcp-guard: {exc}", file=sys.stderr)
        return 2
    if args.fail_on:
        cfg.fail_on = Severity.parse(args.fail_on)

    root = Path(args.root).resolve()
    servers = list(cfg.servers)
    if cfg.discover:
        known = {s.name for s in servers}
        servers += [s for s in discover_servers(root) if s.name not in known]
    skill_files = discover_skills(root, cfg.skills_glob)

    if not servers:
        print("mcp-guard: no MCP servers configured or discovered; nothing to check.", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    server_tools: dict[str, list[dict]] = {}
    do_smoke = cfg.inspector_enabled and not args.skip_smoke
    do_scan = cfg.cisco_enabled and not args.skip_scan

    for server in servers:
        if do_smoke:
            tools, smoke_findings = smoke_server(
                server, inspector_command=cfg.inspector_command, timeout=cfg.smoke_timeout,
            )
            server_tools[server.name] = tools
            findings += smoke_findings
        if do_scan:
            findings += scan_server(server, cisco_command=cfg.cisco_command, timeout=cfg.scan_timeout)

    sarif = build_sarif(findings)
    sarif_path = Path(args.sarif)
    sarif_path.write_text(json.dumps(sarif, indent=2))
    print(_summary(findings, server_tools, skill_files, cfg.fail_on))
    print(f"\nSARIF written to {sarif_path}")

    return 1 if any(f.severity >= cfg.fail_on for f in findings) else 0


def main() -> None:
    try:
        code = run()
    except (InspectorUnavailable, CiscoScannerUnavailable) as exc:
        print(f"mcp-guard: {exc}", file=sys.stderr)
        sys.exit(2)
    sys.exit(code)


if __name__ == "__main__":
    main()

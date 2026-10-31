# mcp-guard-ci

A GitHub Action that tests and security-scans **MCP servers, agent skills and plugins** on every pull request - functional QA and AI security in one CI step.

Status: milestone 1 implemented (see the roadmap below). See [PLAN.md](PLAN.md) for the full spec and milestones.

One GitHub Action that guards MCP servers (and soon `SKILL.md` skills and
agent plugins) on every pull request:

1. **Functional** — each server is started and probed with the
   [MCP Inspector CLI](https://github.com/modelcontextprotocol/inspector):
   `tools/list` must succeed, and smoke calls (every no-arg tool plus any
   calls you configure) must not error.
2. **Security** — [Cisco mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)
   runs its local YARA engine over every tool's name, description and schema
   (prompt injection, credential harvesting, tool poisoning). No API key.
3. **One SARIF report** — all findings land in `mcp-guard-results.sarif`,
   which the action uploads to the GitHub Security tab. The build fails on
   findings at or above `fail_on` (default `high`).

Rug-pull detection (a lockfile of tool hashes, failing CI when a tool's
description or schema silently changes) is milestone 3 and not in this MVP.

## Install

```bash
pip install .
uv tool install cisco-ai-mcp-scanner   # YARA engine, runs locally
# Node.js >= 22 for: npx @modelcontextprotocol/inspector
```

## Run

```bash
mcp-guard run --config mcp-guard.yml --sarif mcp-guard-results.sarif
```

Exit code is `1` when any finding meets `fail_on`, `2` on config/tool errors.

## Config (`mcp-guard.yml`)

```yaml
servers:
  - name: my-server
    command: ["python", "server.py"]     # anything that speaks MCP over stdio
    smoke:                                # optional explicit smoke calls
      - tool: add
        args: {a: 2, b: 3}
        expect_contains: "5"
fail_on: high          # low | medium | high
discover: true         # also read .cursor/mcp.json, .vscode/mcp.json, mcp.json, ...
skills_glob: "skills/**/SKILL.md"
```

Servers you list explicitly win over discovered ones with the same name.
Tools whose `inputSchema` has no required properties are smoke-called
automatically with `{}`.

## Use as a GitHub Action

See `examples/workflow.yml`. The action installs Python 3.11, Node 22, uv,
Cisco mcp-scanner and this package, runs `mcp-guard`, and uploads the SARIF
even when the check fails.

## Development

```bash
uv sync
uv run pytest tests/unit          # fast, no external tools
uv run pytest tests/integration   # real Inspector + mcp-scanner runs on
                                  # tests/fixtures (clean + poisoned servers)
```

`tests/fixtures/poisoned_server.py` and `tests/fixtures/skills/evil-helper/`
are defensive test data: inert malicious-looking text, never executed.

## Layout

```
src/mcp_guard/
  cli.py            # mcp-guard run
  config.py         # mcp-guard.yml parsing
  discover.py       # well-known MCP configs + SKILL.md discovery
  runners/
    inspector.py    # functional smoke via MCP Inspector CLI
    cisco_mcp.py    # YARA scan via Cisco mcp-scanner
  report/
    sarif.py        # findings -> one SARIF 2.1.0 file
tests/fixtures/     # clean + poisoned MCP servers, malicious SKILL.md
examples/workflow.yml
.github/actions/mcp-guard/action.yml
```

Each scanner sits behind a small adapter (`runners/*.py`), so a breaking
change in one upstream tool only touches its own wrapper.

## Roadmap

- [x] MVP: discovery + Inspector smoke + Cisco YARA scan + SARIF
- [ ] Cisco skill-scanner on `SKILL.md` files (fixture already present)
- [ ] Rug-pull lockfile: `mcp-guard lock` writes `mcp-tools.lock.json`;
      CI fails when a tool's description/schema changes without a lock update
- [ ] Optional mcp-eval E2E evals
- [ ] PR comment summary, Marketplace publish, demo GIF
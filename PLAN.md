# mcp-guard-ci — Project Plan

## Goal
One GitHub Action that, on every PR touching an MCP server, a `SKILL.md` skill, or an agent plugin, runs:
1. **Functional tests** — does the MCP server start, list its tools, and answer correctly?
2. **Security scans** — prompt injection, tool poisoning, tool shadowing, data exfiltration, malicious code in skills.
3. **Rug-pull detection** — catch a tool whose name/description/schema silently changed after it was approved (most existing scanners don't do this).

Output: one SARIF report (shows in the GitHub Security tab) + a short PR comment summary. Fails the build on high-severity findings.

## Building blocks (don't reinvent — wrap these)
| Layer | Tool | Link |
|---|---|---|
| Functional | MCP Inspector CLI | https://github.com/modelcontextprotocol/inspector |
| Functional / E2E | mcp-eval (LastMile AI) | https://github.com/lastmile-ai/mcp-eval |
| Security (MCP) | Cisco MCP Scanner (YARA, runs locally, no key) | https://github.com/cisco-ai-defense/mcp-scanner |
| Security (skills) | Cisco Skill Scanner (has SARIF + GH Action) | https://github.com/cisco-ai-defense/skill-scanner |
| Security (optional) | Snyk Agent Scan (needs free token) | https://github.com/snyk/agent-scan |
| Red-team (optional) | promptfoo MCP plugin | https://github.com/promptfoo/promptfoo |

## Architecture
```
.github/actions/mcp-guard/action.yml   # composite action entry point
src/mcp_guard/
  cli.py            # `mcp-guard run --config mcp-guard.yml`
  discover.py       # find MCP configs, servers, SKILL.md files in the repo
  runners/
    inspector.py    # start server, list tools/prompts/resources, smoke-call
    mcp_eval.py     # run user-defined E2E evals
    cisco_mcp.py    # wrap mcp-scanner
    cisco_skill.py  # wrap skill-scanner
  rugpull/
    snapshot.py     # hash name+description+inputSchema per tool -> mcp-tools.lock.json
    diff.py         # compare current vs lock, flag changed/added/removed tools
  report/
    sarif.py        # merge all findings into one SARIF file
    pr_comment.py   # markdown summary
tests/
  fixtures/         # a clean MCP server + a deliberately poisoned one + a malicious SKILL.md
examples/
  workflow.yml
```
Language: Python 3.11, pytest. Package with `uv` or `pip`.

## Config (`mcp-guard.yml` in the target repo)
```yaml
servers:
  - name: my-server
    command: ["python", "server.py"]
skills_glob: "skills/**/SKILL.md"
fail_on: high          # low | medium | high
rugpull:
  lockfile: mcp-tools.lock.json
```

## Milestones
1. **MVP (weekend 1)** — discovery + MCP Inspector smoke test + Cisco MCP Scanner, SARIF output, works on the `tests/fixtures` servers.
2. **Skills** — add Cisco Skill Scanner on `SKILL.md` files; poisoned-skill fixture must be caught.
3. **Rug-pull lockfile** — `mcp-guard lock` writes the lockfile; CI fails if a tool's description/schema changed without updating the lock. This is the differentiator.
4. **E2E evals** — optional mcp-eval integration.
5. **Polish** — PR comment, README with screenshots of the Security tab, publish to GitHub Marketplace, demo GIF.

## Definition of done (MVP)
- `act` or a real PR run on this repo shows: clean server passes, poisoned server fails with a readable SARIF finding.
- Unit tests for discover, rugpull diff, and SARIF merge; CI green.
- README explains install in < 10 lines.

## Notes for the developer
- Keep each scanner behind a small adapter so one breaking change doesn't kill the whole action.
- Run scanners in parallel; cache their installs in the Action.
- No secrets required for the default path (Cisco YARA engine runs locally). Snyk / LLM-judge modes are opt-in.

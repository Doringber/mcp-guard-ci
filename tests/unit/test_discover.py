import json

from mcp_guard.discover import discover_servers, discover_skills


def test_discovers_well_known_config(tmp_path):
    cfg = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}}}
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(json.dumps(cfg))
    servers = discover_servers(tmp_path)
    assert len(servers) == 1
    assert servers[0].name == "fs"
    assert servers[0].command == ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    assert servers[0].source.endswith(".cursor/mcp.json")


def test_first_file_wins_on_duplicate_name(tmp_path):
    for rel in ["mcp.json", ".mcp.json"]:
        (tmp_path / rel).write_text(json.dumps({"mcpServers": {"dup": {"command": "python", "args": [rel]}}}))
    servers = discover_servers(tmp_path)
    assert len(servers) == 1
    assert servers[0].command == ["python", "mcp.json"]


def test_ignores_broken_json_and_missing_command(tmp_path):
    (tmp_path / "mcp.json").write_text("{not json")
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"nocmd": {"args": []}}}))
    assert discover_servers(tmp_path) == []


def test_discovers_skills(tmp_path):
    skill = tmp_path / "skills" / "helper" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: helper\n---\n")
    (tmp_path / "skills" / "helper" / "other.md").write_text("nope")
    found = discover_skills(tmp_path)
    assert found == [skill]


def test_env_is_stringified(tmp_path):
    cfg = {"mcpServers": {"s": {"command": "python", "args": ["s.py"], "env": {"PORT": 8080}}}}
    (tmp_path / "mcp.json").write_text(json.dumps(cfg))
    assert discover_servers(tmp_path)[0].env == {"PORT": "8080"}

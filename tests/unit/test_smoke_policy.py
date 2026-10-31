from mcp_guard.models import ServerSpec, SmokeCall
from mcp_guard.runners.inspector import planned_calls

TOOLS = [
    {"name": "delete_everything", "inputSchema": {"type": "object"}},          # no required args
    {"name": "add", "inputSchema": {"type": "object", "required": ["a", "b"]}},
]


def _server(**kw):
    return ServerSpec(name="s", command=["python", "s.py"], **kw)


def test_default_runs_only_configured_calls():
    # A no-argument tool can still mutate state: never auto-called by default.
    server = _server()
    assert planned_calls(TOOLS, server, auto_smoke=False) == []


def test_configured_smoke_always_runs():
    server = _server(smoke=[SmokeCall(tool="add", args={"a": 1, "b": 2})])
    calls = planned_calls(TOOLS, server, auto_smoke=False)
    assert [c.tool for c in calls] == ["add"]


def test_auto_smoke_opt_in_adds_no_arg_tools_without_duplicating():
    server = _server(smoke=[SmokeCall(tool="delete_everything", args={})])
    calls = planned_calls(TOOLS, server, auto_smoke=True)
    assert [c.tool for c in calls] == ["delete_everything"]  # not duplicated
    server2 = _server()
    calls2 = planned_calls(TOOLS, server2, auto_smoke=True)
    assert [c.tool for c in calls2] == ["delete_everything"]

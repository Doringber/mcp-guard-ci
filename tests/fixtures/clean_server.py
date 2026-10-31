"""Clean MCP server fixture for mcp-guard-ci tests."""
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("clean-fixture", version="0.1.0")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return the sum."""
    return a + b


@mcp.tool()
def greet(name: str = "world") -> str:
    """Return a friendly greeting."""
    return f"Hello, {name}!"


if __name__ == "__main__":
    mcp.run()

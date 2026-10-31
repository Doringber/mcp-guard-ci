import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"


def tools_available() -> bool:
    return shutil.which("mcp-scanner") is not None and shutil.which("npx") is not None


requires_integration = pytest.mark.skipif(
    not tools_available(),
    reason="needs mcp-scanner and npx on PATH",
)

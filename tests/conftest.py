import asyncio
import sys

import pytest


@pytest.fixture
def event_loop_policy():
    if sys.platform == "win32":
        return asyncio.WindowsProactorEventLoopPolicy()
    return asyncio.DefaultEventLoopPolicy()

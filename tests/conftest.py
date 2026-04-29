import pytest


@pytest.fixture
def event_loop_policy():
    import asyncio
    return asyncio.WindowsProactorEventLoopPolicy()

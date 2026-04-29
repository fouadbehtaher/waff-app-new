import asyncio
import os
import pytest
import pytest_asyncio
import tempfile
from src.waf.async_database import AsyncWAFDatabase


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest_asyncio.fixture
async def async_db(db_path):
    db = AsyncWAFDatabase(db_path)
    await db.initialize()
    yield db
    await db.close()


class TestAsyncDatabaseInit:
    async def test_initializes_successfully(self, async_db):
        assert async_db._running is True

    async def test_creates_all_tables(self, async_db):
        async with async_db._pool.acquire() as conn:
            cursor = await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = {row[0] for row in await cursor.fetchall()}
            expected = {
                "request_logs", "ip_blacklist", "ip_violations",
                "rate_limit_stats", "waf_config", "threat_stats",
                "daily_summary", "ml_features"
            }
            assert expected.issubset(tables)

    async def test_double_init_no_error(self, db_path):
        db = AsyncWAFDatabase(db_path)
        await db.initialize()
        await db.initialize()
        assert db._running is True
        await db.close()


class TestAsyncConnectionPooling:
    async def test_acquire_returns_valid_conn(self, async_db):
        async with async_db._pool.acquire() as conn:
            assert conn is not None

    async def test_concurrent_connections(self, async_db):
        async def use_conn():
            async with async_db._pool.acquire() as conn:
                return conn is not None
        results = await asyncio.gather(*[use_conn() for _ in range(5)])
        assert all(results)


class TestAsyncBatchLogWriter:
    async def test_batch_flushes_after_interval(self, async_db):
        await async_db.log_request(
            method="GET", path="/test", query_string="", source_ip="192.168.1.1",
            user_agent="test", decision="allow", threat_level="safe",
            confidence=0.0, reason="", analysis_time_ms=10
        )
        await asyncio.sleep(6.0)
        logs = await async_db.get_logs()
        assert len(logs) >= 1

    async def test_batch_preserves_multiple_logs(self, async_db):
        for i in range(3):
            await async_db.log_request(
                method="GET", path=f"/test/{i}", query_string="", source_ip=f"192.168.1.{i}",
                user_agent="test", decision="allow", threat_level="safe",
                confidence=0.0, reason="", analysis_time_ms=10
            )
        await asyncio.sleep(6.0)
        logs = await async_db.get_logs()
        assert len(logs) >= 3


class TestAsyncBlacklistOperations:
    async def test_add_violation(self, async_db):
        await async_db.blacklist_add_violation("192.168.1.100", "sqli", "high")
        all_entries = await async_db.blacklist_get_all()
        assert any(e["ip"] == "192.168.1.100" for e in all_entries)

    async def test_ban_ip(self, async_db):
        await async_db.blacklist_ban("192.168.1.101", "test ban")
        is_blocked = await async_db.blacklist_is_blocked("192.168.1.101")
        assert is_blocked

    async def test_unban_ip(self, async_db):
        await async_db.blacklist_ban("192.168.1.102", "temp ban")
        await async_db.blacklist_unban("192.168.1.102")
        is_blocked = await async_db.blacklist_is_blocked("192.168.1.102")
        assert not is_blocked

    async def test_permanent_ban(self, async_db):
        await async_db.blacklist_ban("192.168.1.103", "perm ban", permanent=True)
        is_blocked = await async_db.blacklist_is_blocked("192.168.1.103")
        assert is_blocked

    async def test_clean_ip_not_blocked(self, async_db):
        is_blocked = await async_db.blacklist_is_blocked("192.168.1.200")
        assert not is_blocked


class TestAsyncRateLimitOperations:
    async def test_update_rate_limit(self, async_db):
        async with async_db._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO rate_limit_stats (ip, request_count) VALUES (?, ?)",
                ("192.168.1.50", 10)
            )
        result = await async_db.rate_limit_get("192.168.1.50")
        assert result is not None
        assert result["request_count"] == 10


class TestAsyncClose:
    async def test_close_twice_no_error(self, db_path):
        db = AsyncWAFDatabase(db_path)
        await db.initialize()
        await db.close()
        await db.close()

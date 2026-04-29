import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from src.waf.redis_cache import RedisCache, REDIS_AVAILABLE


class TestRedisCacheConnect:
    @pytest.mark.asyncio
    async def test_connect_without_redis_package(self):
        if REDIS_AVAILABLE:
            pytest.skip("redis package is installed")
        cache = RedisCache("redis://localhost:6379/0")
        await cache.connect()
        assert cache.is_connected() is False

    @pytest.mark.asyncio
    async def test_connect_fails_on_bad_url(self):
        if not REDIS_AVAILABLE:
            pytest.skip("redis package not installed")
        cache = RedisCache("redis://nonexistent-host:9999/0")
        await cache.connect()
        assert cache.is_connected() is False

    @pytest.mark.asyncio
    async def test_close_no_error_when_not_connected(self):
        cache = RedisCache()
        await cache.close()
        assert cache.is_connected() is False


class TestRedisCacheRateLimitFallback:
    @pytest.mark.asyncio
    async def test_rate_limit_returns_fallback_when_not_connected(self):
        cache = RedisCache()
        result = await cache.rate_limit_check("192.168.1.1")
        assert result["allowed"] is True
        assert result["fallback"] is True

    @pytest.mark.asyncio
    async def test_rate_limit_count_returns_zero_when_not_connected(self):
        cache = RedisCache()
        count = await cache.rate_limit_get_count("192.168.1.1")
        assert count == 0

    @pytest.mark.asyncio
    async def test_rate_limit_stats_returns_empty_when_not_connected(self):
        cache = RedisCache()
        stats = await cache.rate_limit_get_stats()
        assert stats["total_requests_tracked"] == 0

    @pytest.mark.asyncio
    async def test_rate_limit_top_ips_returns_empty_when_not_connected(self):
        cache = RedisCache()
        top_ips = await cache.rate_limit_top_ips()
        assert top_ips == []


class TestRedisCacheBlacklistFallback:
    @pytest.mark.asyncio
    async def test_is_blocked_returns_false_when_not_connected(self):
        cache = RedisCache()
        assert await cache.blacklist_is_blocked("192.168.1.1") is False

    @pytest.mark.asyncio
    async def test_add_violation_returns_zero_when_not_connected(self):
        cache = RedisCache()
        count = await cache.blacklist_add_violation("192.168.1.1", "sqli", "high")
        assert count == 0

    @pytest.mark.asyncio
    async def test_ban_returns_when_not_connected(self):
        cache = RedisCache()
        result = await cache.blacklist_ban("192.168.1.1", "test ban")
        assert result is None

    @pytest.mark.asyncio
    async def test_unban_returns_when_not_connected(self):
        cache = RedisCache()
        result = await cache.blacklist_unban("192.168.1.1")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_all_returns_empty_when_not_connected(self):
        cache = RedisCache()
        entries = await cache.blacklist_get_all()
        assert entries == []

    @pytest.mark.asyncio
    async def test_get_stats_returns_empty_when_not_connected(self):
        cache = RedisCache()
        stats = await cache.blacklist_get_stats()
        assert stats["total_blacklisted"] == 0


class TestRedisCacheGenericFallback:
    @pytest.mark.asyncio
    async def test_get_returns_empty_when_not_connected(self):
        cache = RedisCache()
        result = await cache.get_all()
        assert result == {}

    @pytest.mark.asyncio
    async def test_set_returns_when_not_connected(self):
        cache = RedisCache()
        result = await cache.set("key", "value")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_value_returns_none_when_not_connected(self):
        cache = RedisCache()
        result = await cache.get_value("key")
        assert result is None


class TestRedisCacheWithMockRedis:
    @pytest.mark.asyncio
    async def test_rate_limit_check_with_redis(self):
        if not REDIS_AVAILABLE:
            pytest.skip("redis package not installed")
        mock_pipe = MagicMock()
        mock_pipe.execute = AsyncMock(return_value=[0, 10, 0, True])
        mock_client = MagicMock()
        mock_client.ping = AsyncMock(return_value=True)
        mock_client.pipeline.return_value = mock_pipe
        mock_client.keys = AsyncMock(return_value=[])
        with patch("src.waf.redis_cache.redis.from_url", return_value=mock_client):
            cache = RedisCache("redis://localhost:6379/0")
            await cache.connect()
            assert cache.is_connected() is True
            result = await cache.rate_limit_check("192.168.1.1", max_requests=100)
            assert result["allowed"] is True

    @pytest.mark.asyncio
    async def test_blacklist_is_blocked_with_redis(self):
        if not REDIS_AVAILABLE:
            pytest.skip("redis package not installed")
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        mock_client.hgetall = AsyncMock(return_value={"is_permanent": "1"})
        mock_client.keys = AsyncMock(return_value=[])
        with patch("src.waf.redis_cache.redis.from_url", return_value=mock_client):
            cache = RedisCache("redis://localhost:6379/0")
            await cache.connect()
            assert await cache.blacklist_is_blocked("192.168.1.1") is True

    @pytest.mark.asyncio
    async def test_blacklist_whitelisted_not_blocked(self):
        if not REDIS_AVAILABLE:
            pytest.skip("redis package not installed")
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        mock_client.hgetall = AsyncMock(return_value={"is_whitelisted": "1"})
        mock_client.keys = AsyncMock(return_value=[])
        with patch("src.waf.redis_cache.redis.from_url", return_value=mock_client):
            cache = RedisCache("redis://localhost:6379/0")
            await cache.connect()
            assert await cache.blacklist_is_blocked("192.168.1.1") is False

    @pytest.mark.asyncio
    async def test_close_disconnects(self):
        if not REDIS_AVAILABLE:
            pytest.skip("redis package not installed")
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        mock_client.close = AsyncMock()
        with patch("src.waf.redis_cache.redis.from_url", return_value=mock_client):
            cache = RedisCache("redis://localhost:6379/0")
            await cache.connect()
            await cache.close()
            assert cache.is_connected() is False

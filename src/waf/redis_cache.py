import json
import time
import structlog
from typing import Optional, Dict, List
from datetime import datetime, timedelta

logger = structlog.get_logger()

REDIS_AVAILABLE = False
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    pass


class RedisCache:
    def __init__(self, url: str = "redis://localhost:6379/0"):
        self.url = url
        self._client = None
        self._connected = False

    async def connect(self):
        if not REDIS_AVAILABLE:
            logger.warning("redis_not_available_falling_back_to_memory")
            return
        try:
            self._client = redis.from_url(self.url, decode_responses=True)
            await self._client.ping()
            self._connected = True
            logger.info("redis_connected", url=self.url)
        except Exception as e:
            logger.error("redis_connection_failed", error=str(e))
            self._connected = False

    async def close(self):
        if self._client:
            await self._client.close()
            self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    async def rate_limit_check(self, ip: str, max_requests: int = 100, window_seconds: int = 60) -> Dict:
        if not self._connected:
            return {"allowed": True, "fallback": True}
        key = f"rl:{ip}"
        now = time.time()
        pipe = self._client.pipeline()
        pipe.zremrangebyscore(key, 0, now - window_seconds)
        pipe.zcard(key)
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, window_seconds)
        results = await pipe.execute()
        count = results[1]
        if count >= max_requests:
            return {"allowed": False, "current": count, "limit": max_requests, "window": window_seconds}
        return {"allowed": True, "current": count + 1, "limit": max_requests, "window": window_seconds}

    async def rate_limit_get_count(self, ip: str, window_seconds: int = 60) -> int:
        if not self._connected:
            return 0
        key = f"rl:{ip}"
        now = time.time()
        await self._client.zremrangebyscore(key, 0, now - window_seconds)
        return await self._client.zcard(key)

    async def rate_limit_get_stats(self) -> Dict:
        if not self._connected:
            return {"total_requests_tracked": 0, "unique_ips": 0, "blocked_total": 0, "allowed_total": 0}
        keys = await self._client.keys("rl:*")
        total = 0
        for key in keys:
            total += await self._client.zcard(key)
        return {"total_requests_tracked": total, "unique_ips": len(keys), "blocked_total": 0, "allowed_total": 0}

    async def rate_limit_top_ips(self, limit: int = 10, window_seconds: int = 60) -> List:
        if not self._connected:
            return []
        keys = await self._client.keys("rl:*")
        ip_counts = []
        for key in keys:
            now = time.time()
            await self._client.zremrangebyscore(key, 0, now - window_seconds)
            count = await self._client.zcard(key)
            if count > 0:
                ip = key.replace("rl:", "")
                ip_counts.append({"ip": ip, "requests": count})
        ip_counts.sort(key=lambda x: x["requests"], reverse=True)
        return ip_counts[:limit]

    async def blacklist_is_blocked(self, ip: str) -> bool:
        if not self._connected:
            return False
        entry = await self._client.hgetall(f"bl:{ip}")
        if not entry:
            return False
        if entry.get("is_whitelisted") == "1":
            return False
        if entry.get("is_permanent") == "1":
            return True
        expires_at = entry.get("expires_at")
        if expires_at and datetime.fromisoformat(expires_at) > datetime.utcnow():
            return True
        if expires_at:
            await self._client.delete(f"bl:{ip}")
        return False

    async def blacklist_add_violation(self, ip: str, threat: str, threat_level: str) -> int:
        if not self._connected:
            return 0
        key = f"bl:{ip}"
        violation_key = f"blv:{ip}"
        await self._client.rpush(violation_key, json.dumps({"threat": threat, "threat_level": threat_level, "timestamp": datetime.utcnow().isoformat()}))
        await self._client.ltrim(violation_key, -20, -1)
        count = await self._client.incr(f"{key}:violations")
        await self._client.hset(key, mapping={
            "ip": ip,
            "violation_count": count,
            "threat_level": threat_level,
            "last_seen": datetime.utcnow().isoformat()
        })
        return count

    async def blacklist_ban(self, ip: str, reason: str, permanent: bool = False, duration_hours: float = 1):
        if not self._connected:
            return
        key = f"bl:{ip}"
        expires = (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat() if not permanent else None
        await self._client.hset(key, mapping={
            "ip": ip,
            "reason": reason,
            "is_permanent": "1" if permanent else "0",
            "banned_at": datetime.utcnow().isoformat(),
            "expires_at": expires or ""
        })
        if not permanent and expires:
            ttl = int(duration_hours * 3600)
            await self._client.expire(key, ttl)

    async def blacklist_unban(self, ip: str):
        if not self._connected:
            return
        await self._client.delete(f"bl:{ip}")
        await self._client.delete(f"blv:{ip}")

    async def blacklist_get_all(self) -> List:
        if not self._connected:
            return []
        keys = await self._client.keys("bl:*")
        entries = []
        for key in keys:
            if ":violations" in key:
                continue
            entry = await self._client.hgetall(key)
            if entry and entry.get("is_whitelisted") != "1":
                entries.append(entry)
        entries.sort(key=lambda x: int(x.get("violation_count", 0)), reverse=True)
        return entries

    async def blacklist_get_stats(self) -> Dict:
        if not self._connected:
            return {"total_blacklisted": 0, "active_bans": 0, "permanent_bans": 0, "total_ips_tracked": 0, "whitelisted": 0}
        keys = await self._client.keys("bl:*")
        total = 0
        permanent = 0
        whitelisted = 0
        tracked = 0
        for key in keys:
            if ":violations" in key:
                tracked += 1
                continue
            entry = await self._client.hgetall(key)
            if entry.get("is_whitelisted") == "1":
                whitelisted += 1
            else:
                total += 1
                if entry.get("is_permanent") == "1":
                    permanent += 1
        return {"total_blacklisted": total, "active_bans": total, "permanent_bans": permanent, "total_ips_tracked": tracked, "whitelisted": whitelisted}

    async def get_all(self) -> Dict:
        if not self._connected:
            return {}
        keys = await self._client.keys("*")
        return {k: await self._client.get(k) for k in keys[:100]}

    async def set(self, key: str, value: str, ttl: Optional[int] = None):
        if not self._connected:
            return
        await self._client.set(key, value, ex=ttl)

    async def get_value(self, key: str) -> Optional[str]:
        if not self._connected:
            return None
        return await self._client.get(key)


redis_cache = RedisCache()

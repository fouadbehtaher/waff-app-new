import aiosqlite
import sqlite3
import json
import asyncio
import structlog
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

logger = structlog.get_logger()

MAX_POOL_SIZE = 10


class ConnectionPool:
    def __init__(self, db_path: str, max_size: int = MAX_POOL_SIZE):
        self.db_path = db_path
        self.max_size = max_size
        self._pool: asyncio.Queue = asyncio.Queue(maxsize=max_size)
        self._initialized = False

    async def initialize(self):
        if self._initialized:
            return
        for _ in range(self.max_size):
            conn = await aiosqlite.connect(self.db_path)
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA journal_mode=WAL")
            await conn.execute("PRAGMA foreign_keys=ON")
            await self._pool.put(conn)
        self._initialized = True
        logger.info("connection_pool_initialized", path=self.db_path, size=self.max_size)

    @asynccontextmanager
    async def acquire(self):
        if not self._initialized:
            await self.initialize()
        conn = await self._pool.get()
        try:
            yield conn
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise
        finally:
            await self._pool.put(conn)

    async def close_all(self):
        while not self._pool.empty():
            conn = await self._pool.get()
            await conn.close()
        self._initialized = False
        logger.info("connection_pool_closed")


class AsyncWAFDatabase:
    def __init__(self, db_path: Optional[str] = None):
        if not db_path:
            db_path = str(Path(__file__).parent / "waf.db")
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._pool = ConnectionPool(db_path)
        self._batch_queue: asyncio.Queue = asyncio.Queue()
        self._batch_task: Optional[asyncio.Task] = None
        self._batch_interval = 5.0
        self._running = False

    async def initialize(self):
        await self._pool.initialize()
        await self._init_db()
        self._running = True
        self._batch_task = asyncio.create_task(self._batch_writer())
        logger.info("async_database_initialized", path=self.db_path)

    async def _init_db(self):
        async with self._pool.acquire() as conn:
            await conn.executescript("""
                CREATE TABLE IF NOT EXISTS request_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    query_string TEXT DEFAULT '',
                    source_ip TEXT NOT NULL,
                    user_agent TEXT DEFAULT '',
                    decision TEXT NOT NULL,
                    threat_level TEXT NOT NULL DEFAULT 'none',
                    confidence REAL DEFAULT 0.0,
                    reason TEXT DEFAULT '',
                    analysis_time_ms REAL DEFAULT 0.0,
                    strategies_json TEXT DEFAULT '[]',
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS ip_blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL UNIQUE,
                    reason TEXT DEFAULT '',
                    violation_count INTEGER DEFAULT 0,
                    threat_level TEXT DEFAULT 'none',
                    is_permanent INTEGER DEFAULT 0,
                    is_whitelisted INTEGER DEFAULT 0,
                    banned_at TEXT DEFAULT (datetime('now')),
                    expires_at TEXT,
                    last_seen TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS ip_violations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    threat TEXT DEFAULT '',
                    threat_level TEXT DEFAULT 'none',
                    timestamp TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS rate_limit_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    request_count INTEGER DEFAULT 0,
                    window_start TEXT,
                    window_end TEXT,
                    blocked INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS waf_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS threat_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    category TEXT NOT NULL,
                    count INTEGER DEFAULT 0,
                    UNIQUE(date, category)
                );
                CREATE TABLE IF NOT EXISTS daily_summary (
                    date TEXT PRIMARY KEY,
                    total_requests INTEGER DEFAULT 0,
                    blocked_requests INTEGER DEFAULT 0,
                    allowed_requests INTEGER DEFAULT 0,
                    avg_analysis_time_ms REAL DEFAULT 0.0,
                    top_threat TEXT DEFAULT 'none',
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS ml_features (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    method TEXT,
                    path_length INTEGER,
                    query_length INTEGER,
                    body_length INTEGER,
                    has_special_chars INTEGER,
                    has_sql_keywords INTEGER,
                    has_script_tags INTEGER,
                    has_traversal INTEGER,
                    has_command_chars INTEGER,
                    decision TEXT,
                    threat_level TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS ai_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signature_id TEXT UNIQUE,
                    pattern TEXT NOT NULL,
                    category TEXT,
                    threat_level TEXT DEFAULT 'low',
                    source TEXT,
                    status TEXT DEFAULT 'pending_review',
                    confidence REAL DEFAULT 0.5,
                    hit_count INTEGER DEFAULT 0,
                    review_count INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON request_logs(timestamp);
                CREATE INDEX IF NOT EXISTS idx_logs_ip ON request_logs(source_ip);
                CREATE INDEX IF NOT EXISTS idx_logs_decision ON request_logs(decision);
                CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON ip_blacklist(ip);
                CREATE INDEX IF NOT EXISTS idx_violations_ip ON ip_violations(ip);
            """)

    async def queue_log(self, **kwargs):
        await self._batch_queue.put(kwargs)

    async def _batch_writer(self):
        batch = []
        while self._running:
            try:
                item = await asyncio.wait_for(self._batch_queue.get(), timeout=self._batch_interval)
                batch.append(item)
                while True:
                    try:
                        item = self._batch_queue.get_nowait()
                        batch.append(item)
                    except asyncio.QueueEmpty:
                        break
                if batch:
                    await self._flush_batch(batch)
                    batch = []
            except asyncio.TimeoutError:
                if batch:
                    await self._flush_batch(batch)
                    batch = []
            except asyncio.CancelledError:
                if batch:
                    await self._flush_batch(batch)
                break

    async def _flush_batch(self, batch: List[Dict]):
        if not batch:
            return
        async with self._pool.acquire() as conn:
            await conn.executemany("""
                INSERT INTO request_logs (timestamp, method, path, query_string, source_ip, user_agent, decision, threat_level, confidence, reason, analysis_time_ms, strategies_json)
                VALUES (:timestamp, :method, :path, :query_string, :source_ip, :user_agent, :decision, :threat_level, :confidence, :reason, :analysis_time_ms, :strategies_json)
            """, batch)

    async def log_request(self, method, path, query_string, source_ip, user_agent, decision, threat_level, confidence, reason, analysis_time_ms, strategies_json="[]"):
        await self.queue_log(
            timestamp=datetime.utcnow().isoformat(),
            method=method, path=path, query_string=query_string,
            source_ip=source_ip, user_agent=user_agent, decision=decision,
            threat_level=threat_level, confidence=confidence, reason=reason,
            analysis_time_ms=analysis_time_ms, strategies_json=strategies_json
        )

    async def get_logs(self, limit=50, offset=0, decision_filter=None, threat_filter=None, ip_filter=None):
        query = "SELECT * FROM request_logs WHERE 1=1"
        params = []
        if decision_filter:
            query += " AND decision = ?"
            params.append(decision_filter)
        if threat_filter:
            query += " AND threat_level = ?"
            params.append(threat_filter)
        if ip_filter:
            query += " AND source_ip = ?"
            params.append(ip_filter)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        async with self._pool.acquire() as conn:
            async with conn.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def get_summary(self):
        async with self._pool.acquire() as conn:
            async with conn.execute("SELECT COUNT(*) as count FROM request_logs") as cursor:
                total_row = await cursor.fetchone()
            total = total_row["count"]
            async with conn.execute("SELECT COUNT(*) as count FROM request_logs WHERE decision = 'block'") as cursor:
                blocked_row = await cursor.fetchone()
            blocked = blocked_row["count"]
            async with conn.execute("SELECT COUNT(*) as count FROM request_logs WHERE decision = 'allow'") as cursor:
                allowed_row = await cursor.fetchone()
            allowed = allowed_row["count"]
            async with conn.execute("SELECT AVG(analysis_time_ms) as avg_time FROM request_logs") as cursor:
                avg_row = await cursor.fetchone()
            avg_time = avg_row["avg_time"] or 0
            threat_levels = {}
            async with conn.execute("SELECT threat_level, COUNT(*) as count FROM request_logs GROUP BY threat_level") as cursor:
                async for row in cursor:
                    threat_levels[row["threat_level"]] = row["count"]
            top_ips = []
            async with conn.execute("SELECT source_ip as ip, COUNT(*) as count FROM request_logs WHERE decision='block' GROUP BY source_ip ORDER BY count DESC LIMIT 10") as cursor:
                async for row in cursor:
                    top_ips.append(dict(row))
            top_paths = []
            async with conn.execute("SELECT path, COUNT(*) as count FROM request_logs WHERE decision='block' GROUP BY path ORDER BY count DESC LIMIT 10") as cursor:
                async for row in cursor:
                    top_paths.append(dict(row))
            return {
                "total_requests": total,
                "blocked": blocked,
                "allowed": allowed,
                "block_rate": round(blocked / total * 100, 2) if total > 0 else 0,
                "threat_levels": threat_levels,
                "top_blocked_paths": top_paths,
                "top_blocked_ips": top_ips,
                "avg_analysis_time_ms": round(avg_time, 2)
            }

    async def get_timeline(self, minutes=60):
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        async with self._pool.acquire() as conn:
            result = []
            async with conn.execute("SELECT threat_level, decision, COUNT(*) as count FROM request_logs WHERE timestamp > ? GROUP BY threat_level, decision", (cutoff,)) as cursor:
                async for row in cursor:
                    result.append({"threat_level": row["threat_level"], "decision": row["decision"], "count": row["count"]})
            return result

    async def get_strategy_stats(self):
        async with self._pool.acquire() as conn:
            strategy_stats = {}
            async with conn.execute("SELECT strategies_json, decision FROM request_logs") as cursor:
                async for log in cursor:
                    try:
                        strategies = json.loads(log["strategies_json"])
                    except (json.JSONDecodeError, TypeError):
                        strategies = []
                    for s in strategies:
                        name = s.get("name", "unknown")
                        if name not in strategy_stats:
                            strategy_stats[name] = {"name": name, "total": 0, "blocked": 0, "allowed": 0, "patterns_detected": {}}
                        strategy_stats[name]["total"] += 1
                        if log["decision"] == "block":
                            strategy_stats[name]["blocked"] += 1
                        else:
                            strategy_stats[name]["allowed"] += 1
                        for p in s.get("patterns", []):
                            strategy_stats[name]["patterns_detected"][p] = strategy_stats[name]["patterns_detected"].get(p, 0) + 1
            return list(strategy_stats.values())

    async def blacklist_add_violation(self, ip, threat, threat_level):
        async with self._pool.acquire() as conn:
            await conn.execute("INSERT INTO ip_violations (ip, threat, threat_level) VALUES (?, ?, ?)", (ip, threat, threat_level))
            await conn.execute("""
                INSERT INTO ip_blacklist (ip, violation_count, threat_level, last_seen)
                VALUES (?, 1, ?, datetime('now'))
                ON CONFLICT(ip) DO UPDATE SET violation_count = violation_count + 1, threat_level = ?, last_seen = datetime('now')
            """, (ip, threat_level, threat_level))
            cursor = await conn.execute("SELECT violation_count FROM ip_blacklist WHERE ip = ?", (ip,))
            row = await cursor.fetchone()
            return row["violation_count"] if row else 0

    async def blacklist_ban(self, ip, reason, permanent=False, duration_hours=1):
        expires = (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat() if not permanent else None
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO ip_blacklist (ip, reason, is_permanent, banned_at, expires_at)
                VALUES (?, ?, ?, datetime('now'), ?)
                ON CONFLICT(ip) DO UPDATE SET reason = ?, is_permanent = ?, banned_at = datetime('now'), expires_at = ?
            """, (ip, reason, permanent, expires, reason, permanent, expires))

    async def blacklist_unban(self, ip):
        async with self._pool.acquire() as conn:
            await conn.execute("DELETE FROM ip_blacklist WHERE ip = ?", (ip,))

    async def blacklist_is_blocked(self, ip):
        async with self._pool.acquire() as conn:
            cursor = await conn.execute("SELECT * FROM ip_blacklist WHERE ip = ? AND is_whitelisted = 0", (ip,))
            row = await cursor.fetchone()
            if not row:
                return False
            if row["is_permanent"]:
                return True
            if row["expires_at"]:
                if datetime.fromisoformat(row["expires_at"]) > datetime.utcnow():
                    return True
                await conn.execute("DELETE FROM ip_blacklist WHERE ip = ? AND is_permanent = 0 AND expires_at < ?", (ip, datetime.utcnow().isoformat()))
            return False

    async def blacklist_get_all(self):
        async with self._pool.acquire() as conn:
            result = []
            async with conn.execute("SELECT * FROM ip_blacklist WHERE is_whitelisted = 0 ORDER BY violation_count DESC") as cursor:
                async for row in cursor:
                    result.append(dict(row))
            return result

    async def blacklist_get_stats(self):
        async with self._pool.acquire() as conn:
            async with conn.execute("SELECT COUNT(*) as count FROM ip_blacklist WHERE is_whitelisted = 0") as cursor:
                total_row = await cursor.fetchone()
            total = total_row["count"]
            async with conn.execute("SELECT COUNT(*) as count FROM ip_blacklist WHERE is_permanent = 1") as cursor:
                perm_row = await cursor.fetchone()
            permanent = perm_row["count"]
            async with conn.execute("SELECT COUNT(DISTINCT ip) as count FROM ip_violations") as cursor:
                tracked_row = await cursor.fetchone()
            tracked = tracked_row["count"]
            async with conn.execute("SELECT COUNT(*) as count FROM ip_blacklist WHERE is_whitelisted = 1") as cursor:
                wl_row = await cursor.fetchone()
            whitelisted = wl_row["count"]
            return {"total_blacklisted": total, "active_bans": total, "permanent_bans": permanent, "total_ips_tracked": tracked, "whitelisted": whitelisted}

    async def rate_limit_get(self, ip):
        async with self._pool.acquire() as conn:
            cursor = await conn.execute("SELECT * FROM rate_limit_stats WHERE ip = ?", (ip,))
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def rate_limit_update(self, ip, count, blocked=False):
        async with self._pool.acquire() as conn:
            await conn.execute("UPDATE rate_limit_stats SET request_count = ?, blocked = blocked + ? WHERE ip = ?", (count, blocked, ip))

    async def extract_features(self, method, path, query_string, body_preview, decision, threat_level):
        features = {
            "method": method,
            "path_length": len(path),
            "query_length": len(query_string),
            "body_length": len(body_preview),
            "has_special_chars": 1 if any(c in query_string + body_preview for c in ["'", '"', "<", ">", ";", "|", "`"]) else 0,
            "has_sql_keywords": 1 if any(kw in (query_string + body_preview).lower() for kw in ["select", "union", "drop", "insert", "delete", "update", "or 1=1", "and 1=1"]) else 0,
            "has_script_tags": 1 if any(kw in (query_string + body_preview).lower() for kw in ["<script", "javascript:", "onerror=", "onload="]) else 0,
            "has_traversal": 1 if "../" in query_string or "..\\" in query_string else 0,
            "has_command_chars": 1 if any(c in query_string + body_preview for c in [";cat ", "|ls ", "&&", "`", "$("]) else 0,
            "decision": decision,
            "threat_level": threat_level
        }
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO ml_features (method, path_length, query_length, body_length, has_special_chars, has_sql_keywords, has_script_tags, has_traversal, has_command_chars, decision, threat_level)
                VALUES (:method, :path_length, :query_length, :body_length, :has_special_chars, :has_sql_keywords, :has_script_tags, :has_traversal, :has_command_chars, :decision, :threat_level)
            """, features)

    async def get_ml_training_data(self, limit=10000):
        async with self._pool.acquire() as conn:
            cursor = await conn.execute("SELECT * FROM ml_features ORDER BY id DESC LIMIT ?", (limit,))
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def cleanup_old_logs(self, days=30):
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        async with self._pool.acquire() as conn:
            cursor = await conn.execute("DELETE FROM request_logs WHERE timestamp < ?", (cutoff,))
            return cursor.rowcount

    async def close(self):
        self._running = False
        if self._batch_task:
            self._batch_task.cancel()
            try:
                await self._batch_task
            except asyncio.CancelledError:
                pass
        await self._pool.close_all()


async_waf_db = AsyncWAFDatabase()

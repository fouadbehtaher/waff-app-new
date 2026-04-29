import sqlite3
import json
import structlog
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

logger = structlog.get_logger()


class WAFDatabase:
    def __init__(self, db_path: Optional[str] = None):
        if not db_path:
            db_path = str(Path(__file__).parent / "waf.db")
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        logger.info("waf_database_initialized", path=db_path)

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
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
                timestamp TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (ip) REFERENCES ip_blacklist(ip)
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

            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON request_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_logs_ip ON request_logs(source_ip);
            CREATE INDEX IF NOT EXISTS idx_logs_decision ON request_logs(decision);
            CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON ip_blacklist(ip);
            CREATE INDEX IF NOT EXISTS idx_violations_ip ON ip_violations(ip);
        """)
        conn.commit()
        conn.close()

    def log_request(self, method, path, query_string, source_ip, user_agent, decision, threat_level, confidence, reason, analysis_time_ms, strategies_json="[]"):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO request_logs (timestamp, method, path, query_string, source_ip, user_agent, decision, threat_level, confidence, reason, analysis_time_ms, strategies_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (datetime.utcnow().isoformat(), method, path, query_string, source_ip, user_agent, decision, threat_level, confidence, reason, analysis_time_ms, strategies_json))
        conn.commit()
        conn.close()

    def get_logs(self, limit=50, offset=0, decision_filter=None, threat_filter=None, ip_filter=None):
        conn = self._get_conn()
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
        rows = conn.execute(query, params).fetchall()
        result = [dict(r) for r in rows]
        conn.close()
        return result

    def get_summary(self):
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) as count FROM request_logs").fetchone()["count"]
        blocked = conn.execute("SELECT COUNT(*) as count FROM request_logs WHERE decision = 'block'").fetchone()["count"]
        allowed = conn.execute("SELECT COUNT(*) as count FROM request_logs WHERE decision = 'allow'").fetchone()["count"]
        avg_time = conn.execute("SELECT AVG(analysis_time_ms) as avg_time FROM request_logs").fetchone()["avg_time"] or 0

        threat_levels = {}
        for row in conn.execute("SELECT threat_level, COUNT(*) as count FROM request_logs GROUP BY threat_level").fetchall():
            threat_levels[row["threat_level"]] = row["count"]

        top_ips = [dict(r) for r in conn.execute("SELECT source_ip as ip, COUNT(*) as count FROM request_logs WHERE decision='block' GROUP BY source_ip ORDER BY count DESC LIMIT 10").fetchall()]
        top_paths = [dict(r) for r in conn.execute("SELECT path, COUNT(*) as count FROM request_logs WHERE decision='block' GROUP BY path ORDER BY count DESC LIMIT 10").fetchall()]

        conn.close()
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

    def get_timeline(self, minutes=60):
        conn = self._get_conn()
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        rows = conn.execute("""
            SELECT threat_level, decision, COUNT(*) as count
            FROM request_logs
            WHERE timestamp > ?
            GROUP BY threat_level, decision
        """, (cutoff,)).fetchall()
        conn.close()
        result = []
        for row in rows:
            result.append({"threat_level": row["threat_level"], "decision": row["decision"], "count": row["count"]})
        return result

    def get_strategy_stats(self):
        conn = self._get_conn()
        logs = conn.execute("SELECT strategies_json, decision FROM request_logs").fetchall()
        conn.close()
        strategy_stats = {}
        for log in logs:
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

    def blacklist_add_violation(self, ip, threat, threat_level):
        conn = self._get_conn()
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("INSERT INTO ip_violations (ip, threat, threat_level) VALUES (?, ?, ?)", (ip, threat, threat_level))
        conn.execute("""
            INSERT INTO ip_blacklist (ip, violation_count, threat_level, last_seen)
            VALUES (?, 1, ?, datetime('now'))
            ON CONFLICT(ip) DO UPDATE SET violation_count = violation_count + 1, threat_level = ?, last_seen = datetime('now')
        """, (ip, threat_level, threat_level))
        conn.commit()
        count = conn.execute("SELECT violation_count FROM ip_blacklist WHERE ip = ?", (ip,)).fetchone()
        result = count["violation_count"] if count else 0
        conn.execute("PRAGMA foreign_keys=ON")
        conn.close()
        return result

    def blacklist_ban(self, ip, reason, permanent=False, duration_hours=1):
        conn = self._get_conn()
        expires = (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat() if not permanent else None
        conn.execute("""
            INSERT INTO ip_blacklist (ip, reason, is_permanent, banned_at, expires_at)
            VALUES (?, ?, ?, datetime('now'), ?)
            ON CONFLICT(ip) DO UPDATE SET reason = ?, is_permanent = ?, banned_at = datetime('now'), expires_at = ?
        """, (ip, reason, permanent, expires, reason, permanent, expires))
        conn.commit()
        conn.close()

    def blacklist_unban(self, ip):
        conn = self._get_conn()
        conn.execute("DELETE FROM ip_blacklist WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()

    def blacklist_is_blocked(self, ip):
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM ip_blacklist WHERE ip = ? AND is_whitelisted = 0", (ip,)).fetchone()
        if not row:
            conn.close()
            return False
        if row["is_permanent"]:
            conn.close()
            return True
        if row["expires_at"]:
            if datetime.fromisoformat(row["expires_at"]) > datetime.utcnow():
                conn.close()
                return True
            conn.execute("DELETE FROM ip_blacklist WHERE ip = ? AND is_permanent = 0 AND expires_at < ?", (ip, datetime.utcnow().isoformat()))
            conn.commit()
        conn.close()
        return False

    def blacklist_get_all(self):
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM ip_blacklist WHERE is_whitelisted = 0 ORDER BY violation_count DESC").fetchall()
        result = [dict(r) for r in rows]
        conn.close()
        return result

    def blacklist_get_stats(self):
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) as count FROM ip_blacklist WHERE is_whitelisted = 0").fetchone()["count"]
        permanent = conn.execute("SELECT COUNT(*) as count FROM ip_blacklist WHERE is_permanent = 1").fetchone()["count"]
        tracked = conn.execute("SELECT COUNT(DISTINCT ip) as count FROM ip_violations").fetchone()["count"]
        whitelisted = conn.execute("SELECT COUNT(*) as count FROM ip_blacklist WHERE is_whitelisted = 1").fetchone()["count"]
        conn.close()
        return {"total_blacklisted": total, "active_bans": total, "permanent_bans": permanent, "total_ips_tracked": tracked, "whitelisted": whitelisted}

    def rate_limit_get(self, ip):
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM rate_limit_stats WHERE ip = ?", (ip,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def rate_limit_update(self, ip, count, blocked=False):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO rate_limit_stats (ip, request_count, blocked)
            VALUES (?, ?, ?)
            ON CONFLICT DO NOTHING
        """, (ip, count, blocked))
        conn.execute("UPDATE rate_limit_stats SET request_count = ?, blocked = blocked + ? WHERE ip = ?", (count, blocked, ip))
        conn.commit()
        conn.close()

    def cleanup_old_logs(self, days=30):
        conn = self._get_conn()
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        deleted = conn.execute("DELETE FROM request_logs WHERE timestamp < ?", (cutoff,)).rowcount
        conn.commit()
        conn.close()
        return deleted

    def close(self):
        pass


waf_db = WAFDatabase()

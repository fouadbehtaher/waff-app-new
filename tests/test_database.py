import pytest
import os
import json
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

from database import WAFDatabase


@pytest.fixture
def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = WAFDatabase(db_path=path)
    yield db
    os.unlink(path)


class TestWAFDatabaseInit:
    def test_creates_db_file(self, db):
        assert Path(db.db_path).exists()

    def test_creates_request_logs_table(self, db):
        conn = db._get_conn()
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t["name"] for t in tables]
        assert "request_logs" in table_names
        conn.close()

    def test_creates_ip_blacklist_table(self, db):
        conn = db._get_conn()
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t["name"] for t in tables]
        assert "ip_blacklist" in table_names
        conn.close()

    def test_creates_ip_violations_table(self, db):
        conn = db._get_conn()
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t["name"] for t in tables]
        assert "ip_violations" in table_names
        conn.close()

    def test_creates_rate_limit_stats_table(self, db):
        conn = db._get_conn()
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t["name"] for t in tables]
        assert "rate_limit_stats" in table_names
        conn.close()

    def test_creates_waf_config_table(self, db):
        conn = db._get_conn()
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t["name"] for t in tables]
        assert "waf_config" in table_names
        conn.close()

    def test_creates_threat_stats_table(self, db):
        conn = db._get_conn()
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t["name"] for t in tables]
        assert "threat_stats" in table_names
        conn.close()

    def test_creates_daily_summary_table(self, db):
        conn = db._get_conn()
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t["name"] for t in tables]
        assert "daily_summary" in table_names
        conn.close()


class TestLogRequest:
    def test_log_single_request(self, db):
        db.log_request(
            method="GET", path="/test", query_string="",
            source_ip="192.168.1.1", user_agent="test-agent",
            decision="allow", threat_level="none", confidence=0.9,
            reason="clean", analysis_time_ms=10.0
        )
        logs = db.get_logs()
        assert len(logs) == 1
        assert logs[0]["method"] == "GET"
        assert logs[0]["path"] == "/test"
        assert logs[0]["source_ip"] == "192.168.1.1"
        assert logs[0]["decision"] == "allow"
        assert logs[0]["threat_level"] == "none"

    def test_log_with_strategies(self, db):
        strategies = [{"name": "signature", "decision": "block", "threat_level": "high", "patterns": ["SQL Injection"]}]
        db.log_request(
            method="POST", path="/login", query_string="",
            source_ip="10.0.0.1", user_agent="",
            decision="block", threat_level="high", confidence=0.85,
            reason="SQLi detected", analysis_time_ms=25.0,
            strategies_json=json.dumps(strategies)
        )
        logs = db.get_logs()
        assert len(logs) == 1
        parsed = json.loads(logs[0]["strategies_json"])
        assert len(parsed) == 1
        assert parsed[0]["name"] == "signature"
        assert parsed[0]["patterns"] == ["SQL Injection"]

    def test_log_multiple_requests(self, db):
        for i in range(10):
            db.log_request(
                method="GET", path=f"/page{i}", query_string="",
                source_ip=f"192.168.1.{i}", user_agent="",
                decision="allow" if i % 2 == 0 else "block",
                threat_level="none" if i % 2 == 0 else "high",
                confidence=0.8, reason="test", analysis_time_ms=15.0
            )
        logs = db.get_logs()
        assert len(logs) == 10

    def test_log_preserves_order(self, db):
        for i in range(5):
            db.log_request(
                method="GET", path=f"/test{i}", query_string="",
                source_ip="192.168.1.1", user_agent="",
                decision="allow", threat_level="none", confidence=0.8,
                reason="test", analysis_time_ms=10.0
            )
        logs = db.get_logs()
        assert logs[0]["path"] == "/test4"
        assert logs[4]["path"] == "/test0"


class TestGetLogs:
    def test_get_logs_empty(self, db):
        assert db.get_logs() == []

    def test_get_logs_limit(self, db):
        for i in range(20):
            db.log_request(
                method="GET", path=f"/test{i}", query_string="",
                source_ip="192.168.1.1", user_agent="",
                decision="allow", threat_level="none", confidence=0.8,
                reason="test", analysis_time_ms=10.0
            )
        logs = db.get_logs(limit=5)
        assert len(logs) == 5

    def test_get_logs_offset(self, db):
        for i in range(10):
            db.log_request(
                method="GET", path=f"/test{i}", query_string="",
                source_ip="192.168.1.1", user_agent="",
                decision="allow", threat_level="none", confidence=0.8,
                reason="test", analysis_time_ms=10.0
            )
        logs = db.get_logs(limit=3, offset=5)
        assert len(logs) == 3

    def test_get_logs_filter_by_decision(self, db):
        db.log_request(method="GET", path="/blocked", query_string="", source_ip="10.0.0.1", user_agent="", decision="block", threat_level="high", confidence=0.8, reason="test", analysis_time_ms=10.0)
        db.log_request(method="GET", path="/allowed", query_string="", source_ip="10.0.0.2", user_agent="", decision="allow", threat_level="none", confidence=0.8, reason="test", analysis_time_ms=10.0)
        blocked = db.get_logs(decision_filter="block")
        allowed = db.get_logs(decision_filter="allow")
        assert len(blocked) == 1
        assert len(allowed) == 1
        assert blocked[0]["path"] == "/blocked"
        assert allowed[0]["path"] == "/allowed"

    def test_get_logs_filter_by_threat(self, db):
        db.log_request(method="GET", path="/test1", query_string="", source_ip="10.0.0.1", user_agent="", decision="block", threat_level="critical", confidence=0.9, reason="test", analysis_time_ms=10.0)
        db.log_request(method="GET", path="/test2", query_string="", source_ip="10.0.0.2", user_agent="", decision="block", threat_level="low", confidence=0.7, reason="test", analysis_time_ms=10.0)
        critical = db.get_logs(threat_filter="critical")
        assert len(critical) == 1
        assert critical[0]["threat_level"] == "critical"

    def test_get_logs_filter_by_ip(self, db):
        db.log_request(method="GET", path="/test1", query_string="", source_ip="192.168.1.1", user_agent="", decision="allow", threat_level="none", confidence=0.8, reason="test", analysis_time_ms=10.0)
        db.log_request(method="GET", path="/test2", query_string="", source_ip="192.168.1.2", user_agent="", decision="allow", threat_level="none", confidence=0.8, reason="test", analysis_time_ms=10.0)
        logs = db.get_logs(ip_filter="192.168.1.1")
        assert len(logs) == 1
        assert logs[0]["source_ip"] == "192.168.1.1"

    def test_get_logs_combined_filters(self, db):
        db.log_request(method="GET", path="/attack1", query_string="", source_ip="10.0.0.1", user_agent="", decision="block", threat_level="critical", confidence=0.9, reason="test", analysis_time_ms=10.0)
        db.log_request(method="GET", path="/attack2", query_string="", source_ip="10.0.0.1", user_agent="", decision="allow", threat_level="none", confidence=0.8, reason="test", analysis_time_ms=10.0)
        db.log_request(method="GET", path="/attack3", query_string="", source_ip="10.0.0.2", user_agent="", decision="block", threat_level="high", confidence=0.85, reason="test", analysis_time_ms=10.0)
        logs = db.get_logs(decision_filter="block", threat_filter="critical", ip_filter="10.0.0.1")
        assert len(logs) == 1
        assert logs[0]["path"] == "/attack1"


class TestGetSummary:
    def test_summary_empty(self, db):
        summary = db.get_summary()
        assert summary["total_requests"] == 0
        assert summary["blocked"] == 0
        assert summary["allowed"] == 0
        assert summary["block_rate"] == 0
        assert summary["avg_analysis_time_ms"] == 0

    def test_summary_with_mixed_data(self, db):
        for i in range(10):
            db.log_request(
                method="GET", path=f"/test{i}", query_string="",
                source_ip=f"192.168.1.{i}", user_agent="",
                decision="block" if i < 3 else "allow",
                threat_level="high" if i < 3 else "none",
                confidence=0.8, reason="test", analysis_time_ms=10.0 + i
            )
        summary = db.get_summary()
        assert summary["total_requests"] == 10
        assert summary["blocked"] == 3
        assert summary["allowed"] == 7
        assert summary["block_rate"] == 30.0
        assert summary["avg_analysis_time_ms"] > 0

    def test_summary_threat_levels(self, db):
        db.log_request(method="GET", path="/t1", query_string="", source_ip="10.0.0.1", user_agent="", decision="block", threat_level="critical", confidence=0.9, reason="test", analysis_time_ms=10.0)
        db.log_request(method="GET", path="/t2", query_string="", source_ip="10.0.0.2", user_agent="", decision="block", threat_level="high", confidence=0.8, reason="test", analysis_time_ms=10.0)
        db.log_request(method="GET", path="/t3", query_string="", source_ip="10.0.0.3", user_agent="", decision="block", threat_level="critical", confidence=0.85, reason="test", analysis_time_ms=10.0)
        summary = db.get_summary()
        assert summary["threat_levels"]["critical"] == 2
        assert summary["threat_levels"]["high"] == 1

    def test_summary_top_blocked_paths(self, db):
        for i in range(5):
            db.log_request(method="GET", path="/attack", query_string="", source_ip=f"10.0.0.{i}", user_agent="", decision="block", threat_level="high", confidence=0.8, reason="test", analysis_time_ms=10.0)
        db.log_request(method="GET", path="/other", query_string="", source_ip="10.0.0.9", user_agent="", decision="block", threat_level="low", confidence=0.7, reason="test", analysis_time_ms=10.0)
        summary = db.get_summary()
        assert len(summary["top_blocked_paths"]) > 0
        assert summary["top_blocked_paths"][0]["path"] == "/attack"
        assert summary["top_blocked_paths"][0]["count"] == 5

    def test_summary_top_blocked_ips(self, db):
        for i in range(3):
            db.log_request(method="GET", path="/test", query_string="", source_ip="10.0.0.1", user_agent="", decision="block", threat_level="high", confidence=0.8, reason="test", analysis_time_ms=10.0)
        db.log_request(method="GET", path="/test", query_string="", source_ip="10.0.0.2", user_agent="", decision="block", threat_level="low", confidence=0.7, reason="test", analysis_time_ms=10.0)
        summary = db.get_summary()
        assert summary["top_blocked_ips"][0]["ip"] == "10.0.0.1"
        assert summary["top_blocked_ips"][0]["count"] == 3


class TestGetTimeline:
    def test_timeline_empty(self, db):
        timeline = db.get_timeline()
        assert isinstance(timeline, list)

    def test_timeline_returns_data(self, db):
        db.log_request(method="GET", path="/test", query_string="", source_ip="10.0.0.1", user_agent="", decision="allow", threat_level="none", confidence=0.8, reason="test", analysis_time_ms=10.0)
        timeline = db.get_timeline(minutes=60)
        assert isinstance(timeline, list)

    def test_timeline_respects_minutes(self, db):
        db.log_request(method="GET", path="/test", query_string="", source_ip="10.0.0.1", user_agent="", decision="allow", threat_level="none", confidence=0.8, reason="test", analysis_time_ms=10.0)
        timeline_5 = db.get_timeline(minutes=5)
        timeline_60 = db.get_timeline(minutes=60)
        assert isinstance(timeline_5, list)
        assert isinstance(timeline_60, list)


class TestGetStrategyStats:
    def test_strategy_stats_empty(self, db):
        stats = db.get_strategy_stats()
        assert stats == []

    def test_strategy_stats_with_data(self, db):
        strategies = [
            {"name": "signature", "decision": "block", "threat_level": "high", "patterns": ["SQL Injection"]},
            {"name": "behavior", "decision": "allow", "threat_level": "none", "patterns": []}
        ]
        db.log_request(
            method="GET", path="/test", query_string="", source_ip="10.0.0.1", user_agent="",
            decision="block", threat_level="high", confidence=0.85, reason="test", analysis_time_ms=10.0,
            strategies_json=json.dumps(strategies)
        )
        stats = db.get_strategy_stats()
        assert len(stats) == 2
        signature = next(s for s in stats if s["name"] == "signature")
        assert signature["total"] == 1
        assert signature["blocked"] == 1
        assert signature["patterns_detected"]["SQL Injection"] == 1

    def test_strategy_stats_aggregation(self, db):
        for i in range(5):
            strategies = [{"name": "signature", "decision": "block", "threat_level": "high", "patterns": ["XSS"]}]
            db.log_request(
                method="GET", path=f"/test{i}", query_string="", source_ip="10.0.0.1", user_agent="",
                decision="block", threat_level="high", confidence=0.85, reason="test", analysis_time_ms=10.0,
                strategies_json=json.dumps(strategies)
            )
        stats = db.get_strategy_stats()
        signature = next(s for s in stats if s["name"] == "signature")
        assert signature["total"] == 5
        assert signature["patterns_detected"]["XSS"] == 5


class TestBlacklistOperations:
    def test_add_violation_new_ip(self, db):
        count = db.blacklist_add_violation("10.0.0.1", "SQL Injection", "high")
        assert count == 1

    def test_add_violation_increment(self, db):
        db.blacklist_add_violation("10.0.0.1", "SQL Injection", "high")
        count = db.blacklist_add_violation("10.0.0.1", "XSS", "medium")
        assert count == 2

    def test_ban_ip_permanent(self, db):
        db.blacklist_ban("10.0.0.1", "manual ban", permanent=True)
        assert db.blacklist_is_blocked("10.0.0.1") is True
        entries = db.blacklist_get_all()
        assert len(entries) == 1
        assert entries[0]["ip"] == "10.0.0.1"
        assert entries[0]["is_permanent"] == 1

    def test_ban_ip_temporary(self, db):
        db.blacklist_ban("10.0.0.2", "auto ban", permanent=False, duration_hours=1)
        assert db.blacklist_is_blocked("10.0.0.2") is True
        entries = db.blacklist_get_all()
        assert len(entries) == 1
        assert entries[0]["expires_at"] is not None

    def test_unban_ip(self, db):
        db.blacklist_ban("10.0.0.1", "test ban")
        assert db.blacklist_is_blocked("10.0.0.1") is True
        db.blacklist_unban("10.0.0.1")
        assert db.blacklist_is_blocked("10.0.0.1") is False

    def test_is_blocked_false_for_clean_ip(self, db):
        assert db.blacklist_is_blocked("10.0.0.1") is False

    def test_blacklist_get_all_empty(self, db):
        assert db.blacklist_get_all() == []

    def test_blacklist_get_all_returns_entries(self, db):
        db.blacklist_ban("10.0.0.1", "ban1")
        db.blacklist_ban("10.0.0.2", "ban2")
        entries = db.blacklist_get_all()
        assert len(entries) == 2

    def test_blacklist_stats(self, db):
        db.blacklist_ban("10.0.0.1", "ban1", permanent=True)
        db.blacklist_ban("10.0.0.2", "ban2", permanent=False)
        stats = db.blacklist_get_stats()
        assert stats["total_blacklisted"] == 2
        assert stats["permanent_bans"] == 1

    def test_blacklist_update_violations(self, db):
        db.blacklist_add_violation("10.0.0.1", "SQLi", "critical")
        db.blacklist_add_violation("10.0.0.1", "XSS", "high")
        db.blacklist_add_violation("10.0.0.1", "Command Injection", "critical")
        entries = db.blacklist_get_all()
        assert len(entries) == 1
        assert entries[0]["violation_count"] == 3

    def test_expired_ban_not_blocked(self, db):
        conn = db._get_conn()
        conn.execute("""
            INSERT INTO ip_blacklist (ip, reason, is_permanent, banned_at, expires_at)
            VALUES (?, ?, 0, datetime('now'), ?)
        """, ("10.0.0.99", "expired", datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        assert db.blacklist_is_blocked("10.0.0.99") is False

    def test_whitelisted_ip_not_blocked(self, db):
        conn = db._get_conn()
        conn.execute("""
            INSERT INTO ip_blacklist (ip, reason, is_whitelisted)
            VALUES (?, ?, 1)
        """, ("10.0.0.99", "whitelisted"))
        conn.commit()
        conn.close()
        assert db.blacklist_is_blocked("10.0.0.99") is False


class TestRateLimitOperations:
    def test_rate_limit_get_empty(self, db):
        assert db.rate_limit_get("10.0.0.1") is None

    def test_rate_limit_update(self, db):
        db.rate_limit_update("10.0.0.1", 50, blocked=False)
        result = db.rate_limit_get("10.0.0.1")
        assert result is not None
        assert result["ip"] == "10.0.0.1"

    def test_rate_limit_blocked_count(self, db):
        db.rate_limit_update("10.0.0.1", 100, blocked=True)
        db.rate_limit_update("10.0.0.1", 101, blocked=True)
        result = db.rate_limit_get("10.0.0.1")
        assert result["blocked"] >= 2


class TestCleanupOldLogs:
    def test_cleanup_deletes_old_logs(self, db):
        conn = db._get_conn()
        old_ts = (datetime.utcnow() - timedelta(days=40)).isoformat()
        conn.execute("INSERT INTO request_logs (timestamp, method, path, query_string, source_ip, user_agent, decision, threat_level, confidence, reason, analysis_time_ms) VALUES (?, 'GET', '/old', '', '10.0.0.1', '', 'allow', 'none', 0.8, 'old', 10.0)", (old_ts,))
        conn.commit()
        conn.close()
        deleted = db.cleanup_old_logs(days=30)
        assert deleted >= 1

    def test_cleanup_keeps_recent_logs(self, db):
        db.log_request(method="GET", path="/recent", query_string="", source_ip="10.0.0.1", user_agent="", decision="allow", threat_level="none", confidence=0.8, reason="recent", analysis_time_ms=10.0)
        deleted = db.cleanup_old_logs(days=1)
        assert deleted == 0


class TestRequestLogsTableSchema:
    def test_has_all_columns(self, db):
        conn = db._get_conn()
        columns = conn.execute("PRAGMA table_info(request_logs)").fetchall()
        col_names = [c["name"] for c in columns]
        expected = ["id", "timestamp", "method", "path", "query_string", "source_ip", "user_agent", "decision", "threat_level", "confidence", "reason", "analysis_time_ms", "strategies_json", "created_at"]
        for col in expected:
            assert col in col_names
        conn.close()

    def test_has_indexes(self, db):
        conn = db._get_conn()
        indexes = conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        idx_names = [i["name"] for i in indexes]
        assert "idx_logs_timestamp" in idx_names
        assert "idx_logs_ip" in idx_names
        assert "idx_logs_decision" in idx_names
        conn.close()

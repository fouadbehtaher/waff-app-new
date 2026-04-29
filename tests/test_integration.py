import pytest
import os
import json
import tempfile
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from database import WAFDatabase
from request_log import RequestLogger
from models.request import RequestMetadata, Decision, ThreatLevel, AIAnalysisResult, AIStrategyResult


@pytest.fixture
def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return WAFDatabase(db_path=path)


@pytest.fixture
def logger():
    return RequestLogger()


class TestRequestLoggerWithDB:
    def test_log_persists_to_db(self, db, logger):
        with patch("request_log.waf_db", db):
            metadata = RequestMetadata(
                method="GET", path="/test", query_string="q=1",
                headers={"user-agent": "test-agent"}, source_ip="10.0.0.1"
            )
            analysis = AIAnalysisResult(
                overall_decision=Decision.BLOCK,
                overall_threat_level=ThreatLevel.HIGH,
                confidence=0.85,
                reasoning="test threat",
                strategy_results=[
                    AIStrategyResult(
                        strategy_name="signature",
                        decision=Decision.BLOCK,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.85,
                        reason="pattern match",
                        matched_patterns=["SQL Injection"]
                    )
                ]
            )
            logger.log(metadata, analysis, 25.0)

            db_logs = db.get_logs()
            assert len(db_logs) == 1
            assert db_logs[0]["method"] == "GET"
            assert db_logs[0]["path"] == "/test"
            assert db_logs[0]["decision"] == "block"
            assert db_logs[0]["threat_level"] == "high"
            assert db_logs[0]["source_ip"] == "10.0.0.1"

    def test_log_with_multiple_strategies(self, db, logger):
        with patch("request_log.waf_db", db):
            metadata = RequestMetadata(
                method="POST", path="/api/data", query_string="",
                headers={"user-agent": "test"}, source_ip="10.0.0.1"
            )
            analysis = AIAnalysisResult(
                overall_decision=Decision.BLOCK,
                overall_threat_level=ThreatLevel.CRITICAL,
                confidence=0.9,
                reasoning="multiple threats",
                strategy_results=[
                    AIStrategyResult(
                        strategy_name="signature",
                        decision=Decision.BLOCK,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.8,
                        reason="signature match",
                        matched_patterns=["XSS"]
                    ),
                    AIStrategyResult(
                        strategy_name="behavior",
                        decision=Decision.BLOCK,
                        threat_level=ThreatLevel.CRITICAL,
                        confidence=0.95,
                        reason="anomalous behavior",
                        matched_patterns=["rapid_requests"]
                    )
                ]
            )
            logger.log(metadata, analysis, 30.0)

            db_logs = db.get_logs()
            assert len(db_logs) == 1
            strategies = json.loads(db_logs[0]["strategies_json"])
            assert len(strategies) == 2
            assert strategies[0]["name"] == "signature"
            assert strategies[1]["name"] == "behavior"

    def test_log_without_headers(self, db, logger):
        with patch("request_log.waf_db", db):
            metadata = RequestMetadata(
                method="GET", path="/test", query_string="",
                headers={}, source_ip="10.0.0.1"
            )
            analysis = AIAnalysisResult(
                overall_decision=Decision.ALLOW,
                overall_threat_level=ThreatLevel.NONE,
                confidence=0.9,
                reasoning="clean"
            )
            logger.log(metadata, analysis, 5.0)

            db_logs = db.get_logs()
            assert len(db_logs) == 1
            assert db_logs[0]["user_agent"] == ""


class TestSeedDataWithDB:
    def test_seed_loads_data_to_db(self, db, logger):
        with patch("request_log.waf_db", db):
            result = logger.seed_sample_data()
            assert result["status"] == "sample_data_loaded"

            db_logs = db.get_logs()
            assert len(db_logs) > 0

            blocked = db.get_logs(decision_filter="block")
            allowed = db.get_logs(decision_filter="allow")
            assert len(blocked) > 0
            assert len(allowed) > 0

    def test_seed_cannot_be_called_twice(self, logger):
        result1 = logger.seed_sample_data()
        result2 = logger.seed_sample_data()
        assert result1["status"] == "sample_data_loaded"
        assert result2["status"] == "data_already_loaded"

    def test_seed_contains_varied_threats(self, db, logger):
        with patch("request_log.waf_db", db):
            logger.seed_sample_data()
            summary = db.get_summary()
            assert "critical" in summary["threat_levels"]
            assert "high" in summary["threat_levels"]
            assert "none" in summary["threat_levels"]


class TestDashboardEndpointsIntegration:
    def test_summary_matches_db_data(self, db, logger):
        with patch("request_log.waf_db", db):
            logger.seed_sample_data()

            summary = db.get_summary()
            assert summary["total_requests"] > 0
            assert summary["blocked"] > 0
            assert summary["allowed"] > 0
            assert summary["block_rate"] > 0
            assert summary["avg_analysis_time_ms"] > 0

    def test_logs_pagination(self, db, logger):
        with patch("request_log.waf_db", db):
            logger.seed_sample_data()

            logs_10 = db.get_logs(limit=10)
            logs_5 = db.get_logs(limit=5)
            assert len(logs_10) == 10 or len(logs_10) <= len(db.get_logs())
            assert len(logs_5) == 5

    def test_timeline_returns_data(self, db, logger):
        with patch("request_log.waf_db", db):
            logger.seed_sample_data()
            timeline = db.get_timeline(minutes=60)
            assert isinstance(timeline, list)

    def test_strategy_stats_after_seed(self, db, logger):
        with patch("request_log.waf_db", db):
            logger.seed_sample_data()
            stats = db.get_strategy_stats()
            assert len(stats) > 0
            names = [s["name"] for s in stats]
            assert "signature" in names


class TestBlacklistIntegrationWithProxy:
    def test_violation_triggers_blacklist_entry(self, db):
        count = db.blacklist_add_violation("10.0.0.1", "SQL Injection", "high")
        assert count == 1
        entries = db.blacklist_get_all()
        assert len(entries) == 1
        assert entries[0]["ip"] == "10.0.0.1"

    def test_threshold_ban_flow(self, db):
        threshold = 5
        for i in range(threshold):
            count = db.blacklist_add_violation("10.0.0.1", f"threat_{i}", "high")
        assert count >= threshold

        db.blacklist_ban("10.0.0.1", f"Auto-banned after {count} violations")
        assert db.blacklist_is_blocked("10.0.0.1") is True

    def test_check_blocked_before_allow(self, db):
        db.blacklist_ban("10.0.0.1", "blocked")
        assert db.blacklist_is_blocked("10.0.0.1") is True

        db.blacklist_unban("10.0.0.1")
        assert db.blacklist_is_blocked("10.0.0.1") is False


class TestEndToEndFlow:
    def test_full_attack_to_block_flow(self, db, logger):
        with patch("request_log.waf_db", db):
            metadata = RequestMetadata(
                method="GET", path="/search", query_string="q=1' OR '1'='1",
                headers={"user-agent": "attacker"}, source_ip="192.168.1.100"
            )
            analysis = AIAnalysisResult(
                overall_decision=Decision.BLOCK,
                overall_threat_level=ThreatLevel.HIGH,
                confidence=0.9,
                reasoning="SQL Injection detected",
                strategy_results=[
                    AIStrategyResult(
                        strategy_name="signature",
                        decision=Decision.BLOCK,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.9,
                        reason="SQL pattern match",
                        matched_patterns=["SQL Injection: sql_injection_or_and"]
                    )
                ]
            )
            logger.log(metadata, analysis, 15.0)

            db_logs = db.get_logs()
            assert len(db_logs) == 1
            assert db_logs[0]["decision"] == "block"
            assert db_logs[0]["threat_level"] == "high"
            assert db_logs[0]["path"] == "/search"

            summary = db.get_summary()
            assert summary["total_requests"] == 1
            assert summary["blocked"] == 1
            assert summary["block_rate"] == 100.0

    def test_full_clean_to_allow_flow(self, db, logger):
        with patch("request_log.waf_db", db):
            metadata = RequestMetadata(
                method="GET", path="/api/users", query_string="page=1",
                headers={"user-agent": "Mozilla/5.0"}, source_ip="8.8.8.8"
            )
            analysis = AIAnalysisResult(
                overall_decision=Decision.ALLOW,
                overall_threat_level=ThreatLevel.NONE,
                confidence=0.95,
                reasoning="No threats detected",
                strategy_results=[
                    AIStrategyResult(
                        strategy_name="signature",
                        decision=Decision.ALLOW,
                        threat_level=ThreatLevel.NONE,
                        confidence=0.95,
                        reason="Clean request",
                        matched_patterns=[]
                    )
                ]
            )
            logger.log(metadata, analysis, 8.0)

            db_logs = db.get_logs()
            assert len(db_logs) == 1
            assert db_logs[0]["decision"] == "allow"

            summary = db.get_summary()
            assert summary["allowed"] == 1
            assert summary["blocked"] == 0

    def test_mixed_flow_with_summary(self, db, logger):
        with patch("request_log.waf_db", db):
            for i in range(5):
                metadata = RequestMetadata(
                    method="GET", path=f"/api/resource{i}", query_string="",
                    headers={"user-agent": "test"}, source_ip=f"10.0.0.{i}"
                )
                is_attack = i < 2
                analysis = AIAnalysisResult(
                    overall_decision=Decision.BLOCK if is_attack else Decision.ALLOW,
                    overall_threat_level=ThreatLevel.HIGH if is_attack else ThreatLevel.NONE,
                    confidence=0.85,
                    reasoning="attack" if is_attack else "clean",
                    strategy_results=[
                        AIStrategyResult(
                            strategy_name="signature",
                            decision=Decision.BLOCK if is_attack else Decision.ALLOW,
                            threat_level=ThreatLevel.HIGH if is_attack else ThreatLevel.NONE,
                            confidence=0.85,
                            reason="test",
                            matched_patterns=["SQL Injection"] if is_attack else []
                        )
                    ]
                )
                logger.log(metadata, analysis, 10.0 + i)

            summary = db.get_summary()
            assert summary["total_requests"] == 5
            assert summary["blocked"] == 2
            assert summary["allowed"] == 3
            assert summary["block_rate"] == 40.0

    def test_persistence_survives_new_logger(self, db):
        with patch("request_log.waf_db", db):
            db.log_request(
                method="GET", path="/persist", query_string="",
                source_ip="10.0.0.1", user_agent="",
                decision="allow", threat_level="none", confidence=0.9,
                reason="test", analysis_time_ms=10.0
            )

            new_db = WAFDatabase(db_path=db.db_path)
            logs = new_db.get_logs()
            assert len(logs) == 1
            assert logs[0]["path"] == "/persist"


class TestRateLimitDBIntegration:
    def test_rate_limit_tracks_requests(self, db):
        db.rate_limit_update("10.0.0.1", 50, blocked=False)
        result = db.rate_limit_get("10.0.0.1")
        assert result is not None
        assert result["ip"] == "10.0.0.1"

    def test_rate_limit_tracks_blocked(self, db):
        db.rate_limit_update("10.0.0.1", 100, blocked=True)
        db.rate_limit_update("10.0.0.1", 101, blocked=True)
        result = db.rate_limit_get("10.0.0.1")
        assert result["blocked"] >= 2


class TestConfigDBIntegration:
    def test_config_table_exists(self, db):
        conn = db._get_conn()
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        assert any(t["name"] == "waf_config" for t in tables)
        conn.close()

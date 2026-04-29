import pytest
from datetime import datetime
from models.request import RequestMetadata, Decision, ThreatLevel, AIAnalysisResult, AIStrategyResult
from request_log import RequestLogger


@pytest.fixture
def logger():
    return RequestLogger()


def create_sample_entry(decision="allow", threat_level="none"):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "method": "GET",
        "path": "/test",
        "source_ip": "192.168.1.1",
        "decision": decision,
        "threat_level": threat_level,
        "confidence": 0.8,
        "reason": "test",
        "analysis_time_ms": 10.0,
        "strategies": []
    }


class TestRequestLogger:
    def test_log_entry(self, logger):
        metadata = RequestMetadata(
            method="GET", path="/test", source_ip="192.168.1.1"
        )
        analysis = AIAnalysisResult(
            overall_decision=Decision.ALLOW,
            overall_threat_level=ThreatLevel.NONE
        )
        logger.log(metadata, analysis, 15.0)
        logs = logger.get_logs()
        assert len(logs) == 1
        assert logs[0]["decision"] == "allow"

    def test_get_logs_empty(self, logger):
        assert logger.get_logs() == []

    def test_get_logs_with_entries(self, logger):
        for i in range(5):
            metadata = RequestMetadata(
                method="GET", path=f"/test{i}", source_ip="192.168.1.1"
            )
            analysis = AIAnalysisResult(
                overall_decision=Decision.ALLOW,
                overall_threat_level=ThreatLevel.NONE
            )
            logger.log(metadata, analysis, 10.0)

        logs = logger.get_logs(limit=3)
        assert len(logs) == 3

    def test_summary_empty(self, logger):
        summary = logger.get_summary()
        assert summary["total_requests"] == 0
        assert summary["blocked"] == 0
        assert summary["allowed"] == 0

    def test_summary_with_data(self, logger):
        metadata = RequestMetadata(
            method="GET", path="/test", source_ip="192.168.1.1"
        )
        analysis = AIAnalysisResult(
            overall_decision=Decision.BLOCK,
            overall_threat_level=ThreatLevel.HIGH
        )
        logger.log(metadata, analysis, 10.0)

        summary = logger.get_summary()
        assert summary["total_requests"] == 1
        assert summary["blocked"] == 1
        assert summary["block_rate"] == 100.0

    def test_timeline_empty(self, logger):
        timeline = logger.get_timeline()
        assert len(timeline) == 60

    def test_strategy_stats_empty(self, logger):
        stats = logger.get_strategy_stats()
        assert stats == []

    def test_subscriber_notification(self, logger):
        received = []

        def callback(entry):
            received.append(entry)

        logger.subscribe(callback)
        metadata = RequestMetadata(
            method="POST", path="/api/data", source_ip="10.0.0.1"
        )
        analysis = AIAnalysisResult(
            overall_decision=Decision.ALLOW,
            overall_threat_level=ThreatLevel.NONE
        )
        logger.log(metadata, analysis, 5.0)

        assert len(received) == 1
        assert received[0]["decision"] == "allow"

    def test_max_log_size(self, logger):
        for i in range(1100):
            metadata = RequestMetadata(
                method="GET", path=f"/test{i}", source_ip="192.168.1.1"
            )
            analysis = AIAnalysisResult(
                overall_decision=Decision.ALLOW,
                overall_threat_level=ThreatLevel.NONE
            )
            logger.log(metadata, analysis, 10.0)

        logs = logger.get_logs(limit=2000)
        assert len(logs) <= 1000

import pytest
from datetime import datetime
from models.request import RequestMetadata, Decision, ThreatLevel, AIStrategyResult

from strategies.signature import SignatureStrategy
from strategies.behavior import BehaviorStrategy, BehaviorTracker


@pytest.fixture
def signature_strategy():
    return SignatureStrategy()


@pytest.fixture
def behavior_strategy():
    return BehaviorStrategy()


@pytest.fixture
def sample_request():
    return RequestMetadata(
        method="GET",
        path="/api/users",
        query_string="id=1",
        headers={"Content-Type": "application/json"},
        body_preview="",
        source_ip="192.168.1.1",
        timestamp=datetime.utcnow()
    )


@pytest.fixture
def sql_injection_request():
    return RequestMetadata(
        method="GET",
        path="/api/users",
        query_string="id=1' OR '1'='1",
        headers={"Content-Type": "application/json"},
        body_preview="",
        source_ip="10.0.0.1",
        timestamp=datetime.utcnow()
    )


@pytest.fixture
def xss_request():
    return RequestMetadata(
        method="POST",
        path="/api/comments",
        query_string="",
        headers={"Content-Type": "application/json"},
        body_preview='<script>alert("XSS")</script>',
        source_ip="10.0.0.2",
        timestamp=datetime.utcnow()
    )


@pytest.fixture
def path_traversal_request():
    return RequestMetadata(
        method="GET",
        path="/api/files",
        query_string="file=../../../etc/passwd",
        headers={"Content-Type": "application/json"},
        body_preview="",
        source_ip="10.0.0.3",
        timestamp=datetime.utcnow()
    )


class TestSignatureStrategy:
    @pytest.mark.asyncio
    async def test_clean_request(self, signature_strategy, sample_request):
        result = await signature_strategy.evaluate(sample_request)
        assert result.decision == Decision.ALLOW
        assert len(result.matched_patterns) == 0

    @pytest.mark.asyncio
    async def test_sql_injection_blocked(self, signature_strategy, sql_injection_request):
        result = await signature_strategy.evaluate(sql_injection_request)
        assert result.decision == Decision.BLOCK
        assert len(result.matched_patterns) > 0
        assert any("sql" in p.lower() for p in result.matched_patterns)

    @pytest.mark.asyncio
    async def test_xss_blocked(self, signature_strategy, xss_request):
        result = await signature_strategy.evaluate(xss_request)
        assert result.decision == Decision.BLOCK
        assert len(result.matched_patterns) > 0
        assert any("xss" in p.lower() for p in result.matched_patterns)

    @pytest.mark.asyncio
    async def test_path_traversal_blocked(self, signature_strategy, path_traversal_request):
        result = await signature_strategy.evaluate(path_traversal_request)
        assert result.decision == Decision.BLOCK
        assert len(result.matched_patterns) > 0
        assert any("traversal" in p.lower() or "inclusion" in p.lower() or "linux" in p.lower() for p in result.matched_patterns)


class TestBehaviorStrategy:
    @pytest.mark.asyncio
    async def test_normal_request(self, behavior_strategy, sample_request):
        result = await behavior_strategy.evaluate(sample_request)
        assert result.decision == Decision.ALLOW

    @pytest.mark.asyncio
    async def test_suspicious_path(self, behavior_strategy):
        suspicious_request = RequestMetadata(
            method="GET",
            path="/wp-admin",
            query_string="",
            headers={},
            body_preview="",
            source_ip="10.0.0.5",
            timestamp=datetime.utcnow()
        )
        result = await behavior_strategy.evaluate(suspicious_request)
        assert any("suspicious_path" in p for p in result.matched_patterns)


class TestBehaviorTracker:
    def test_request_tracking(self):
        tracker = BehaviorTracker()
        request = RequestMetadata(
            method="GET",
            path="/test",
            source_ip="192.168.1.1",
            timestamp=datetime.utcnow()
        )
        tracker.track_request(request)
        assert tracker.get_request_count("192.168.1.1") >= 1

    def test_unique_paths(self):
        tracker = BehaviorTracker()
        for i in range(5):
            request = RequestMetadata(
                method="GET",
                path=f"/path{i}",
                source_ip="192.168.1.2",
                timestamp=datetime.utcnow()
            )
            tracker.track_request(request)
        assert tracker.get_unique_paths("192.168.1.2") == 5

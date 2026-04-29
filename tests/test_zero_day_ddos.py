import pytest
import time
from models.request import RequestMetadata
from strategies.zero_day_ddos import ZeroDayDetector, DDoSProtector, ZeroDayStrategy, DDoSStrategy


class TestZeroDayDetector:
    def test_extract_features_basic(self):
        detector = ZeroDayDetector()
        request = RequestMetadata(
            method="GET", path="/api/users", query_string="id=1",
            body_preview="", source_ip="192.168.1.1"
        )
        features = detector._extract_features(request)
        assert features["path_length"] == len("/api/users")
        assert features["param_count"] == 1

    def test_extract_features_special_chars(self):
        detector = ZeroDayDetector()
        request = RequestMetadata(
            method="POST", path="/search", query_string="q=<script>alert(1)</script>",
            body_preview="", source_ip="192.168.1.2"
        )
        features = detector._extract_features(request)
        assert features["special_char_count"] > 3

    def test_entropy_calculation(self):
        detector = ZeroDayDetector()
        low_entropy = detector._calc_entropy("aaaaaaaaaaaa")
        high_entropy = detector._calc_entropy("a1B2c3D4e5F6g7H8")
        assert high_entropy > low_entropy

    def test_no_anomaly_normal_traffic(self):
        detector = ZeroDayDetector(baseline_window=50, deviation_threshold=3.0)
        for i in range(30):
            request = RequestMetadata(
                method="GET", path=f"/api/users/{i}", query_string="",
                body_preview="", source_ip="192.168.1.1"
            )
            detector.analyze(request)
        normal_request = RequestMetadata(
            method="GET", path="/api/users/100", query_string="",
            body_preview="", source_ip="192.168.1.1"
        )
        is_anomalous, confidence, anomalies = detector.analyze(normal_request)
        assert not is_anomalous

    def test_anomaly_on_malicious_input(self):
        detector = ZeroDayDetector(baseline_window=50, deviation_threshold=2.0)
        for i in range(30):
            request = RequestMetadata(
                method="GET", path="/api/data", query_string="",
                body_preview="{}", source_ip="192.168.1.1"
            )
            detector.analyze(request)
        malicious = RequestMetadata(
            method="POST", path="/api/data", query_string="",
            body_preview="'; DROP TABLE users; -- <script>alert(document.cookie)</script>",
            source_ip="192.168.1.1"
        )
        is_anomalous, confidence, anomalies = detector.analyze(malicious)
        assert is_anomalous
        assert confidence > 0.0

    def test_high_entropy_detection(self):
        detector = ZeroDayDetector(baseline_window=50, deviation_threshold=2.0)
        for i in range(30):
            request = RequestMetadata(
                method="GET", path="/page", query_string="",
                body_preview="normal content", source_ip="192.168.1.1"
            )
            detector.analyze(request)
        encoded_payload = RequestMetadata(
            method="GET", path="/exec", query_string="",
            body_preview="%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E" + "A1b2C3d4" * 20,
            source_ip="192.168.1.1"
        )
        is_anomalous, confidence, anomalies = detector.analyze(encoded_payload)
        assert is_anomalous


class TestDDoSProtector:
    def test_normal_traffic_not_blocked(self):
        protector = DDoSProtector(global_rps_threshold=100, ip_flood_threshold=20, window_seconds=5)
        request = RequestMetadata(method="GET", path="/api", query_string="", body_preview="", source_ip="192.168.1.1")
        is_ddos, score, alerts = protector.analyze(request)
        assert not is_ddos
        assert score == 0.0

    def test_ip_flood_detection(self):
        protector = DDoSProtector(global_rps_threshold=100, ip_flood_threshold=5, window_seconds=2)
        ip = "10.0.0.1"
        for i in range(15):
            request = RequestMetadata(method="GET", path="/api", query_string="", body_preview="", source_ip=ip)
            protector.analyze(request)
        is_ddos, score, alerts = protector.analyze(request)
        assert is_ddos
        assert score >= 0.8

    def test_blocked_ip_rejected(self):
        protector = DDoSProtector(global_rps_threshold=100, ip_flood_threshold=5, window_seconds=2)
        ip = "10.0.0.2"
        for i in range(10):
            request = RequestMetadata(method="GET", path="/api", query_string="", body_preview="", source_ip=ip)
            protector.analyze(request)
        blocked_request = RequestMetadata(method="GET", path="/api", query_string="", body_preview="", source_ip=ip)
        is_ddos, score, alerts = protector.analyze(blocked_request)
        assert is_ddos
        assert any("blocked_ip" in a for a in alerts)

    def test_large_payload_flood(self):
        protector = DDoSProtector(global_rps_threshold=100, ip_flood_threshold=100, window_seconds=5)
        ip = "10.0.0.3"
        large_body = "X" * 60000
        for i in range(8):
            request = RequestMetadata(method="POST", path="/upload", query_string="", body_preview=large_body, source_ip=ip)
            protector.analyze(request)
        is_ddos, score, alerts = protector.analyze(request)
        assert is_ddos
        assert any("large_payload" in a for a in alerts)

    def test_cleanup_removes_old_entries(self):
        protector = DDoSProtector(window_seconds=1)
        ip = "10.0.0.4"
        for i in range(5):
            request = RequestMetadata(method="GET", path="/api", query_string="", body_preview="", source_ip=ip)
            protector.analyze(request)
        time.sleep(1.1)
        fresh_request = RequestMetadata(method="GET", path="/api", query_string="", body_preview="", source_ip=ip)
        is_ddos, score, alerts = protector.analyze(fresh_request)
        assert not is_ddos

    def test_distributed_attack_detection(self):
        protector = DDoSProtector(global_rps_threshold=20, ip_flood_threshold=200, window_seconds=2)
        for i in range(60):
            ip = f"10.{i // 256}.{(i * 7) % 256}.{(i * 13) % 256}"
            request = RequestMetadata(method="GET", path="/api", query_string="", body_preview="", source_ip=ip)
            protector.analyze(request)
        is_ddos, score, alerts = protector.analyze(request)
        assert is_ddos
        assert any("distributed" in a.lower() for a in alerts)


class TestZeroDayStrategy:
    @pytest.mark.asyncio
    async def test_allow_normal_request(self):
        strategy = ZeroDayStrategy()
        request = RequestMetadata(method="GET", path="/index.html", query_string="", body_preview="", source_ip="1.2.3.4")
        for _ in range(5):
            await strategy.evaluate(request)
        result = await strategy.evaluate(request)
        assert result.decision.value == "allow"

    @pytest.mark.asyncio
    async def test_block_anomalous_request(self):
        strategy = ZeroDayStrategy()
        for _ in range(20):
            req = RequestMetadata(method="GET", path="/page", query_string="", body_preview="normal", source_ip="1.2.3.4")
            await strategy.evaluate(req)
        malicious = RequestMetadata(
            method="POST", path="/page", query_string="",
            body_preview="' OR 1=1; DROP TABLE <script>",
            source_ip="1.2.3.4"
        )
        result = await strategy.evaluate(malicious)
        assert result.decision.value == "block" or result.confidence > 0


class TestDDoSStrategy:
    @pytest.mark.asyncio
    async def test_allow_normal_request(self):
        strategy = DDoSStrategy()
        request = RequestMetadata(method="GET", path="/api", query_string="", body_preview="", source_ip="5.6.7.8")
        result = await strategy.evaluate(request)
        assert result.decision.value == "allow"

    @pytest.mark.asyncio
    async def test_block_flood(self):
        from strategies import zero_day_ddos
        original_protector = zero_day_ddos.ddos_protector
        zero_day_ddos.ddos_protector = DDoSProtector(global_rps_threshold=100, ip_flood_threshold=5, window_seconds=2)
        try:
            strategy = DDoSStrategy()
            ip = "10.10.10.10"
            for i in range(15):
                req = RequestMetadata(method="GET", path="/api", query_string="", body_preview="", source_ip=ip)
                await strategy.evaluate(req)
            result = await strategy.evaluate(req)
            assert result.decision.value == "block"
        finally:
            zero_day_ddos.ddos_protector = original_protector

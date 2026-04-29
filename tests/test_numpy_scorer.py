import pytest
import numpy as np
from ai_engine.numpy_scorer import ThreatScorer
from models.request import ThreatLevel


@pytest.fixture
def scorer():
    return ThreatScorer()


class TestThreatScorer:
    def test_calculate_threat_score_empty(self, scorer):
        assert scorer.calculate_threat_score([]) == 0.0

    def test_calculate_threat_score_single(self, scorer):
        decisions = [{"confidence": 0.8, "weight": 1.0}]
        assert scorer.calculate_threat_score(decisions) == 0.8

    def test_calculate_threat_score_weighted(self, scorer):
        decisions = [
            {"confidence": 0.9, "weight": 1.5},
            {"confidence": 0.3, "weight": 1.0}
        ]
        score = scorer.calculate_threat_score(decisions)
        assert 0.6 < score < 0.8

    def test_aggregate_threat_levels_empty(self, scorer):
        assert scorer.aggregate_threat_levels([]) == ThreatLevel.NONE

    def test_aggregate_threat_levels_single(self, scorer):
        assert scorer.aggregate_threat_levels([ThreatLevel.HIGH]) == ThreatLevel.HIGH

    def test_aggregate_threat_levels_multiple(self, scorer):
        levels = [ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH]
        result = scorer.aggregate_threat_levels(levels)
        assert result in [ThreatLevel.MEDIUM, ThreatLevel.HIGH]

    def test_detect_anomaly_normal(self, scorer):
        baseline = np.array([10.0, 20.0, 30.0])
        features = [10.5, 19.8, 30.2]
        assert scorer.detect_anomaly(features, baseline) == False

    def test_detect_anomaly_abnormal(self, scorer):
        baseline = np.array([10.0, 20.0, 30.0])
        features = [100.0, 200.0, 300.0]
        assert scorer.detect_anomaly(features, baseline) == True

    def test_compute_baseline(self, scorer):
        data = [[10.0, 20.0], [12.0, 18.0], [11.0, 19.0]]
        baseline = scorer.compute_baseline(data)
        assert np.allclose(baseline, [11.0, 19.0])

    def test_analyze_request_pattern_slow(self, scorer):
        timestamps = [1.0, 2.0, 3.0, 4.0, 5.0]
        result = scorer.analyze_request_pattern(timestamps)
        assert result["rate"] == pytest.approx(1.0, abs=0.01)
        assert result["burst_detected"] == False

    def test_analyze_request_pattern_burst(self, scorer):
        timestamps = [1.0, 1.05, 1.1, 2.0, 3.0]
        result = scorer.analyze_request_pattern(timestamps)
        assert result["burst_detected"] == True

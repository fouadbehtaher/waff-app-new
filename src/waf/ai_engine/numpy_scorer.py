import numpy as np
from typing import List, Dict
from models.request import ThreatLevel


class ThreatScorer:
    def __init__(self):
        self.threat_weights = np.array([0.0, 0.2, 0.4, 0.7, 1.0])
        self.confidence_threshold = 0.6

    def calculate_threat_score(self, decisions: List[dict]) -> float:
        decisions_arr = np.array([d.get("confidence", 0.0) for d in decisions])
        if len(decisions_arr) == 0:
            return 0.0

        weights = np.array([d.get("weight", 1.0) for d in decisions])
        weights = weights / weights.sum()

        score = np.dot(decisions_arr, weights)
        return float(np.clip(score, 0.0, 1.0))

    def aggregate_threat_levels(self, threat_levels: List[ThreatLevel]) -> ThreatLevel:
        level_map = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        reverse_map = {v: k for k, v in level_map.items()}

        levels_arr = np.array([level_map.get(tl.value, 0) for tl in threat_levels])

        if len(levels_arr) == 0:
            return ThreatLevel.NONE

        percentile_90 = np.percentile(levels_arr, 90)
        return ThreatLevel(reverse_map[int(np.clip(round(percentile_90), 0, 4))])

    def detect_anomaly(self, request_features: List[float], baseline: np.ndarray) -> bool:
        features = np.array(request_features)

        if len(features) != len(baseline):
            return False

        z_scores = np.abs((features - baseline) / (np.std(baseline) + 1e-8))
        return bool(np.any(z_scores > 2.0))

    def compute_baseline(self, historical_features: List[List[float]]) -> np.ndarray:
        data = np.array(historical_features)
        if data.size == 0:
            return np.array([])
        return np.mean(data, axis=0)

    def analyze_request_pattern(self, timestamps: List[float]) -> dict:
        if len(timestamps) < 2:
            return {"rate": 0.0, "burst_detected": False, "periodicity": 0.0}

        ts_arr = np.array(timestamps)
        intervals = np.diff(ts_arr)

        rate = 1.0 / (np.mean(intervals) + 1e-8)
        cv = np.std(intervals) / (np.mean(intervals) + 1e-8)

        burst_detected = bool(np.any(intervals < np.mean(intervals) * 0.3))

        return {
            "rate": float(rate),
            "burst_detected": burst_detected,
            "periodicity": float(cv)
        }


threat_scorer = ThreatScorer()

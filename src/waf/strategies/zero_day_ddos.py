import time
import structlog
import numpy as np
from collections import defaultdict
from typing import Dict, List, Tuple
from models.request import RequestMetadata, AIStrategyResult, Decision, ThreatLevel
from strategies.base import Strategy

logger = structlog.get_logger()


class ZeroDayDetector:
    def __init__(self, baseline_window: int = 200, deviation_threshold: float = 2.5):
        self._baseline_window = baseline_window
        self._deviation_threshold = deviation_threshold
        self._request_history: List[Dict] = []
        self._path_lengths: List[int] = []
        self._param_counts: List[int] = []
        self._special_char_counts: List[int] = []
        self._baseline_computed = False
        self._baseline_stats: Dict[str, Tuple[float, float]] = {}

    def _extract_features(self, request: RequestMetadata) -> Dict[str, int]:
        path = request.path or ""
        query = request.query_string or ""
        body = request.body_preview or ""
        combined = f"{path}{query}{body}"
        special_chars = sum(1 for c in combined if c in "<>;'\"|`$\\{}[]!@#%&*")
        param_count = query.count("=") + body.count(":")
        return {
            "path_length": len(path),
            "query_length": len(query),
            "body_length": len(body),
            "special_char_count": special_chars,
            "param_count": param_count,
            "depth": path.count("/"),
            "entropy": self._calc_entropy(combined),
        }

    def _calc_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq = defaultdict(int)
        for c in text:
            freq[c] += 1
        length = len(text)
        return -sum((count / length) * np.log2(count / length) for count in freq.values())

    def _update_baseline(self, features: Dict[str, int]):
        self._path_lengths.append(features["path_length"])
        self._param_counts.append(features["param_count"])
        self._special_char_counts.append(features["special_char_count"])
        max_len = self._baseline_window
        self._path_lengths = self._path_lengths[-max_len:]
        self._param_counts = self._param_counts[-max_len:]
        self._special_char_counts = self._special_char_counts[-max_len:]

        if len(self._path_lengths) >= 20:
            self._baseline_stats = {
                "path_length": (np.mean(self._path_lengths), np.std(self._path_lengths) + 1e-8),
                "param_count": (np.mean(self._param_counts), np.std(self._param_counts) + 1e-8),
                "special_char_count": (np.mean(self._special_char_counts), np.std(self._special_char_counts) + 1e-8),
            }
            self._baseline_computed = True

    def analyze(self, request: RequestMetadata) -> Tuple[bool, float, List[str]]:
        features = self._extract_features(request)
        self._update_baseline(features)

        if not self._baseline_computed:
            return False, 0.0, []

        anomalies = []
        max_deviation = 0.0

        for feature_name, (mean, std) in self._baseline_stats.items():
            value = features.get(feature_name.replace("_count", "_count"), 0)
            if feature_name == "path_length":
                value = features["path_length"]
            elif feature_name == "param_count":
                value = features["param_count"]
            elif feature_name == "special_char_count":
                value = features["special_char_count"]
            deviation = abs(value - mean) / std
            if deviation > self._deviation_threshold:
                anomalies.append(f"{feature_name}_anomaly: value={value}, mean={mean:.1f}, deviation={deviation:.1f}σ")
                max_deviation = max(max_deviation, deviation)

        entropy = features["entropy"]
        if entropy > 5.5:
            anomalies.append(f"high_entropy: {entropy:.2f}")
            max_deviation = max(max_deviation, entropy / 5.5)

        is_anomalous = len(anomalies) >= 2 or max_deviation > self._deviation_threshold * 1.5
        confidence = min(0.95, 0.5 + (max_deviation / 10)) if is_anomalous else 0.0

        return is_anomalous, confidence, anomalies


class DDoSProtector:
    def __init__(self, global_rps_threshold: int = 500, ip_flood_threshold: int = 60, window_seconds: int = 10):
        self._global_rps_threshold = global_rps_threshold
        self._ip_flood_threshold = ip_flood_threshold
        self._window_seconds = window_seconds
        self._request_timestamps: List[float] = []
        self._ip_timestamps: Dict[str, List[float]] = defaultdict(list)
        self._ip_request_sizes: Dict[str, List[int]] = defaultdict(list)
        self._blocked_ips: Dict[str, float] = {}
        self._ddos_active = False

    def _clean_old_entries(self):
        now = time.time()
        cutoff = now - self._window_seconds
        self._request_timestamps = [t for t in self._request_timestamps if t > cutoff]
        for ip in list(self._ip_timestamps.keys()):
            self._ip_timestamps[ip] = [t for t in self._ip_timestamps[ip] if t > cutoff]
            if not self._ip_timestamps[ip]:
                del self._ip_timestamps[ip]
        expired = [ip for ip, t in self._blocked_ips.items() if now > t]
        for ip in expired:
            del self._blocked_ips[ip]

    def analyze(self, request: RequestMetadata) -> Tuple[bool, float, List[str]]:
        now = time.time()
        ip = request.source_ip or "unknown"
        self._clean_old_entries()

        self._request_timestamps.append(now)
        self._ip_timestamps[ip].append(now)

        body_size = len(request.body_preview or "")
        self._ip_request_sizes[ip].append(body_size)
        self._ip_request_sizes[ip] = self._ip_request_sizes[ip][-100:]

        alerts = []
        threat_score = 0.0

        global_rps = len(self._request_timestamps) / self._window_seconds
        if global_rps > self._global_rps_threshold:
            self._ddos_active = True
            alerts.append(f"global_flood_detected: {global_rps:.0f} req/s")
            threat_score = max(threat_score, 0.9)

        ip_rps = len(self._ip_timestamps.get(ip, [])) / self._window_seconds
        if ip_rps > self._ip_flood_threshold:
            alerts.append(f"ip_flood_detected: {ip_rps:.0f} req/s from {ip}")
            threat_score = max(threat_score, 0.85)
            self._blocked_ips[ip] = now + 300

        if ip in self._blocked_ips:
            alerts.append(f"ddos_blocked_ip: {ip}")
            threat_score = max(threat_score, 0.95)

        sizes = self._ip_request_sizes.get(ip, [])
        if len(sizes) >= 5:
            avg_size = np.mean(sizes)
            if avg_size > 50000:
                alerts.append(f"large_payload_flood: avg={avg_size:.0f} bytes")
                threat_score = max(threat_score, 0.8)

        if len(self._ip_timestamps) > 50:
            unique_ips = len(self._ip_timestamps)
            if unique_ips > 30 and global_rps > self._global_rps_threshold * 0.5:
                alerts.append(f"distributed_attack: {unique_ips} IPs, {global_rps:.0f} req/s")
                threat_score = max(threat_score, 0.95)

        is_ddos = threat_score > 0.7
        return is_ddos, threat_score, alerts


zero_day_detector = ZeroDayDetector()
ddos_protector = DDoSProtector()


class ZeroDayStrategy(Strategy):
    name = "zero_day"

    async def evaluate(self, request: RequestMetadata) -> AIStrategyResult:
        is_anomalous, confidence, anomalies = zero_day_detector.analyze(request)

        if is_anomalous:
            decision = Decision.BLOCK
            highest_threat = ThreatLevel.HIGH if confidence > 0.7 else ThreatLevel.MEDIUM
            reason = f"Zero-day anomaly detected: {len(anomalies)} deviations"
        else:
            decision = Decision.ALLOW
            highest_threat = ThreatLevel.NONE
            reason = "No zero-day anomalies detected"

        return AIStrategyResult(
            strategy_name=self.name,
            decision=decision,
            threat_level=highest_threat,
            confidence=confidence,
            reason=reason,
            matched_patterns=anomalies
        )


class DDoSStrategy(Strategy):
    name = "ddos_protection"

    async def evaluate(self, request: RequestMetadata) -> AIStrategyResult:
        is_ddos, threat_score, alerts = ddos_protector.analyze(request)

        if is_ddos:
            decision = Decision.BLOCK
            if threat_score > 0.9:
                highest_threat = ThreatLevel.CRITICAL
            elif threat_score > 0.8:
                highest_threat = ThreatLevel.HIGH
            else:
                highest_threat = ThreatLevel.MEDIUM
            reason = f"DDoS threat detected: {'; '.join(alerts[:3])}"
        else:
            decision = Decision.ALLOW
            highest_threat = ThreatLevel.NONE
            reason = "No DDoS threat detected"

        return AIStrategyResult(
            strategy_name=self.name,
            decision=decision,
            threat_level=highest_threat,
            confidence=threat_score,
            reason=reason,
            matched_patterns=alerts
        )

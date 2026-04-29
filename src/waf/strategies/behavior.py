import time
import structlog
import numpy as np
from collections import defaultdict
from typing import Dict, List
from models.request import RequestMetadata, AIStrategyResult, Decision, ThreatLevel
from strategies.base import Strategy

logger = structlog.get_logger()


class BehaviorTracker:
    _requests: Dict[str, list] = defaultdict(list)
    _ip_rates: Dict[str, list] = defaultdict(list)
    _ip_timestamps: Dict[str, List[float]] = defaultdict(list)

    RATE_WINDOW = 60
    RATE_LIMIT = 100

    SUSPICIOUS_PATHS = {
        "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config",
        "/.git", "/backup", "/debug", "/console", "/actuator",
        "/api/v1/debug", "/server-status", "/wp-login.php"
    }

    def track_request(self, request: RequestMetadata):
        ip = request.source_ip or "unknown"
        timestamp = time.time()
        self._requests[ip].append({
            "path": request.path,
            "method": request.method,
            "timestamp": timestamp
        })
        self._ip_rates[ip].append(timestamp)
        self._ip_timestamps[ip].append(timestamp)

        self._requests[ip] = self._requests[ip][-50:]
        self._ip_rates[ip] = [t for t in self._ip_rates[ip] if timestamp - t < self.RATE_WINDOW]

    def get_request_count(self, ip: str) -> int:
        now = time.time()
        return sum(1 for t in self._ip_rates.get(ip, []) if now - t < self.RATE_WINDOW)

    def get_unique_paths(self, ip: str) -> int:
        return len(set(r["path"] for r in self._requests.get(ip, [])))

    def detect_rate_anomaly(self, ip: str) -> bool:
        timestamps = self._ip_timestamps.get(ip, [])
        if len(timestamps) < 5:
            return False

        ts_arr = np.array(timestamps[-20:])
        intervals = np.diff(ts_arr)

        if np.mean(intervals) < 0.1:
            return True

        cv = np.std(intervals) / (np.mean(intervals) + 1e-8)
        return cv < 0.2 and len(ts_arr) > 10


behavior_tracker = BehaviorTracker()


class BehaviorStrategy(Strategy):
    name = "behavior"

    SUSPICIOUS_PATH_THRESHOLD = 3
    SCANNING_PATH_THRESHOLD = 10
    RATE_LIMIT_THRESHOLD = 100

    async def evaluate(self, request: RequestMetadata) -> AIStrategyResult:
        behavior_tracker.track_request(request)

        ip = request.source_ip or "unknown"
        matched_patterns = []
        highest_threat = ThreatLevel.NONE

        request_rate = behavior_tracker.get_request_count(ip)
        if request_rate > self.RATE_LIMIT_THRESHOLD:
            matched_patterns.append(f"rate_limit_exceeded: {request_rate} req/min")
            highest_threat = ThreatLevel.HIGH

        if behavior_tracker.detect_rate_anomaly(ip):
            matched_patterns.append("automated_bot_pattern_detected")
            highest_threat = max(highest_threat, ThreatLevel.HIGH, key=lambda t: {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(t.value, 0))

        path = request.path.lower()
        if path in BehaviorTracker.SUSPICIOUS_PATHS:
            matched_patterns.append(f"suspicious_path_access: {path}")
            highest_threat = max(highest_threat, ThreatLevel.MEDIUM, key=lambda t: {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(t.value, 0))

        unique_paths = behavior_tracker.get_unique_paths(ip)
        if unique_paths > self.SCANNING_PATH_THRESHOLD:
            matched_patterns.append(f"path_scanning_detected: {unique_paths} unique paths")
            highest_threat = max(highest_threat, ThreatLevel.HIGH, key=lambda t: {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(t.value, 0))

        if request.method == "TRACE":
            matched_patterns.append("suspicious_method: TRACE")
            highest_threat = max(highest_threat, ThreatLevel.LOW, key=lambda t: {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(t.value, 0))

        if matched_patterns:
            decision = Decision.BLOCK
            reason = f"Detected {len(matched_patterns)} suspicious behavior(s)"
        else:
            decision = Decision.ALLOW
            reason = "No suspicious behavior detected"

        confidence = min(0.9, 0.5 + (len(matched_patterns) * 0.1)) if matched_patterns else 0.85

        return AIStrategyResult(
            strategy_name=self.name,
            decision=decision,
            threat_level=highest_threat,
            confidence=confidence,
            reason=reason,
            matched_patterns=matched_patterns
        )

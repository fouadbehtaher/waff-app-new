import time
import structlog
from collections import defaultdict
from typing import Dict, Optional

logger = structlog.get_logger()


class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self._requests: Dict[str, list] = defaultdict(list)
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._blocked_count = 0
        self._allowed_count = 0

    def is_rate_limited(self, ip: str) -> bool:
        now = time.time()
        self._cleanup_old_requests(ip, now)

        if len(self._requests[ip]) >= self._max_requests:
            self._blocked_count += 1
            logger.warning("rate_limit_exceeded", ip=ip, requests=len(self._requests[ip]))
            return True

        self._requests[ip].append(now)
        self._allowed_count += 1
        return False

    def get_request_count(self, ip: str) -> int:
        now = time.time()
        self._cleanup_old_requests(ip, now)
        return len(self._requests[ip])

    def get_remaining_requests(self, ip: str) -> int:
        count = self.get_request_count(ip)
        return max(0, self._max_requests - count)

    def get_reset_time(self, ip: str) -> Optional[int]:
        if ip not in self._requests or not self._requests[ip]:
            return 0
        now = time.time()
        oldest = min(self._requests[ip])
        return max(0, int((oldest + self._window_seconds) - now))

    def reset_ip(self, ip: str):
        if ip in self._requests:
            del self._requests[ip]
        logger.info("rate_limit_reset", ip=ip)

    def get_stats(self) -> dict:
        total_tracked = sum(len(reqs) for reqs in self._requests.values())
        return {
            "total_requests_tracked": total_tracked,
            "unique_ips": len(self._requests),
            "blocked_total": self._blocked_count,
            "allowed_total": self._allowed_count,
            "limit": self._max_requests,
            "window_seconds": self._window_seconds
        }

    def get_top_ips(self, limit: int = 10) -> list:
        now = time.time()
        ip_counts = {}
        for ip, reqs in self._requests.items():
            valid_reqs = [r for r in reqs if now - r < self._window_seconds]
            if valid_reqs:
                ip_counts[ip] = len(valid_reqs)
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return [
            {"ip": ip, "requests": count, "remaining": max(0, self._max_requests - count)}
            for ip, count in sorted_ips[:limit]
        ]

    def _cleanup_old_requests(self, ip: str, now: float):
        if ip in self._requests:
            self._requests[ip] = [r for r in self._requests[ip] if now - r < self._window_seconds]
            if not self._requests[ip]:
                del self._requests[ip]


rate_limiter = RateLimiter(max_requests=100, window_seconds=60)

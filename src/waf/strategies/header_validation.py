import structlog
from models.request import RequestMetadata, AIStrategyResult, Decision, ThreatLevel
from strategies.base import Strategy
from waf_config import waf_config

logger = structlog.get_logger()

VALID_CONTENT_TYPES = {
    "application/json", "application/x-www-form-urlencoded", "multipart/form-data",
    "text/plain", "text/html", "application/xml", "text/xml",
    "application/octet-stream", "image/png", "image/jpeg", "image/gif",
    "text/css", "application/javascript", "font/woff", "font/woff2"
}

FORBIDDEN_HEADERS = {
    "x-forwarded-for", "x-real-ip", "x-originating-ip",
    "x-remote-addr", "x-remote-ip", "x-client-ip"
}

SUSPICIOUS_HEADER_VALUES = [
    "sqlmap", "nikto", "nmap", "masscan", "zap", "burp",
    "dirbuster", "gobuster", "wfuzz", "hydra", "metasploit",
    "nessus", "openvas", "acunetix", "appscan"
]

REQUIRED_HEADERS = {"host"}

MAX_HEADER_SIZE = 8192
MAX_HEADER_COUNT = 50


class HeaderValidationStrategy(Strategy):
    name = "header_validation"

    async def evaluate(self, request: RequestMetadata) -> AIStrategyResult:
        cfg = waf_config.get_strategy("header_validation")
        max_headers = cfg.get("max_headers", 50)
        max_header_size = cfg.get("max_header_size", 8192)
        block_forbidden = cfg.get("block_forbidden_headers", True)
        detect_tools = cfg.get("detect_tool_signatures", True)
        validate_ct = cfg.get("validate_content_type", True)

        matched_patterns = []
        highest_threat = ThreatLevel.NONE

        if request.headers:
            header_count = len(request.headers)
            if header_count > max_headers:
                matched_patterns.append(f"excessive_headers: {header_count} > {max_headers}")
                highest_threat = self._update_threat(highest_threat, ThreatLevel.MEDIUM)

            total_size = sum(len(k) + len(v) for k, v in request.headers.items())
            if total_size > max_header_size:
                matched_patterns.append(f"header_size_exceeded: {total_size} > {max_header_size}")
                highest_threat = self._update_threat(highest_threat, ThreatLevel.LOW)

            for key, value in request.headers.items():
                key_lower = key.lower()
                value_lower = value.lower()

                if block_forbidden and key_lower in FORBIDDEN_HEADERS:
                    matched_patterns.append(f"forbidden_header: {key}")
                    highest_threat = self._update_threat(highest_threat, ThreatLevel.HIGH)

                if detect_tools and any(tool in value_lower for tool in SUSPICIOUS_HEADER_VALUES):
                    matched_patterns.append(f"suspicious_tool_detected: {value}")
                    highest_threat = self._update_threat(highest_threat, ThreatLevel.HIGH)

                if validate_ct and key_lower == "content-type":
                    content_type = value_lower.split(";")[0].strip()
                    if content_type and content_type not in VALID_CONTENT_TYPES:
                        matched_patterns.append(f"invalid_content_type: {content_type}")
                        highest_threat = self._update_threat(highest_threat, ThreatLevel.MEDIUM)

                if key_lower == "host":
                    if " " in value or ".." in value:
                        matched_patterns.append(f"malformed_host_header: {value}")
                        highest_threat = self._update_threat(highest_threat, ThreatLevel.MEDIUM)

                if key_lower == "user-agent":
                    if not value or len(value) < 5:
                        matched_patterns.append("missing_or_empty_user_agent")
                        highest_threat = self._update_threat(highest_threat, ThreatLevel.LOW)
                    if value_lower in ("", "curl", "wget", "python-requests", "go-http-client", "java/"):
                        matched_patterns.append(f"automated_user_agent: {value}")
                        highest_threat = self._update_threat(highest_threat, ThreatLevel.LOW)

                if key_lower in ("x-forwarded-for", "x-real-ip"):
                    ips = [ip.strip() for ip in value.split(",")]
                    for ip in ips:
                        if not self._is_valid_ip(ip):
                            matched_patterns.append(f"invalid_ip_in_header: {key}={ip}")
                            highest_threat = self._update_threat(highest_threat, ThreatLevel.MEDIUM)

        if matched_patterns:
            decision = Decision.BLOCK
            reason = f"Header validation: {len(matched_patterns)} issue(s) detected"
        else:
            decision = Decision.ALLOW
            reason = "All headers valid"

        confidence = min(0.95, 0.5 + (len(matched_patterns) * 0.15)) if matched_patterns else 0.95

        return AIStrategyResult(
            strategy_name=self.name,
            decision=decision,
            threat_level=highest_threat,
            confidence=confidence,
            reason=reason,
            matched_patterns=matched_patterns
        )

    def _update_threat(self, current: ThreatLevel, new: ThreatLevel) -> ThreatLevel:
        weights = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if weights.get(new.value, 0) > weights.get(current.value, 0):
            return new
        return current

    def _is_valid_ip(self, ip: str) -> bool:
        if not ip:
            return False
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

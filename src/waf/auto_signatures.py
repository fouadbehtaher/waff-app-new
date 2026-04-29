import re
import json
import structlog
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logger = structlog.get_logger()

SIGNATURE_RULES_PATH = Path(__file__).parent / "auto_signatures.json"


class AutoSignatureGenerator:
    def __init__(self):
        self._rules: List[Dict] = []
        self._load_rules()

    def _load_rules(self):
        if SIGNATURE_RULES_PATH.exists():
            try:
                with open(SIGNATURE_RULES_PATH, "r") as f:
                    self._rules = json.load(f)
                logger.info("auto_signatures_loaded", count=len(self._rules))
            except Exception as e:
                logger.error("auto_signatures_load_failed", error=str(e))
                self._rules = []

    def _save_rules(self):
        SIGNATURE_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(SIGNATURE_RULES_PATH, "w") as f:
            json.dump(self._rules, f, indent=2)

    def analyze_and_generate(self, blocked_requests: List[Dict]) -> List[Dict]:
        new_patterns = []
        for req in blocked_requests:
            path = req.get("path", "")
            query = req.get("query_string", "")
            body = req.get("body_preview", "")
            threat = req.get("reason", "")
            combined = f"{path} {query} {body}".lower()
            candidates = self._extract_patterns(combined, threat)
            for candidate in candidates:
                if not self._pattern_exists(candidate["pattern"]):
                    candidate["created_at"] = datetime.utcnow().isoformat()
                    candidate["confidence"] = 0.5
                    candidate["hit_count"] = 0
                    candidate["status"] = "pending_review"
                    new_patterns.append(candidate)
                    self._rules.append(candidate)
        if new_patterns:
            self._save_rules()
            logger.info("auto_signatures_generated", count=len(new_patterns))
        return new_patterns

    def _extract_patterns(self, text: str, threat: str) -> List[Dict]:
        candidates = []
        sql_patterns = ["union", "select", "drop", "insert", "delete", "update", "or 1=1", "and 1=1", "' or '", "admin'--", "; drop", "information_schema"]
        for kw in sql_patterns:
            if kw in text:
                candidates.append({"category": "SQL Injection", "pattern": re.escape(kw), "name": f"auto_sql_{kw.replace(' ', '_')}", "threat_level": "high", "source": threat})
        xss_patterns = ["<script", "javascript:", "onerror=", "onload=", "onclick=", "document.cookie", "alert(", "eval("]
        for kw in xss_patterns:
            if kw in text:
                candidates.append({"category": "XSS", "pattern": re.escape(kw), "name": f"auto_xss_{kw.replace(' ', '_').replace('=', '').replace('<', '').replace('(', '')}", "threat_level": "medium", "source": threat})
        cmd_patterns = [";cat ", "|ls ", "|whoami", "&&", "`", "$(", "/bin/bash", "/bin/sh", "cmd.exe", "powershell"]
        for kw in cmd_patterns:
            if kw in text:
                candidates.append({"category": "Command Injection", "pattern": re.escape(kw), "name": f"auto_cmd_{kw.replace(' ', '_').replace('/', '').replace(';', '').replace('|', '')}", "threat_level": "critical", "source": threat})
        traversal_patterns = ["../", "..\\", "/etc/passwd", "/etc/shadow", "proc/self"]
        for kw in traversal_patterns:
            if kw in text:
                candidates.append({"category": "File Inclusion", "pattern": re.escape(kw), "name": f"auto_traversal_{kw.replace('/', '').replace('\\\\', '').replace(' ', '_')}", "threat_level": "high", "source": threat})
        if not candidates:
            suspicious_chars = ["<", ">", "'", '"', ";", "|", "`", "$", "{", "}"]
            char_count = sum(1 for c in suspicious_chars if c in text)
            if char_count >= 3:
                pattern_str = re.escape(text[:50]) if len(text) > 50 else re.escape(text)
                candidates.append({"category": "Suspicious Pattern", "pattern": pattern_str, "name": f"auto_suspicious_{hash(text) % 10000}", "threat_level": "low", "source": threat})
        return candidates

    def _pattern_exists(self, pattern: str) -> bool:
        for rule in self._rules:
            if rule.get("pattern") == pattern:
                return True
        return False

    def get_rules(self, status: Optional[str] = None) -> List[Dict]:
        if status:
            return [r for r in self._rules if r.get("status") == status]
        return self._rules

    def approve_rule(self, index: int) -> Dict:
        if 0 <= index < len(self._rules):
            self._rules[index]["status"] = "approved"
            self._rules[index]["confidence"] = 0.9
            self._save_rules()
            return {"status": "approved", "rule": self._rules[index]}
        return {"status": "not_found"}

    def reject_rule(self, index: int) -> Dict:
        if 0 <= index < len(self._rules):
            self._rules[index]["status"] = "rejected"
            self._save_rules()
            return {"status": "rejected", "rule": self._rules[index]}
        return {"status": "not_found"}

    def delete_rule(self, index: int) -> Dict:
        if 0 <= index < len(self._rules):
            deleted = self._rules.pop(index)
            self._save_rules()
            return {"status": "deleted", "rule": deleted}
        return {"status": "not_found"}

    def get_stats(self) -> Dict:
        total = len(self._rules)
        approved = sum(1 for r in self._rules if r.get("status") == "approved")
        pending = sum(1 for r in self._rules if r.get("status") == "pending_review")
        rejected = sum(1 for r in self._rules if r.get("status") == "rejected")
        categories = {}
        for r in self._rules:
            cat = r.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
        return {"total": total, "approved": approved, "pending": pending, "rejected": rejected, "categories": categories}


auto_signature_generator = AutoSignatureGenerator()

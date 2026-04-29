import json
import structlog
from typing import Dict, List, Optional
from pathlib import Path

logger = structlog.get_logger()

DEFAULT_CONFIG = {
    "general": {
        "waf_mode": "blocking",
        "log_blocked": True,
        "log_allowed": False
    },
    "strategies": {
        "signature": {
            "enabled": True,
            "block_threshold": 1,
            "categories": {
                "sql_injection": True,
                "xss": True,
                "ssti": True,
                "ssi": True,
                "xxe_xml": True,
                "command_injection": True,
                "file_inclusion": True,
                "file_upload": True
            }
        },
        "behavior": {
            "enabled": True,
            "suspicious_paths": True,
            "path_scanning_threshold": 10,
            "rate_anomaly_detection": True
        },
        "header_validation": {
            "enabled": True,
            "block_forbidden_headers": True,
            "detect_tool_signatures": True,
            "validate_content_type": True,
            "max_headers": 50,
            "max_header_size": 8192
        }
    },
    "ip_blacklist": {
        "enabled": True,
        "auto_ban_threshold": 5,
        "ban_duration_minutes": 60,
        "permanent_ban_threshold": 20
    },
    "rate_limiting": {
        "enabled": True,
        "max_requests": 100,
        "window_seconds": 60,
        "burst_multiplier": 2.0
    },
    "ai_engine": {
        "enabled": True,
        "confidence_threshold": 0.6,
        "require_agreement": False,
        "timeout_seconds": 5.0
    },
    "whitelist": {
        "ips": [],
        "paths": ["/health", "/waf/health", "/waf/metrics", "/waf/stats", "/dashboard/summary", "/dashboard/logs", "/dashboard/timeline", "/dashboard/strategies", "/dashboard/seed", "/security/"]
    },
    "custom_patterns": []
}


class WAFConfig:
    def __init__(self, config_path: Optional[str] = None):
        self._config = dict(DEFAULT_CONFIG)
        self._config_path = config_path
        if config_path:
            self.load(config_path)

    def get(self) -> dict:
        return dict(self._config)

    def get_strategy(self, name: str) -> dict:
        return self._config.get("strategies", {}).get(name, {})

    def is_strategy_enabled(self, name: str) -> bool:
        return self.get_strategy(name).get("enabled", False)

    def is_ip_whitelisted(self, ip: str) -> bool:
        return ip in self._config.get("whitelist", {}).get("ips", [])

    def is_path_whitelisted(self, path: str) -> bool:
        wl_paths = self._config.get("whitelist", {}).get("paths", [])
        return any(path.startswith(wp) for wp in wl_paths)

    def is_category_enabled(self, strategy: str, category: str) -> bool:
        cats = self._config.get("strategies", {}).get(strategy, {}).get("categories", {})
        return cats.get(category, True)

    def update(self, updates: dict) -> dict:
        self._deep_update(self._config, updates)
        if self._config_path:
            self.save(self._config_path)
        return self.get()

    def reset(self) -> dict:
        self._config = dict(DEFAULT_CONFIG)
        if self._config_path:
            self.save(self._config_path)
        return self.get()

    def toggle_strategy(self, name: str, enabled: bool) -> dict:
        if name in self._config.get("strategies", {}):
            self._config["strategies"][name]["enabled"] = enabled
            if self._config_path:
                self.save(self._config_path)
        return self.get()

    def add_custom_pattern(self, category: str, pattern: str, name: str, threat_level: str = "high") -> dict:
        self._config["custom_patterns"].append({
            "category": category,
            "pattern": pattern,
            "name": name,
            "threat_level": threat_level
        })
        if self._config_path:
            self.save(self._config_path)
        return self.get()

    def remove_custom_pattern(self, index: int) -> dict:
        if 0 <= index < len(self._config["custom_patterns"]):
            self._config["custom_patterns"].pop(index)
            if self._config_path:
                self.save(self._config_path)
        return self.get()

    def get_custom_patterns(self) -> list:
        return list(self._config.get("custom_patterns", []))

    def add_whitelist_ip(self, ip: str) -> dict:
        if ip not in self._config["whitelist"]["ips"]:
            self._config["whitelist"]["ips"].append(ip)
            if self._config_path:
                self.save(self._config_path)
        return self.get()

    def remove_whitelist_ip(self, ip: str) -> dict:
        if ip in self._config["whitelist"]["ips"]:
            self._config["whitelist"]["ips"].remove(ip)
            if self._config_path:
                self.save(self._config_path)
        return self.get()

    def add_whitelist_path(self, path: str) -> dict:
        if path not in self._config["whitelist"]["paths"]:
            self._config["whitelist"]["paths"].append(path)
            if self._config_path:
                self.save(self._config_path)
        return self.get()

    def remove_whitelist_path(self, path: str) -> dict:
        if path in self._config["whitelist"]["paths"]:
            self._config["whitelist"]["paths"].remove(path)
            if self._config_path:
                self.save(self._config_path)
        return self.get()

    def get_rate_limit_config(self) -> dict:
        return self._config.get("rate_limiting", {})

    def get_blacklist_config(self) -> dict:
        return self._config.get("ip_blacklist", {})

    def load(self, path: str):
        try:
            with open(path, "r") as f:
                loaded = json.load(f)
            self._deep_update(self._config, loaded)
            logger.info("waf_config_loaded", path=path)
        except Exception as e:
            logger.error("waf_config_load_failed", error=str(e))

    def save(self, path: str):
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as f:
                json.dump(self._config, f, indent=2)
            logger.info("waf_config_saved", path=path)
        except Exception as e:
            logger.error("waf_config_save_failed", error=str(e))

    def _deep_update(self, base: dict, updates: dict):
        for key, value in updates.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_update(base[key], value)
            else:
                base[key] = value


waf_config = WAFConfig()

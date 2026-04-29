import time
import structlog
import numpy as np
from typing import List, Tuple, Optional
from fastapi import Request, Response
from fastapi.responses import JSONResponse
import httpx

from config import settings
from models.request import RequestMetadata, AIAnalysisResult, Decision, AIStrategyResult
from ai_engine.base import AIAgent
from ai_engine.openai_agent import OpenAIAgent
from ai_engine.custom_agent import CustomAIAgent
from ai_engine.numpy_scorer import threat_scorer
from ai_engine.ip_blacklist import ip_blacklist
from strategies.base import Strategy
from strategies.signature import SignatureStrategy
from strategies.behavior import BehaviorStrategy
from strategies.header_validation import HeaderValidationStrategy
from strategies.zero_day_ddos import ZeroDayStrategy, DDoSStrategy
from strategies.rate_limiter import rate_limiter
from request_log import request_logger

from waf_config import waf_config
from database import waf_db

logger = structlog.get_logger()


class WAFProxy:
    def __init__(self):
        self.ai_agents: List[AIAgent] = []
        self.strategies: List[Strategy] = []
        self.metrics = {
            "total_requests": 0,
            "blocked_requests": 0,
            "allowed_requests": 0,
            "blacklisted_blocks": 0,
            "rate_limit_blocks": 0,
            "analysis_times": []
        }
        self._setup_agents()
        self._setup_strategies()

    def _setup_agents(self):
        ai_cfg = waf_config.get().get("ai_engine", {})
        if waf_config.is_strategy_enabled("ai_engine") and settings.OPENAI_API_KEY:
            self.ai_agents.append(OpenAIAgent())
            logger.info("openai_agent_enabled")
        if waf_config.is_strategy_enabled("ai_engine") and settings.CUSTOM_AI_API_URL:
            self.ai_agents.append(CustomAIAgent())
            logger.info("custom_ai_agent_enabled")
        if not self.ai_agents:
            logger.warning("no_ai_agents_configured")

    def _setup_strategies(self):
        strategy_map = {
            "signature": SignatureStrategy(),
            "behavior": BehaviorStrategy(),
            "header_validation": HeaderValidationStrategy(),
            "zero_day": ZeroDayStrategy(),
            "ddos_protection": DDoSStrategy(),
        }
        for strategy_name, instance in strategy_map.items():
            if waf_config.is_strategy_enabled(strategy_name):
                self.strategies.append(instance)
                logger.info("strategy_enabled", strategy=strategy_name)

    def reload_strategies(self):
        self.strategies.clear()
        self._setup_strategies()
        logger.info("strategies_reloaded", count=len(self.strategies))

    def check_ip_blacklist(self, ip: str) -> Optional[Response]:
        if waf_config.is_ip_whitelisted(ip):
            return None
        bl_cfg = waf_config.get_blacklist_config()
        if not bl_cfg.get("enabled", True):
            return None
        if waf_db.blacklist_is_blocked(ip):
            self.metrics["blacklisted_blocks"] += 1
            return JSONResponse(
                status_code=403,
                content={"error": "IP blocked by WAF", "reason": "IP is blacklisted"}
            )
        return None

    def check_rate_limit(self, ip: str) -> Optional[Response]:
        if waf_config.is_ip_whitelisted(ip):
            return None
        rl_cfg = waf_config.get_rate_limit_config()
        if not rl_cfg.get("enabled", True):
            return None
        rate_limiter._max_requests = rl_cfg.get("max_requests", 100)
        rate_limiter._window_seconds = rl_cfg.get("window_seconds", 60)
        if rate_limiter.is_rate_limited(ip):
            self.metrics["rate_limit_blocks"] += 1
            remaining = rate_limiter.get_reset_time(ip)
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(remaining)},
                content={
                    "error": "Rate limit exceeded",
                    "limit": rate_limiter._max_requests,
                    "window_seconds": rate_limiter._window_seconds,
                    "retry_after_seconds": remaining
                }
            )
        return None

    async def analyze_request(self, request: Request) -> AIAnalysisResult:
        start_time = time.time()

        metadata = await self._extract_metadata(request)

        strategy_results = []
        for strategy in self.strategies:
            try:
                result = await strategy.evaluate(metadata)
                strategy_results.append(result)
            except Exception as e:
                logger.error("strategy_evaluation_failed", strategy=strategy.name, error=str(e))

        ai_results = []
        for agent in self.ai_agents:
            try:
                result = await agent.analyze(metadata)
                ai_results.append(result)
                strategy_results.extend(result.strategy_results)
            except Exception as e:
                logger.error("ai_agent_analysis_failed", agent=agent.name, error=str(e))

        overall = self._aggregate_results(strategy_results)

        elapsed_ms = (time.time() - start_time) * 1000
        self._update_metrics(overall.overall_decision, elapsed_ms)
        request_logger.log(metadata, overall, elapsed_ms)

        if overall.overall_decision == Decision.BLOCK:
            threats = [p for r in strategy_results for p in r.matched_patterns]
            if threats:
                ip_blacklist.add_violation(metadata.source_ip, threats[0], overall.overall_threat_level.value)
                bl_cfg = waf_config.get_blacklist_config()
                threshold = bl_cfg.get("auto_ban_threshold", 5)
                duration = bl_cfg.get("ban_duration_minutes", 60)
                violations = waf_db.blacklist_add_violation(metadata.source_ip, threats[0], overall.overall_threat_level.value)
                if violations >= threshold:
                    waf_db.blacklist_ban(metadata.source_ip, f"Auto-banned after {violations} violations", duration_hours=duration/60)
                    logger.warning("ip_auto_banned_db", ip=metadata.source_ip, violations=violations)

        logger.info(
            "waf_decision",
            decision=overall.overall_decision.value,
            threat_level=overall.overall_threat_level.value,
            confidence=overall.confidence,
            analysis_time_ms=round(elapsed_ms, 2)
        )

        return overall

    def get_block_response(self, analysis: AIAnalysisResult) -> Response:
        return JSONResponse(
            status_code=403,
            content={
                "error": settings.BLOCK_RESPONSE_MESSAGE,
                "reason": analysis.reasoning,
                "threat_level": analysis.overall_threat_level.value,
                "confidence": analysis.confidence
            }
        )

    def get_rate_limit_response(self, ip: str) -> Response:
        remaining = rate_limiter.get_reset_time(ip)
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(remaining)},
            content={
                "error": "Rate limit exceeded",
                "limit": rate_limiter._max_requests,
                "window_seconds": rate_limiter._window_seconds,
                "retry_after_seconds": remaining
            }
        )

    async def forward_request(self, request: Request) -> Response:
        url = f"{settings.UPSTREAM_URL}{request.url.path}"
        if request.url.query:
            url += f"?{request.url.query}"

        body = await request.body()

        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ("host", "content-length")
        }
        headers["X-WAF-Analyzed"] = "true"
        headers["X-WAF-Threat-Score"] = "checked"

        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body,
                timeout=30.0,
                follow_redirects=False
            )

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers)
        )

    def get_metrics(self) -> dict:
        avg_time = (
            sum(self.metrics["analysis_times"]) / len(self.metrics["analysis_times"])
            if self.metrics["analysis_times"] else 0
        )
        return {
            "total_requests": self.metrics["total_requests"],
            "blocked_requests": self.metrics["blocked_requests"],
            "allowed_requests": self.metrics["allowed_requests"],
            "blacklisted_blocks": self.metrics["blacklisted_blocks"],
            "rate_limit_blocks": self.metrics["rate_limit_blocks"],
            "avg_analysis_time_ms": round(avg_time, 2)
        }

    async def health_check(self) -> dict:
        agent_health = {}
        for agent in self.ai_agents:
            try:
                healthy = await agent.health_check()
                agent_health[agent.name] = healthy
            except Exception:
                agent_health[agent.name] = False

        return {
            "status": "healthy",
            "agents": agent_health,
            "strategies": [s.name for s in self.strategies]
        }

    async def _extract_metadata(self, request: Request) -> RequestMetadata:
        body = await request.body()
        body_preview = body[:500].decode("utf-8", errors="ignore") if body else ""

        headers = {k: v for k, v in request.headers.items()}

        client_ip = request.client.host if request.client else "unknown"
        forwarded_for = headers.get("x-forwarded-for", "")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()

        return RequestMetadata(
            method=request.method,
            path=str(request.url.path),
            query_string=str(request.url.query) if request.url.query else "",
            headers=headers,
            body_preview=body_preview,
            source_ip=client_ip
        )

    def _aggregate_results(self, results: List[AIStrategyResult]) -> AIAnalysisResult:
        if not results:
            return AIAnalysisResult(
                overall_decision=Decision.ALLOW,
                overall_threat_level="none",
                confidence=0.0,
                reasoning="No analysis performed"
            )

        decisions_data = []
        threat_levels = []
        for r in results:
            weight = 1.5 if "openai" in r.strategy_name or "custom" in r.strategy_name else 1.0
            # Only include blocking strategies in threat score calculation
            if r.decision == Decision.BLOCK:
                decisions_data.append({
                    "confidence": r.confidence,
                    "weight": weight
                })
            threat_levels.append(r.threat_level)

        threat_score = threat_scorer.calculate_threat_score(decisions_data) if decisions_data else 0.0
        aggregated_threat = threat_scorer.aggregate_threat_levels(threat_levels)

        block_threshold = 0.5
        overall_decision = Decision.BLOCK if threat_score > block_threshold else Decision.ALLOW

        reasons = [r.reason for r in results if r.reason]
        all_patterns = []
        for r in results:
            all_patterns.extend(r.matched_patterns)

        confidence_values = np.array([r.confidence for r in results])
        avg_confidence = float(np.mean(confidence_values))

        return AIAnalysisResult(
            overall_decision=overall_decision,
            overall_threat_level=aggregated_threat,
            confidence=avg_confidence,
            reasoning="; ".join(reasons) if reasons else "Request allowed",
            strategy_results=results
        )

    def _update_metrics(self, decision: Decision, elapsed_ms: float):
        self.metrics["total_requests"] += 1
        if decision == Decision.BLOCK:
            self.metrics["blocked_requests"] += 1
        else:
            self.metrics["allowed_requests"] += 1
        self.metrics["analysis_times"].append(elapsed_ms)
        self.metrics["analysis_times"] = self.metrics["analysis_times"][-100:]

    def get_analysis_stats(self) -> dict:
        times = np.array(self.metrics["analysis_times"])
        if times.size == 0:
            return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "p95": 0.0}
        return {
            "mean": float(np.mean(times)),
            "std": float(np.std(times)),
            "min": float(np.min(times)),
            "max": float(np.max(times)),
            "p95": float(np.percentile(times, 95))
        }

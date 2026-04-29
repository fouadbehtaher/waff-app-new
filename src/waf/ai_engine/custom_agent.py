import json
import structlog
import httpx
from typing import Optional
from config import settings
from models.request import RequestMetadata, AIAnalysisResult, AIStrategyResult, Decision, ThreatLevel
from ai_engine.base import AIAgent

logger = structlog.get_logger()


class CustomAIAgent(AIAgent):
    name = "custom"

    def __init__(self):
        self.client = httpx.AsyncClient(
            base_url=settings.CUSTOM_AI_API_URL,
            timeout=settings.AI_TIMEOUT_SECONDS
        )
        self.api_key = settings.CUSTOM_AI_API_KEY

    async def analyze(self, request: RequestMetadata) -> AIAnalysisResult:
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}" if self.api_key else ""
            }

            payload = {
                "method": request.method,
                "path": request.path,
                "query_string": request.query_string,
                "headers": request.headers,
                "body_preview": request.body_preview,
                "source_ip": request.source_ip
            }

            response = await self.client.post("/analyze", json=payload, headers=headers)
            response.raise_for_status()

            result = response.json()

            return AIAnalysisResult(
                overall_decision=Decision(result.get("decision", "allow")),
                overall_threat_level=ThreatLevel(result.get("threat_level", "none")),
                confidence=result.get("confidence", 0.0),
                reasoning=result.get("reason", ""),
                strategy_results=[
                    AIStrategyResult(
                        strategy_name="custom_ai_analysis",
                        decision=Decision(result.get("decision", "allow")),
                        threat_level=ThreatLevel(result.get("threat_level", "none")),
                        confidence=result.get("confidence", 0.0),
                        reason=result.get("reason", ""),
                        matched_patterns=result.get("matched_patterns", [])
                    )
                ]
            )

        except Exception as e:
            logger.error("custom_ai_analysis_failed", error=str(e))
            return AIAnalysisResult(
                overall_decision=Decision.ALLOW,
                overall_threat_level=ThreatLevel.NONE,
                confidence=0.0,
                reasoning=f"Custom AI analysis failed: {str(e)}"
            )

    async def health_check(self) -> bool:
        try:
            response = await self.client.get("/health")
            return response.status_code == 200
        except Exception:
            return False

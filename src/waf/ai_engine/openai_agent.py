import json
import structlog
from typing import Optional
from openai import AsyncOpenAI
from config import settings
from models.request import RequestMetadata, AIAnalysisResult, AIStrategyResult, Decision, ThreatLevel
from ai_engine.base import AIAgent

logger = structlog.get_logger()

SYSTEM_PROMPT = """You are an AI Web Application Firewall (WAF) agent.
Analyze the incoming HTTP request for potential security threats.

Look for:
- SQL Injection (SQLi): UNION, OR 1=1, DROP TABLE, blind SQLi, error-based SQLi
- Cross-Site Scripting (XSS): script tags, event handlers, javascript: URIs, DOM manipulation
- Server-Side Template Injection (SSTI): Jinja2, Flask, Twig, Django template injection
- Server-Side Includes (SSI): #include, #exec, #echo, SSI directives
- XML External Entity (XXE): DOCTYPE, ENTITY, SYSTEM entities, file:// URIs in XML
- Command Injection: shell commands, pipes, backticks, eval/exec, OS commands
- File Inclusion (LFI/RFI): ../ traversal, php:// wrappers, remote file inclusion
- File Upload: malicious file types, executable extensions, null bytes, polyglot files
- Path Traversal: directory traversal, encoded traversal, /etc/passwd access
- Bot/automated attack signatures

Respond with a JSON object containing:
{
    "decision": "allow" or "block",
    "threat_level": "none" | "low" | "medium" | "high" | "critical",
    "confidence": 0.0-1.0,
    "reason": "brief explanation",
    "matched_patterns": ["list of detected threat patterns"]
}
"""


class OpenAIAgent(AIAgent):
    name = "openai"

    def __init__(self):
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

    async def analyze(self, request: RequestMetadata) -> AIAnalysisResult:
        try:
            request_description = self._format_request(request)

            response = await self.client.chat.completions.create(
                model=settings.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": request_description}
                ],
                temperature=0.1,
                max_tokens=300,
                response_format={"type": "json_object"}
            )

            content = response.choices[0].message.content
            result = json.loads(content)

            return AIAnalysisResult(
                overall_decision=Decision(result.get("decision", "allow")),
                overall_threat_level=ThreatLevel(result.get("threat_level", "none")),
                confidence=result.get("confidence", 0.0),
                reasoning=result.get("reason", ""),
                strategy_results=[
                    AIStrategyResult(
                        strategy_name="openai_analysis",
                        decision=Decision(result.get("decision", "allow")),
                        threat_level=ThreatLevel(result.get("threat_level", "none")),
                        confidence=result.get("confidence", 0.0),
                        reason=result.get("reason", ""),
                        matched_patterns=result.get("matched_patterns", [])
                    )
                ]
            )

        except Exception as e:
            logger.error("openai_analysis_failed", error=str(e))
            return AIAnalysisResult(
                overall_decision=Decision.ALLOW,
                overall_threat_level=ThreatLevel.NONE,
                confidence=0.0,
                reasoning=f"OpenAI analysis failed: {str(e)}"
            )

    async def health_check(self) -> bool:
        try:
            response = await self.client.chat.completions.create(
                model=settings.OPENAI_MODEL,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=5
            )
            return response is not None
        except Exception:
            return False

    def _format_request(self, request: RequestMetadata) -> str:
        headers_str = json.dumps(request.headers, indent=2)
        return f"""HTTP Request Analysis:

Method: {request.method}
Path: {request.path}
Query String: {request.query_string}
Source IP: {request.source_ip}
Headers: {headers_str}
Body Preview: {request.body_preview}
"""

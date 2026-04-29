from abc import ABC, abstractmethod
from typing import Optional
from models.request import RequestMetadata, AIAnalysisResult


class AIAgent(ABC):
    name: str = "base"

    @abstractmethod
    async def analyze(self, request: RequestMetadata) -> AIAnalysisResult:
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        pass

from abc import ABC, abstractmethod
from models.request import RequestMetadata, AIStrategyResult


class Strategy(ABC):
    name: str = "base"

    @abstractmethod
    async def evaluate(self, request: RequestMetadata) -> AIStrategyResult:
        pass

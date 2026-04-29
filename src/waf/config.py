from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import List, Optional


class Settings(BaseSettings):
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )
    APP_NAME: str = "AI-WAF"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    UPSTREAM_URL: str = "http://localhost:8080"

    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"

    CUSTOM_AI_API_URL: Optional[str] = None
    CUSTOM_AI_API_KEY: Optional[str] = None

    ENABLED_STRATEGIES: List[str] = ["signature", "behavior"]

    AI_TIMEOUT_SECONDS: float = 5.0
    BLOCK_RESPONSE_MESSAGE: str = "Request blocked by AI-WAF"

    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    APPLICATIONINSIGHTS_CONNECTION_STRING: Optional[str] = None

    TLS_CERT_PATH: Optional[str] = None
    TLS_KEY_PATH: Optional[str] = None
    TLS_CA_PATH: Optional[str] = None

    REDIS_URL: Optional[str] = "redis://localhost:6379/0"
    USE_REDIS: bool = False

    LOG_BATCH_INTERVAL: float = 5.0
    USE_ASYNC_DB: bool = True

    ZERO_DAY_DEV_THRESHOLD: float = 2.5
    ZERO_DAY_BASELINE_WINDOW: int = 200

    DDOS_GLOBAL_RPS_THRESHOLD: int = 500
    DDOS_IP_FLOOD_THRESHOLD: int = 60


settings = Settings()

from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://aegis:aegis_dev_password@localhost:5432/aegis"
    kafka_bootstrap_servers: str = "localhost:9092"
    elasticsearch_url: str = "http://localhost:9200"
    redis_url: str = "redis://localhost:6379"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    llm_enabled: bool = False
    ollama_timeout: int = 30

    detection_engine_url: str = "http://localhost:8004"
    agent_orchestrator_url: str = "http://localhost:8005"

    prediction_confidence_threshold: float = 0.75
    prediction_ttl_minutes: int = 10
    monitor_interval_seconds: int = 30

    model_config = {"env_file": ".env", "case_sensitive": False}


@lru_cache()
def get_settings() -> Settings:
    return Settings()

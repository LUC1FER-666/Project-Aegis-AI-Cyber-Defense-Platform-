from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://aegis:aegis_dev_password@localhost:5432/aegis"
    kafka_bootstrap_servers: str = "localhost:9092"
    elasticsearch_url: str = "http://localhost:9200"
    redis_url: str = "redis://localhost:6379"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    llm_enabled: bool = False
    asset_discovery_url: str = "http://localhost:8001"
    ollama_timeout: int = 30
    execution_timeout: int = 120

    model_config = {"env_file": ".env", "case_sensitive": False}


@lru_cache()
def get_settings() -> Settings:
    return Settings()

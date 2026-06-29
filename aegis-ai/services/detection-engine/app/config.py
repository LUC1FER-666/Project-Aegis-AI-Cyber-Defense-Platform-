"""
Detection Engine — Configuration
"""
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Service
    service_name: str = "detection-engine"
    service_port: int = 8004
    debug: bool = False

    # PostgreSQL
    database_url: str = Field(
        default="postgresql+asyncpg://aegis:aegis_password@localhost:5432/aegis",
        alias="DATABASE_URL",
    )

    # Kafka
    kafka_bootstrap_servers: str = Field(
        default="localhost:9092",
        alias="KAFKA_BOOTSTRAP_SERVERS",
    )
    kafka_consumer_group: str = "detection-engine-group"

    # Elasticsearch
    elasticsearch_url: str = Field(
        default="http://localhost:9200",
        alias="ELASTICSEARCH_URL",
    )

    # Redis
    redis_url: str = Field(
        default="redis://localhost:6379",
        alias="REDIS_URL",
    )

    # Ollama
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        alias="OLLAMA_BASE_URL",
    )
    ollama_model: str = Field(
        default="llama3.2",
        alias="OLLAMA_MODEL",
    )
    llm_enabled: bool = Field(
        default=True,
        alias="LLM_ENABLED",
    )

    # ML
    anomaly_contamination: float = 0.05  # expected anomaly fraction
    anomaly_min_samples: int = 100        # minimum samples before model trains
    anomaly_retrain_interval: int = 3600  # seconds between retrains

    # Sigma
    sigma_rules_path: str = "sigma_rules"

    # Correlation
    correlation_window_seconds: int = 300   # 5 minutes
    correlation_min_alerts: int = 2          # min alerts to form incident

    # JWT (shared with gateway)
    jwt_secret: str = Field(
        default="aegis-secret-key-change-in-production",
        alias="JWT_SECRET",
    )
    jwt_algorithm: str = "HS256"

    model_config = {
        "env_file": ".env",
        "extra": "ignore",
        "populate_by_name": True,
    }


settings = Settings()

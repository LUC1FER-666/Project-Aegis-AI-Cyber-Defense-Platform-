from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://aegis:aegis_dev_password@localhost:5432/aegis"
    REDIS_URL: str = "redis://localhost:6379"
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "aegis_dev_password"

    # Downstream service URLs
    DETECTION_ENGINE_URL: str = "http://localhost:8004"
    AGENT_ORCHESTRATOR_URL: str = "http://localhost:8005"
    THREAT_DEFENSE_URL: str = "http://localhost:8006"

    # Poll interval in seconds
    TIMELINE_POLL_INTERVAL: int = 10
    GRAPH_BUILD_INTERVAL: int = 30

    # Redis keys
    REDIS_TIMELINE_CACHE: str = "aegis:timeline:events"
    REDIS_SEEN_PREFIX: str = "aegis:timeline:seen"
    REDIS_TIMELINE_MAX: int = 500

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()

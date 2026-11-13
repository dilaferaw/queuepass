from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "Queuepass"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"
    DATABASE_URL: str

    # Redis logical DB assignments:
    # DB 0 -> JWT revocation (JTI denylist + user cutoff)
    # DB 1 -> Seat locks / holds
    # DB 2 -> Celery broker
    REDIS_REVOCATION_URL: str
    REDIS_LOCKS_URL: str
    REDIS_BROKER_URL: str


settings = Settings()

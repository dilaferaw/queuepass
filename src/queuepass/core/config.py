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

    # JWT — auth tokens (Increment 1).
    #   `sub` is the user id as a STRING (RFC 7519 StringOrURI). If you put an
    #   int, some JWT libraries reject the token; the spec-compliant form is str.
    #   `jti` is a per-token unique id — reserved for Increment 2 (JWT revocation
    #   via a Redis denylist keyed on jti; user-level cutoff keyed on cutoff time).
    #   `type` is reserved for future refresh tokens so we can distinguish an
    #   access token from a refresh token with the same signing key.
    # JWT_SECRET_KEY has no default — pydantic-settings will raise at startup
    # if it is missing. This is deliberate: a missing secret should hard-fail
    # the process, not silently fall back to a dev default in production.
    # Generate with: openssl rand -hex 32
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 30

    # Redis logical DB assignments:
    # DB 0 -> JWT revocation (JTI denylist + user cutoff)
    # DB 1 -> Seat locks / holds
    # DB 2 -> Celery broker
    REDIS_REVOCATION_URL: str
    REDIS_LOCKS_URL: str
    REDIS_BROKER_URL: str


settings = Settings()

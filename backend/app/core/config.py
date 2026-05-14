from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(ENV_PATH, override=False)


class Settings(BaseSettings):
    app_name: str = Field(default="RJ Intelligence API", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    app_log_level: str = Field(default="INFO", alias="APP_LOG_LEVEL")

    jwt_secret_key: str = Field(default="change-me", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    jwt_access_token_expire_minutes: int = Field(
        default=60, alias="JWT_ACCESS_TOKEN_EXPIRE_MINUTES"
    )

    mongodb_url: str = Field(default="mongodb://localhost:27017", alias="MONGODB_URL")
    mongodb_db_name: str = Field(default="threat_intel", alias="MONGODB_DB_NAME")
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    celery_broker_url: str = Field(
        default="redis://localhost:6379/1", alias="CELERY_BROKER_URL"
    )
    celery_result_backend: str = Field(
        default="redis://localhost:6379/2", alias="CELERY_RESULT_BACKEND"
    )

    allowed_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000", alias="ALLOWED_ORIGINS"
    )
    rate_limit_requests: int = Field(default=120, alias="RATE_LIMIT_REQUESTS")
    rate_limit_window_seconds: int = Field(default=60, alias="RATE_LIMIT_WINDOW_SECONDS")
    alert_risk_threshold: float = Field(default=60.0, alias="ALERT_RISK_THRESHOLD")

    virustotal_api_key: str | None = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    shodan_api_key: str | None = Field(default=None, alias="SHODAN_API_KEY")
    ipinfo_token: str | None = Field(default=None, alias="IPINFO_TOKEN")
    external_api_timeout_seconds: float = Field(
        default=15.0, alias="EXTERNAL_API_TIMEOUT_SECONDS"
    )
    external_api_max_retries: int = Field(default=3, alias="EXTERNAL_API_MAX_RETRIES")
    external_api_backoff_seconds: float = Field(
        default=0.75, alias="EXTERNAL_API_BACKOFF_SECONDS"
    )

    risk_weight_breach_db: float = Field(default=0.9, alias="RISK_WEIGHT_BREACH_DB")
    risk_weight_forum: float = Field(default=0.6, alias="RISK_WEIGHT_FORUM")
    risk_weight_paste: float = Field(default=0.7, alias="RISK_WEIGHT_PASTE")
    risk_sensitivity_password: float = Field(default=1.0, alias="RISK_SENSITIVITY_PASSWORD")
    risk_sensitivity_email: float = Field(default=0.7, alias="RISK_SENSITIVITY_EMAIL")
    risk_sensitivity_username: float = Field(default=0.5, alias="RISK_SENSITIVITY_USERNAME")
    risk_sensitivity_domain: float = Field(default=0.6, alias="RISK_SENSITIVITY_DOMAIN")

    model_config = SettingsConfigDict(env_file=ENV_PATH, extra="ignore")

    def external_api_status(self) -> dict[str, bool]:
        return {
            "virustotal": bool((self.virustotal_api_key or "").strip()),
            "shodan": bool((self.shodan_api_key or "").strip()),
            "ipinfo": bool((self.ipinfo_token or "").strip()),
        }

    def missing_external_env_vars(self) -> list[str]:
        missing = []
        if not (self.virustotal_api_key or "").strip():
            missing.append("VIRUSTOTAL_API_KEY")
        if not (self.shodan_api_key or "").strip():
            missing.append("SHODAN_API_KEY")
        if not (self.ipinfo_token or "").strip():
            missing.append("IPINFO_TOKEN")
        return missing


@lru_cache
def get_settings() -> Settings:
    return Settings()
import os
import secrets
import logging
from functools import lru_cache
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    # App
    APP_NAME: str = "SecureWatch SIEM"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False

    # Secret key — MUST be set via env in production
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")

    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://siem:siem_change_me_now@localhost:5432/siem"
    )
    DB_POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", "20"))
    DB_MAX_OVERFLOW: int = int(os.getenv("DB_MAX_OVERFLOW", "40"))
    DB_POOL_TIMEOUT: int = int(os.getenv("DB_POOL_TIMEOUT", "30"))

    # Elasticsearch
    ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    ES_LOG_INDEX_PREFIX: str = "siem-logs"
    ES_NUMBER_OF_SHARDS: int = int(os.getenv("ES_NUMBER_OF_SHARDS", "2"))
    ES_NUMBER_OF_REPLICAS: int = int(os.getenv("ES_NUMBER_OF_REPLICAS", "1"))

    # Data retention
    LOG_RETENTION_DAYS: int = int(os.getenv("LOG_RETENTION_DAYS", "90"))

    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

    # CORS
    CORS_ORIGINS: list = [
        "https://localhost",
        "https://localhost:8443",
        "http://localhost:3000",
        "http://localhost:8080",
        "http://frontend:3000",
    ]

    # Agent
    AGENT_HEARTBEAT_TIMEOUT: int = 90
    AGENT_STATUS_CHECK_INTERVAL: int = 60

    # Admin defaults (only used on first startup)
    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin@SIEM2024!")
    DEFAULT_ADMIN_EMAIL: str = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@siem.local")

    # Password policy
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # Email (SMTP)
    SMTP_ENABLED:  bool = os.getenv("SMTP_ENABLED", "false").lower() == "true"
    SMTP_HOST:     str  = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT:     int  = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str  = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str  = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM:     str  = os.getenv("SMTP_FROM", "siem@yourdomain.com")
    SMTP_TO:       str  = os.getenv("SMTP_TO", "")
    SMTP_USE_TLS:  bool = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

    # Slack
    SLACK_ENABLED:     bool = os.getenv("SLACK_ENABLED", "false").lower() == "true"
    SLACK_WEBHOOK_URL: str  = os.getenv("SLACK_WEBHOOK_URL", "")
    SLACK_CHANNEL:     str  = os.getenv("SLACK_CHANNEL", "#siem-alerts")

    # GeoIP (ip-api.com — free tier, 45 req/min)
    GEOIP_ENABLED: bool = os.getenv("GEOIP_ENABLED", "true").lower() == "true"

    # AbuseIPDB (free tier: 1000 checks/day)
    ABUSEIPDB_API_KEY:  str  = os.getenv("ABUSEIPDB_API_KEY", "")
    ABUSEIPDB_ENABLED:  bool = os.getenv("ABUSEIPDB_ENABLED", "false").lower() == "true"
    ABUSEIPDB_MIN_SCORE: int = int(os.getenv("ABUSEIPDB_MIN_SCORE", "50"))

    # VirusTotal v3 API (free: 500 lookups/day)
    VT_API_KEY: str = os.getenv("VT_API_KEY", "")

    # Correlation Engine
    CORRELATION_EVAL_INTERVAL: int = int(os.getenv("CORRELATION_EVAL_INTERVAL", "60"))

    # NVD (NIST) CVE API
    NVD_API_KEY: str  = os.getenv("NVD_API_KEY", "")
    NVD_ENABLED: bool = os.getenv("NVD_ENABLED", "true").lower() == "true"

    # Prometheus metrics
    METRICS_ENABLED: bool = os.getenv("METRICS_ENABLED", "true").lower() == "true"

    # Agent shared secret — when set, /api/ar/pending and /api/ar/complete
    # require the matching X-Agent-Token header from agents.
    AGENT_SECRET: str = os.getenv("AGENT_SECRET", "")

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    s = Settings()

    # Auto-generate SECRET_KEY if not provided (warn loudly)
    if not s.SECRET_KEY:
        generated = secrets.token_hex(32)
        logger.critical(
            "SECRET_KEY not set! A random key has been generated for this session. "
            "Set SECRET_KEY in your .env file for persistent authentication. "
            f"Example: SECRET_KEY={generated}"
        )
        # Allow startup but tokens will invalidate on restart
        object.__setattr__(s, "SECRET_KEY", generated)

    return s


settings = get_settings()

import json
from dataclasses import dataclass
from decimal import Decimal
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import EmailStr, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

DEVELOPMENT_SECRET = "development-only-change-me-at-least-32-characters"

AIProvider = Literal["disabled", "anthropic", "openai"]
TicketProvider = Literal["disabled", "jira"]


@dataclass(frozen=True, slots=True)
class AIProviderConfig:
    provider: Literal["anthropic", "openai"]
    api_key: str
    model: str
    timeout_seconds: int
    max_output_tokens: int
    prompt_version: str
    input_price_per_million_usd: Decimal
    output_price_per_million_usd: Decimal
    workspace_id: str | None = None


@dataclass(frozen=True, slots=True)
class JiraConfig:
    base_url: str
    email: str
    api_token: str
    project_key: str
    issue_type: str
    timeout_seconds: int
    include_asset_details: bool
    app_public_url: str


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: str = "development"
    app_secret_key: str = DEVELOPMENT_SECRET
    database_url: str = (
        "postgresql+asyncpg://neoguardian:neoguardian-local-only@localhost:5432/neoguardian"
    )
    api_cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:3000"]
    max_scan_upload_mb: int | None = Field(default=None, ge=1, le=2048)
    max_nessus_upload_mb: int = Field(default=200, ge=1, le=2048)
    session_cookie_name: str = "ng_session"
    session_duration_hours: int = Field(default=8, ge=1, le=168)
    bootstrap_admin_name: str = "Administrador local"
    bootstrap_admin_email: EmailStr | None = None
    bootstrap_admin_password: str | None = None
    bootstrap_client_name: str = "Ambiente de demonstração"
    bootstrap_client_slug: str = "demo"
    app_public_url: str = "http://localhost:3000"
    ai_provider: AIProvider = "disabled"
    ai_timeout_seconds: int = Field(default=45, ge=5, le=120)
    ai_max_output_tokens: int = Field(default=2200, ge=500, le=8192)
    ai_prompt_version: str = Field(default="2026-09-04-v2", min_length=1, max_length=80)

    anthropic_api_key: str | None = None
    anthropic_workspace_id: str | None = None
    anthropic_model: str = Field(default="claude-haiku-4-5", min_length=1, max_length=120)
    anthropic_input_price_per_million_usd: Decimal = Field(default=Decimal("1.00"), ge=0)
    anthropic_output_price_per_million_usd: Decimal = Field(default=Decimal("5.00"), ge=0)

    openai_api_key: str | None = None
    openai_model: str = Field(default="gpt-5.4-mini", min_length=1, max_length=120)
    openai_input_price_per_million_usd: Decimal = Field(default=Decimal("0.75"), ge=0)
    openai_output_price_per_million_usd: Decimal = Field(default=Decimal("4.50"), ge=0)

    ticket_provider: TicketProvider = "disabled"
    jira_base_url: str | None = None
    jira_email: EmailStr | None = None
    jira_api_token: str | None = None
    jira_project_key: str | None = None
    jira_issue_type: str = Field(default="Task", min_length=1, max_length=80)
    jira_timeout_seconds: int = Field(default=20, ge=5, le=60)
    jira_include_asset_details: bool = False

    @field_validator("api_cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: object) -> object:
        if not isinstance(value, str):
            return value

        normalized = value.strip()
        if normalized.startswith("["):
            try:
                decoded = json.loads(normalized)
            except json.JSONDecodeError as exc:
                raise ValueError("API_CORS_ORIGINS contém um array JSON inválido.") from exc
            if not isinstance(decoded, list):
                raise ValueError("API_CORS_ORIGINS precisa conter uma lista de origens.")
            return decoded

        return [origin.strip() for origin in normalized.split(",") if origin.strip()]

    @field_validator("bootstrap_admin_email", mode="before")
    @classmethod
    def normalize_optional_email(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip().lower()
            return value or None
        return value

    @field_validator("bootstrap_admin_password", mode="before")
    @classmethod
    def normalize_optional_password(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip()
            return value or None
        return value

    @field_validator(
        "anthropic_api_key",
        "anthropic_workspace_id",
        "openai_api_key",
        "jira_base_url",
        "jira_api_token",
        "jira_project_key",
        mode="before",
    )
    @classmethod
    def normalize_optional_api_key(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip()
            return value or None
        return value

    @field_validator("jira_email", mode="before")
    @classmethod
    def normalize_optional_jira_email(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip().lower()
            return value or None
        return value

    @field_validator("jira_base_url", "app_public_url", mode="after")
    @classmethod
    def normalize_base_url(cls, value: str | None) -> str | None:
        return value.rstrip("/") if value else value

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        if not self.is_development and (
            len(self.app_secret_key) < 32 or self.app_secret_key == DEVELOPMENT_SECRET
        ):
            raise ValueError(
                "APP_SECRET_KEY precisa ser exclusiva e ter pelo menos 32 caracteres fora de "
                "desenvolvimento."
            )
        if self.bootstrap_admin_password and len(self.bootstrap_admin_password) < 12:
            raise ValueError("BOOTSTRAP_ADMIN_PASSWORD precisa ter pelo menos 12 caracteres.")
        return self

    @property
    def cors_origins(self) -> list[str]:
        return self.api_cors_origins

    @property
    def is_development(self) -> bool:
        return self.app_env.lower() == "development"

    @property
    def secure_cookies(self) -> bool:
        return not self.is_development

    @property
    def scan_upload_limit_mb(self) -> int:
        # MAX_NESSUS_UPLOAD_MB remains a backwards-compatible fallback.
        return self.max_scan_upload_mb or self.max_nessus_upload_mb

    @property
    def active_ai(self) -> AIProviderConfig | None:
        if self.ai_provider == "anthropic" and self.anthropic_api_key:
            return AIProviderConfig(
                provider="anthropic",
                api_key=self.anthropic_api_key,
                model=self.anthropic_model,
                timeout_seconds=self.ai_timeout_seconds,
                max_output_tokens=self.ai_max_output_tokens,
                prompt_version=self.ai_prompt_version,
                input_price_per_million_usd=self.anthropic_input_price_per_million_usd,
                output_price_per_million_usd=self.anthropic_output_price_per_million_usd,
                workspace_id=self.anthropic_workspace_id,
            )
        if self.ai_provider == "openai" and self.openai_api_key:
            return AIProviderConfig(
                provider="openai",
                api_key=self.openai_api_key,
                model=self.openai_model,
                timeout_seconds=self.ai_timeout_seconds,
                max_output_tokens=self.ai_max_output_tokens,
                prompt_version=self.ai_prompt_version,
                input_price_per_million_usd=self.openai_input_price_per_million_usd,
                output_price_per_million_usd=self.openai_output_price_per_million_usd,
            )
        return None

    @property
    def active_jira(self) -> JiraConfig | None:
        if (
            self.ticket_provider == "jira"
            and self.jira_base_url
            and self.jira_email
            and self.jira_api_token
            and self.jira_project_key
        ):
            return JiraConfig(
                base_url=self.jira_base_url,
                email=str(self.jira_email),
                api_token=self.jira_api_token,
                project_key=self.jira_project_key.upper(),
                issue_type=self.jira_issue_type,
                timeout_seconds=self.jira_timeout_seconds,
                include_asset_details=self.jira_include_asset_details,
                app_public_url=self.app_public_url,
            )
        return None


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

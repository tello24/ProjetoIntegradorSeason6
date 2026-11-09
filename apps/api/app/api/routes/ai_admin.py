"""Read-only, tenant-scoped administration. No provider requests or credentials."""

from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Response
from pydantic import BaseModel
from sqlalchemy import text

from app.api.dependencies import CurrentUserDep, SessionDep, require_role
from app.core.config import AIProvider, Settings, settings
from app.services.ai_errors import ERROR_MESSAGES

router = APIRouter()


class AIConfiguration(BaseModel):
    provider: AIProvider
    state: Literal["disabled", "missing_key", "configured"]
    key_configured: bool
    workspace_configured: bool
    model: str | None
    prompt_version: str
    timeout_seconds: int
    max_output_tokens: int
    input_price_per_million_usd: float | None
    output_price_per_million_usd: float | None


def configuration_snapshot(config: Settings) -> AIConfiguration:
    # Explicit allowlist: never serialize Settings or AIProviderConfig.
    prefix = config.ai_provider if config.ai_provider != "disabled" else None
    has_key = bool(getattr(config, f"{prefix}_api_key")) if prefix else False
    return AIConfiguration(
        provider=config.ai_provider,
        state="disabled" if not prefix else "configured" if has_key else "missing_key",
        key_configured=has_key,
        workspace_configured=(
            bool(config.anthropic_workspace_id) if prefix == "anthropic" else False
        ),
        model=getattr(config, f"{prefix}_model") if prefix else None,
        prompt_version=config.ai_prompt_version,
        timeout_seconds=config.ai_timeout_seconds,
        max_output_tokens=config.ai_max_output_tokens,
        input_price_per_million_usd=(
            float(getattr(config, f"{prefix}_input_price_per_million_usd")) if prefix else None
        ),
        output_price_per_million_usd=(
            float(getattr(config, f"{prefix}_output_price_per_million_usd")) if prefix else None
        ),
    )


class AIUsage(BaseModel):
    analyses: int
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float


class AIModelUsage(AIUsage):
    provider: str
    model: str


class AIFailure(BaseModel):
    id: int
    occurred_at: datetime
    provider: AIProvider
    error_code: str
    guidance: str
    cost_status: Literal["not_requested", "unknown"]


class AIAdminSummary(BaseModel):
    configuration: AIConfiguration
    days: int
    period_start: datetime
    as_of: datetime
    usage: AIUsage
    last_success_at: datetime | None
    failures: int
    failures_unknown_cost: int
    configuration_blocks: int
    models: list[AIModelUsage]
    recent_failures: list[AIFailure]


@router.get("/summary", response_model=AIAdminSummary)
async def get_ai_summary(
    current_user: CurrentUserDep,
    session: SessionDep,
    response: Response,
    days: Literal["7", "30", "90"] = "30",
) -> AIAdminSummary:
    require_role(current_user, frozenset({"administrador"}),
                 detail="Somente administradores podem consultar o painel da IA.")
    response.headers["Cache-Control"] = "private, no-store"
    as_of = datetime.now(UTC)
    since = as_of - timedelta(days=int(days))
    params = {"client_id": current_user.client_id, "since": since, "as_of": as_of}
    # All versions count toward spending, including superseded analyses.
    usage_result = await session.execute(text("""
        SELECT count(*) FILTER (WHERE criado_em >= :since) AS analyses,
               coalesce(sum(tokens_entrada) FILTER (WHERE criado_em >= :since), 0) AS input_tokens,
               coalesce(sum(tokens_saida) FILTER (WHERE criado_em >= :since), 0) AS output_tokens,
               coalesce(sum(custo_estimado_usd) FILTER (WHERE criado_em >= :since), 0)
                   AS estimated_cost_usd,
               max(criado_em) AS last_success_at
        FROM app.vulnerabilidade_analise_ia
        WHERE cliente_id = :client_id AND criado_em < :as_of
    """), params)
    usage = usage_result.mappings().one()
    failures_result = await session.execute(text("""
        SELECT count(*) AS failures,
               count(*) FILTER (WHERE detalhes->>'cost_status' = 'not_requested')
                   AS configuration_blocks,
               count(*) FILTER (WHERE detalhes->>'cost_status' IS DISTINCT FROM 'not_requested')
                   AS failures_unknown_cost
        FROM app.evento_auditoria
        WHERE cliente_id = :client_id AND acao = 'ai_analysis.failed'
          AND criado_em >= :since AND criado_em < :as_of
    """), params)
    failures = failures_result.mappings().one()
    models_result = await session.execute(text("""
        SELECT provedor AS provider, modelo AS model, count(*) AS analyses,
               sum(tokens_entrada) AS input_tokens, sum(tokens_saida) AS output_tokens,
               sum(custo_estimado_usd) AS estimated_cost_usd
        FROM app.vulnerabilidade_analise_ia
        WHERE cliente_id = :client_id AND criado_em >= :since AND criado_em < :as_of
        GROUP BY provedor, modelo
        ORDER BY estimated_cost_usd DESC, provedor, modelo
    """), params)
    recent_result = await session.execute(text("""
        SELECT id, criado_em, detalhes->>'provider' AS provider,
               detalhes->>'error_code' AS error_code, detalhes->>'cost_status' AS cost_status
        FROM app.evento_auditoria
        WHERE cliente_id = :client_id AND acao = 'ai_analysis.failed'
          AND criado_em >= :since AND criado_em < :as_of
        ORDER BY criado_em DESC, id DESC LIMIT 20
    """), params)
    recent = []
    for row in recent_result.mappings().all():
        code = row["error_code"] if row["error_code"] in ERROR_MESSAGES else "invalid_response"
        recent.append(AIFailure(
            id=row["id"], occurred_at=row["criado_em"],
            provider=row["provider"] if row["provider"] in {"anthropic", "openai"} else "disabled",
            error_code=code, guidance=ERROR_MESSAGES[code],
            cost_status="not_requested" if row["cost_status"] == "not_requested" else "unknown",
        ))
    return AIAdminSummary(
        configuration=configuration_snapshot(settings), days=int(days), period_start=since,
        as_of=as_of, usage=AIUsage(**usage), last_success_at=usage["last_success_at"],
        **failures, models=[AIModelUsage(**row) for row in models_result.mappings().all()],
        recent_failures=recent,
    )

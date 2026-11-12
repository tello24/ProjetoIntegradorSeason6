"""Read-only, tenant-scoped administration. No provider requests or credentials."""

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import AwareDatetime, BaseModel
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


class AIUserUsage(AIUsage):
    user_id: UUID | None
    name: str
    active: bool
    vulnerabilities: int
    failures_unknown_cost: int
    configuration_blocks: int


class AIUserVulnerability(AIUsage):
    workflow_id: UUID
    finding_id: int | None
    plugin_id: int | None
    title: str
    asset: str | None
    protocol: str | None
    port: int | None
    last_generated_at: datetime


class AIUserVulnerabilities(BaseModel):
    user_id: UUID | None
    days: int
    period_start: datetime
    as_of: datetime
    page: int
    page_size: int
    total: int
    items: list[AIUserVulnerability]


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
    users: list[AIUserUsage]
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
    users_result = await session.execute(text("""
        WITH activity AS (
            SELECT criado_por AS user_id, count(*) AS analyses,
                   count(DISTINCT tratamento_id) AS vulnerabilities,
                   sum(tokens_entrada) AS input_tokens, sum(tokens_saida) AS output_tokens,
                   sum(custo_estimado_usd) AS estimated_cost_usd,
                   0::bigint AS failures_unknown_cost, 0::bigint AS configuration_blocks
            FROM app.vulnerabilidade_analise_ia
            WHERE cliente_id = :client_id AND criado_em >= :since AND criado_em < :as_of
            GROUP BY criado_por
            UNION ALL
            SELECT usuario_id AS user_id, 0, 0, 0, 0, 0,
                   count(*) FILTER (
                       WHERE detalhes->>'cost_status' IS DISTINCT FROM 'not_requested'),
                   count(*) FILTER (WHERE detalhes->>'cost_status' = 'not_requested')
            FROM app.evento_auditoria
            WHERE cliente_id = :client_id AND acao = 'ai_analysis.failed'
              AND criado_em >= :since AND criado_em < :as_of
            GROUP BY usuario_id
        ), totals AS (
            SELECT user_id, sum(analyses) AS analyses, sum(vulnerabilities) AS vulnerabilities,
                   sum(input_tokens) AS input_tokens, sum(output_tokens) AS output_tokens,
                   sum(estimated_cost_usd) AS estimated_cost_usd,
                   sum(failures_unknown_cost) AS failures_unknown_cost,
                   sum(configuration_blocks) AS configuration_blocks
            FROM activity GROUP BY user_id
        ), members AS (
            SELECT u.id, u.nome, (u.ativo AND uc.ativo) AS active
            FROM app.usuario u JOIN app.usuario_cliente uc ON uc.usuario_id = u.id
            WHERE uc.cliente_id = :client_id
        )
        SELECT t.*, coalesce(m.nome, CASE WHEN t.user_id IS NULL THEN 'Autoria não registrada'
                       ELSE 'Usuário sem vínculo atual' END) AS name,
               coalesce(m.active, false) AS active
        FROM totals t LEFT JOIN members m ON m.id = t.user_id
        ORDER BY estimated_cost_usd DESC, (input_tokens + output_tokens) DESC,
                 name, t.user_id NULLS LAST
    """), params)
    return AIAdminSummary(
        configuration=configuration_snapshot(settings), days=int(days), period_start=since,
        as_of=as_of, usage=AIUsage(**usage), last_success_at=usage["last_success_at"],
        **failures, models=[AIModelUsage(**row) for row in models_result.mappings().all()],
        users=[AIUserUsage(**row) for row in users_result.mappings().all()],
        recent_failures=recent,
    )


@router.get("/users/{user_id}/vulnerabilities", response_model=AIUserVulnerabilities)
async def get_user_ai_vulnerabilities(
    user_id: UUID | Literal["unattributed"],
    current_user: CurrentUserDep,
    session: SessionDep,
    response: Response,
    days: Literal["7", "30", "90"] = "30",
    page: int = Query(default=1, ge=1, le=100000),
    as_of: AwareDatetime | None = None,
) -> AIUserVulnerabilities:
    require_role(current_user, frozenset({"administrador"}),
                 detail="Somente administradores podem consultar o consumo por pessoa.")
    response.headers["Cache-Control"] = "private, no-store"
    now = datetime.now(UTC)
    end = as_of or now
    if end > now:
        raise HTTPException(status_code=422, detail="O fim do período não pode estar no futuro.")
    since = end - timedelta(days=int(days))
    author = None if user_id == "unattributed" else user_id
    page_size = 20
    params = {"client_id": current_user.client_id, "user_id": author, "since": since,
              "as_of": end, "limit": page_size, "offset": (page - 1) * page_size}
    # Attribution always uses the requester, not the current workflow assignee.
    count_result = await session.execute(text("""
        SELECT count(DISTINCT tratamento_id) AS total
        FROM app.vulnerabilidade_analise_ia
        WHERE cliente_id = :client_id AND criado_em >= :since AND criado_em < :as_of
          AND criado_por IS NOT DISTINCT FROM CAST(:user_id AS uuid)
    """), params)
    total = count_result.mappings().one()["total"]
    items_result = await session.execute(text("""
        WITH grouped AS (
            SELECT tratamento_id AS workflow_id, count(*) AS analyses,
                   sum(tokens_entrada) AS input_tokens, sum(tokens_saida) AS output_tokens,
                   sum(custo_estimado_usd) AS estimated_cost_usd,
                   max(criado_em) AS last_generated_at
            FROM app.vulnerabilidade_analise_ia
            WHERE cliente_id = :client_id AND criado_em >= :since AND criado_em < :as_of
              AND criado_por IS NOT DISTINCT FROM CAST(:user_id AS uuid)
            GROUP BY tratamento_id
        ), paged AS (
            SELECT * FROM grouped
            ORDER BY estimated_cost_usd DESC, last_generated_at DESC, workflow_id
            LIMIT :limit OFFSET :offset
        )
        SELECT g.*, w.plugin_id, coalesce(p.nome, 'Vulnerabilidade sem metadados') AS title,
               h.endereco AS asset, w.protocolo AS protocol, w.porta AS port,
               latest.id AS finding_id
        FROM paged g
        LEFT JOIN app.vulnerabilidade_tratamento w
          ON w.id = g.workflow_id AND w.cliente_id = :client_id
        LEFT JOIN vm.host h ON h.id = w.host_id AND h.cliente_id = :client_id
        LEFT JOIN vm.plugin p ON p.plugin_id = w.plugin_id
        LEFT JOIN LATERAL (
            SELECT f.id FROM vm.achado f JOIN vm.scan s ON s.id = f.scan_id
            WHERE s.cliente_id = :client_id AND s.status = 'concluido'
              AND f.host_id = w.host_id AND f.plugin_id = w.plugin_id
              AND f.protocolo = w.protocolo AND f.porta = w.porta
            ORDER BY s.concluido_em DESC NULLS LAST, s.importado_em DESC, s.id DESC, f.id DESC
            LIMIT 1
        ) latest ON true
        ORDER BY g.estimated_cost_usd DESC, g.last_generated_at DESC, g.workflow_id
    """), params)
    return AIUserVulnerabilities(
        user_id=author, days=int(days), period_start=since, as_of=end,
        page=page, page_size=page_size, total=total,
        items=[AIUserVulnerability(**row) for row in items_result.mappings().all()],
    )

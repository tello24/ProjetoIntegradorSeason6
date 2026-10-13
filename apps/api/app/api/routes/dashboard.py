from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import CurrentUserDep, SessionDep
from app.services.risk import NEO_SCORE_SQL

router = APIRouter()

SeverityFilter = Literal["critical", "high", "medium", "low"]
ReliabilityLevel = Literal["healthy", "attention", "critical", "empty"]

_LATEST_SCANS_CTE = """
WITH latest_scans AS (
    SELECT ranked.*
    FROM (
        SELECT
            scan.*,
            row_number() OVER (
                PARTITION BY scan.escopo_chave
                ORDER BY
                    scan.concluido_em DESC NULLS LAST,
                    scan.importado_em DESC,
                    scan.id DESC
            ) AS scope_order
        FROM vm.scan scan
        WHERE scan.cliente_id = :client_id
          AND scan.status = 'concluido'
    ) ranked
    WHERE ranked.scope_order = 1
      AND (
          CAST(:scope_key AS text) IS NULL
          OR ranked.escopo_chave = CAST(:scope_key AS text)
      )
)
"""


class RiskAsset(BaseModel):
    id: int
    name: str
    operating_system: str | None
    credentialed: bool
    vulnerabilities: int
    critical: int
    high: int
    risk_score: int


class RiskTrendPoint(BaseModel):
    scan_id: int
    name: str
    imported_at: datetime
    assets: int
    vulnerabilities: int
    risk_score: int


class WorkflowSummary(BaseModel):
    open: int
    in_triage: int
    in_progress: int
    awaiting_validation: int
    reopened: int
    accepted_risk: int
    overdue: int
    unassigned: int
    resolved_this_week: int
    resolved_last_30_days: int
    reopened_last_30_days: int
    resolution_rate: float
    avg_resolution_days: float | None
    sla_compliance: float | None


class DashboardScopeOption(BaseModel):
    key: str
    label: str
    scanner: str
    last_scan_at: datetime
    assets: int


class DashboardFilters(BaseModel):
    scope_key: str | None
    severity: SeverityFilter | None


class DataReliability(BaseModel):
    level: ReliabilityLevel
    last_scan_name: str | None
    last_scan_at: datetime | None
    last_scan_age_days: int | None
    completed_scans: int
    failed_imports_last_30_days: int
    total_scopes: int
    stale_scopes: int
    current_assets: int
    credentialed_assets: int
    uncredentialed_assets: int
    credentialed_percentage: float


class DashboardSummary(BaseModel):
    assets: int
    open_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    resolved_this_week: int
    urgent_findings: int
    risk_score: int
    top_assets: list[RiskAsset]
    risk_trend: list[RiskTrendPoint]
    workflow: WorkflowSummary
    reliability: DataReliability
    scope_options: list[DashboardScopeOption]
    applied_filters: DashboardFilters
    source: Literal["empty", "database"] = "empty"


@router.get("/summary", response_model=DashboardSummary)
async def get_summary(
    current_user: CurrentUserDep,
    session: SessionDep,
    scope_key: str | None = Query(default=None, min_length=1, max_length=64),
    severity: SeverityFilter | None = None,
) -> DashboardSummary:
    scope_options = await _get_scope_options(
        session=session,
        client_id=current_user.client_id,
    )
    if scope_key is not None and scope_key not in {option.key for option in scope_options}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="O escopo selecionado não pertence a este ambiente.",
        )

    parameters: dict[str, object] = {
        "client_id": current_user.client_id,
        "scope_key": scope_key,
        "severity": _severity_number(severity),
    }
    overview = await _get_overview(session=session, parameters=parameters)
    workflow = await _get_workflow_summary(session=session, parameters=parameters)
    reliability = await _get_data_reliability(
        session=session,
        client_id=current_user.client_id,
        scope_key=scope_key,
    )
    return DashboardSummary(
        assets=overview["assets"],
        open_vulnerabilities=overview["open_vulnerabilities"],
        critical=overview["critical"],
        high=overview["high"],
        medium=overview["medium"],
        low=overview["low"],
        resolved_this_week=workflow.resolved_this_week,
        urgent_findings=await _get_urgent_findings(
            session=session,
            parameters=parameters,
        ),
        risk_score=overview["risk_score"],
        top_assets=await _get_top_assets(session=session, parameters=parameters),
        risk_trend=await _get_risk_trend(session=session, parameters=parameters),
        workflow=workflow,
        reliability=reliability,
        scope_options=scope_options,
        applied_filters=DashboardFilters(scope_key=scope_key, severity=severity),
        source="database" if reliability.completed_scans > 0 else "empty",
    )


async def _get_overview(
    *,
    session: AsyncSession,
    parameters: dict[str, object],
) -> dict[str, int]:
    result = await session.execute(
        text(
            _LATEST_SCANS_CTE
            + """
            SELECT
                count(DISTINCT scan_host.host_id)::integer AS assets,
                count(finding.id)::integer AS open_vulnerabilities,
                count(finding.id) FILTER (WHERE finding.severidade = 4)::integer AS critical,
                count(finding.id) FILTER (WHERE finding.severidade = 3)::integer AS high,
                count(finding.id) FILTER (WHERE finding.severidade = 2)::integer AS medium,
                count(finding.id) FILTER (WHERE finding.severidade = 1)::integer AS low,
                least(
                    100,
                    coalesce(
                        round(
                            sum(
                                CASE finding.severidade
                                    WHEN 4 THEN 10
                                    WHEN 3 THEN 5
                                    WHEN 2 THEN 2
                                    WHEN 1 THEN 1
                                    ELSE 0
                                END
                            )::numeric / greatest(count(DISTINCT scan_host.host_id), 1)
                        ),
                        0
                    )
                )::integer AS risk_score
            FROM latest_scans scan
            LEFT JOIN vm.scan_host scan_host ON scan_host.scan_id = scan.id
            LEFT JOIN vm.achado finding
              ON finding.scan_id = scan.id
             AND finding.host_id = scan_host.host_id
             AND finding.severidade > 0
             AND (
                 CAST(:severity AS integer) IS NULL
                 OR finding.severidade = CAST(:severity AS integer)
             )
            """
        ),
        parameters,
    )
    row = result.mappings().one()
    return {
        "assets": int(row["assets"] or 0),
        "open_vulnerabilities": int(row["open_vulnerabilities"] or 0),
        "critical": int(row["critical"] or 0),
        "high": int(row["high"] or 0),
        "medium": int(row["medium"] or 0),
        "low": int(row["low"] or 0),
        "risk_score": int(row["risk_score"] or 0),
    }


async def _get_urgent_findings(
    *,
    session: AsyncSession,
    parameters: dict[str, object],
) -> int:
    result = await session.execute(
        text(
            f"""
            SELECT count(*)::integer
            FROM vm.vw_achado_atual finding
            JOIN vm.scan scan ON scan.id = finding.scan_id
            WHERE finding.cliente_id = :client_id
              AND (
                  CAST(:scope_key AS text) IS NULL
                  OR scan.escopo_chave = CAST(:scope_key AS text)
              )
              AND (
                  CAST(:severity AS integer) IS NULL
                  OR finding.severidade = CAST(:severity AS integer)
              )
              AND ({NEO_SCORE_SQL}) >= 80
            """
        ),
        parameters,
    )
    return int(result.scalar_one())


async def _get_workflow_summary(
    *,
    session: AsyncSession,
    parameters: dict[str, object],
) -> WorkflowSummary:
    result = await session.execute(
        text(
            """
            WITH scoped_workflows AS (
                SELECT
                    workflow.*,
                    finding.severidade,
                    coalesce(
                        workflow.prazo,
                        workflow.primeiro_detectado_em::date + CASE finding.severidade
                            WHEN 4 THEN 7
                            WHEN 3 THEN 15
                            WHEN 2 THEN 30
                            WHEN 1 THEN 60
                            ELSE 90
                        END
                    ) AS effective_due_date
                FROM app.vulnerabilidade_tratamento workflow
                JOIN vm.vw_achado finding ON finding.id = workflow.ultimo_achado_id
                JOIN vm.scan scan ON scan.id = workflow.ultimo_scan_id
                WHERE workflow.cliente_id = :client_id
                  AND (
                      CAST(:scope_key AS text) IS NULL
                      OR scan.escopo_chave = CAST(:scope_key AS text)
                  )
                  AND (
                      CAST(:severity AS integer) IS NULL
                      OR finding.severidade = CAST(:severity AS integer)
                  )
            )
            SELECT
                count(*) FILTER (WHERE status = 'open')::integer AS abertas,
                count(*) FILTER (WHERE status = 'triage')::integer AS em_triagem,
                count(*) FILTER (WHERE status = 'in_progress')::integer AS em_correcao,
                count(*) FILTER (WHERE status = 'validation')::integer AS aguardando_validacao,
                count(*) FILTER (WHERE status = 'reopened')::integer AS reabertas,
                count(*) FILTER (WHERE status = 'accepted_risk')::integer AS risco_aceito,
                count(*) FILTER (
                    WHERE effective_due_date < current_date
                      AND status IN ('open', 'triage', 'in_progress', 'reopened')
                )::integer AS atrasadas,
                count(*) FILTER (
                    WHERE responsavel_id IS NULL
                      AND status IN ('open', 'triage', 'in_progress', 'validation', 'reopened')
                )::integer AS sem_responsavel,
                count(*) FILTER (
                    WHERE status = 'resolved'
                      AND resolvido_em >= date_trunc('week', now())
                )::integer AS resolvidas_semana,
                count(*) FILTER (
                    WHERE status = 'resolved'
                      AND resolvido_em >= now() - interval '30 days'
                )::integer AS resolvidas_30_dias,
                count(*) FILTER (
                    WHERE reaberto_em >= now() - interval '30 days'
                )::integer AS reabertas_30_dias,
                round(
                    100.0 * count(*) FILTER (WHERE status = 'resolved')
                    / greatest(count(*), 1),
                    1
                )::double precision AS taxa_resolucao,
                round(
                    avg(
                        extract(epoch FROM (resolvido_em - primeiro_detectado_em)) / 86400.0
                    ) FILTER (
                        WHERE resolvido_em IS NOT NULL
                          AND primeiro_detectado_em IS NOT NULL
                    )::numeric,
                    1
                )::double precision AS media_dias_resolucao,
                round(
                    100.0 * count(*) FILTER (
                        WHERE resolvido_em IS NOT NULL
                          AND effective_due_date IS NOT NULL
                          AND resolvido_em::date <= effective_due_date
                    )
                    / nullif(count(*) FILTER (
                        WHERE resolvido_em IS NOT NULL
                          AND effective_due_date IS NOT NULL
                    ), 0),
                    1
                )::double precision AS conformidade_sla
            FROM scoped_workflows
            """
        ),
        parameters,
    )
    row = result.mappings().one()
    return WorkflowSummary(
        open=row["abertas"],
        in_triage=row["em_triagem"],
        in_progress=row["em_correcao"],
        awaiting_validation=row["aguardando_validacao"],
        reopened=row["reabertas"],
        accepted_risk=row["risco_aceito"],
        overdue=row["atrasadas"],
        unassigned=row["sem_responsavel"],
        resolved_this_week=row["resolvidas_semana"],
        resolved_last_30_days=row["resolvidas_30_dias"],
        reopened_last_30_days=row["reabertas_30_dias"],
        resolution_rate=row["taxa_resolucao"],
        avg_resolution_days=row["media_dias_resolucao"],
        sla_compliance=row["conformidade_sla"],
    )


async def _get_top_assets(
    *,
    session: AsyncSession,
    parameters: dict[str, object],
) -> list[RiskAsset]:
    result = await session.execute(
        text(
            _LATEST_SCANS_CTE
            + """
            SELECT
                host.id AS host_id,
                coalesce(max(scan_host.fqdn), host.endereco) AS nome,
                max(scan_host.sistema_operacional) AS sistema_operacional,
                bool_or(scan_host.credenciado) AS credenciado,
                count(finding.id)::integer AS total,
                count(finding.id) FILTER (WHERE finding.severidade = 4)::integer AS criticas,
                count(finding.id) FILTER (WHERE finding.severidade = 3)::integer AS altas,
                coalesce(sum(
                    CASE finding.severidade
                        WHEN 4 THEN 10
                        WHEN 3 THEN 5
                        WHEN 2 THEN 2
                        WHEN 1 THEN 1
                        ELSE 0
                    END
                ), 0)::integer AS risco
            FROM latest_scans scan
            JOIN vm.scan_host scan_host ON scan_host.scan_id = scan.id
            JOIN vm.host host ON host.id = scan_host.host_id
            LEFT JOIN vm.achado finding
              ON finding.scan_id = scan.id
             AND finding.host_id = host.id
             AND finding.severidade > 0
             AND (
                 CAST(:severity AS integer) IS NULL
                 OR finding.severidade = CAST(:severity AS integer)
             )
            GROUP BY host.id
            HAVING count(finding.id) > 0
            ORDER BY risco DESC, criticas DESC, altas DESC, nome
            LIMIT 5
            """
        ),
        parameters,
    )
    return [
        RiskAsset(
            id=row["host_id"],
            name=row["nome"],
            operating_system=row["sistema_operacional"],
            credentialed=row["credenciado"],
            vulnerabilities=row["total"],
            critical=row["criticas"],
            high=row["altas"],
            risk_score=row["risco"],
        )
        for row in result.mappings().all()
    ]


async def _get_risk_trend(
    *,
    session: AsyncSession,
    parameters: dict[str, object],
) -> list[RiskTrendPoint]:
    result = await session.execute(
        text(
            """
            SELECT
                scan.id,
                scan.nome,
                scan.importado_em,
                count(DISTINCT scan_host.host_id)::integer AS ativos,
                count(finding.id)::integer AS vulnerabilidades,
                least(
                    100,
                    coalesce(
                        round(
                            sum(
                                CASE finding.severidade
                                    WHEN 4 THEN 10
                                    WHEN 3 THEN 5
                                    WHEN 2 THEN 2
                                    WHEN 1 THEN 1
                                    ELSE 0
                                END
                            )::numeric / greatest(count(DISTINCT scan_host.host_id), 1)
                        ),
                        0
                    )
                )::integer AS risco
            FROM vm.scan scan
            LEFT JOIN vm.scan_host scan_host ON scan_host.scan_id = scan.id
            LEFT JOIN vm.achado finding
              ON finding.scan_id = scan.id
             AND finding.host_id = scan_host.host_id
             AND finding.severidade > 0
             AND (
                 CAST(:severity AS integer) IS NULL
                 OR finding.severidade = CAST(:severity AS integer)
             )
            WHERE scan.cliente_id = :client_id
              AND scan.status = 'concluido'
              AND (
                  CAST(:scope_key AS text) IS NULL
                  OR scan.escopo_chave = CAST(:scope_key AS text)
              )
            GROUP BY scan.id
            ORDER BY scan.importado_em DESC, scan.id DESC
            LIMIT 10
            """
        ),
        parameters,
    )
    rows = list(reversed(result.mappings().all()))
    return [
        RiskTrendPoint(
            scan_id=row["id"],
            name=row["nome"],
            imported_at=row["importado_em"],
            assets=row["ativos"],
            vulnerabilities=row["vulnerabilidades"],
            risk_score=row["risco"],
        )
        for row in rows
    ]


async def _get_scope_options(
    *,
    session: AsyncSession,
    client_id: int,
) -> list[DashboardScopeOption]:
    result = await session.execute(
        text(
            """
            SELECT
                latest.escopo_chave,
                latest.nome,
                latest.scanner,
                latest.importado_em,
                count(DISTINCT scan_host.host_id)::integer AS assets
            FROM vm.vw_scan_mais_recente latest
            LEFT JOIN vm.scan_host scan_host ON scan_host.scan_id = latest.id
            WHERE latest.cliente_id = :client_id
            GROUP BY
                latest.id,
                latest.escopo_chave,
                latest.nome,
                latest.scanner,
                latest.importado_em
            ORDER BY latest.importado_em DESC, latest.id DESC
            """
        ),
        {"client_id": client_id},
    )
    return [
        DashboardScopeOption(
            key=row["escopo_chave"],
            label=row["nome"],
            scanner=row["scanner"],
            last_scan_at=row["importado_em"],
            assets=row["assets"],
        )
        for row in result.mappings().all()
    ]


async def _get_data_reliability(
    *,
    session: AsyncSession,
    client_id: int,
    scope_key: str | None,
) -> DataReliability:
    result = await session.execute(
        text(
            _LATEST_SCANS_CTE
            + """
            SELECT
                (SELECT count(*)::integer FROM latest_scans) AS total_scopes,
                (SELECT count(*)::integer FROM vm.scan historical
                 WHERE historical.cliente_id = :client_id
                   AND historical.status = 'concluido'
                   AND (
                       CAST(:scope_key AS text) IS NULL
                       OR historical.escopo_chave = CAST(:scope_key AS text)
                   )) AS completed_scans,
                (SELECT latest.nome FROM latest_scans latest
                 ORDER BY latest.importado_em DESC, latest.id DESC LIMIT 1) AS last_scan_name,
                (SELECT latest.importado_em FROM latest_scans latest
                 ORDER BY latest.importado_em DESC, latest.id DESC LIMIT 1) AS last_scan_at,
                (SELECT greatest(
                    floor(extract(epoch FROM (now() - latest.importado_em)) / 86400),
                    0
                 )::integer FROM latest_scans latest
                 ORDER BY latest.importado_em DESC, latest.id DESC LIMIT 1) AS last_scan_age_days,
                (SELECT count(*)::integer FROM latest_scans latest
                 WHERE latest.importado_em < now() - interval '30 days') AS stale_scopes,
                count(DISTINCT scan_host.host_id)::integer AS current_assets,
                count(DISTINCT scan_host.host_id) FILTER (
                    WHERE scan_host.credenciado
                )::integer AS credentialed_assets,
                (SELECT count(*)::integer FROM vm.importacao imported
                 WHERE imported.cliente_id = :client_id
                   AND imported.status = 'falhou'
                   AND imported.iniciado_em >= now() - interval '30 days'
                ) AS failed_imports
            FROM latest_scans latest
            LEFT JOIN vm.scan_host scan_host ON scan_host.scan_id = latest.id
            """
        ),
        {"client_id": client_id, "scope_key": scope_key},
    )
    row = result.mappings().one()
    current_assets = int(row["current_assets"] or 0)
    credentialed_assets = int(row["credentialed_assets"] or 0)
    credentialed_percentage = (
        round(credentialed_assets / current_assets * 100, 1) if current_assets else 0.0
    )
    completed_scans = int(row["completed_scans"] or 0)
    failed_imports = int(row["failed_imports"] or 0)
    total_scopes = int(row["total_scopes"] or 0)
    stale_scopes = int(row["stale_scopes"] or 0)
    age_days = (
        int(row["last_scan_age_days"]) if row["last_scan_age_days"] is not None else None
    )
    return DataReliability(
        level=_reliability_level(
            completed_scans=completed_scans,
            age_days=age_days,
            credentialed_percentage=credentialed_percentage,
            failed_imports=failed_imports,
            stale_scopes=stale_scopes,
        ),
        last_scan_name=row["last_scan_name"],
        last_scan_at=row["last_scan_at"],
        last_scan_age_days=age_days,
        completed_scans=completed_scans,
        failed_imports_last_30_days=failed_imports,
        total_scopes=total_scopes,
        stale_scopes=stale_scopes,
        current_assets=current_assets,
        credentialed_assets=credentialed_assets,
        uncredentialed_assets=max(current_assets - credentialed_assets, 0),
        credentialed_percentage=credentialed_percentage,
    )


def _severity_number(severity: SeverityFilter | None) -> int | None:
    if severity is None:
        return None
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}[severity]


def _reliability_level(
    *,
    completed_scans: int,
    age_days: int | None,
    credentialed_percentage: float,
    failed_imports: int,
    stale_scopes: int,
) -> ReliabilityLevel:
    if completed_scans == 0 or age_days is None:
        return "empty"
    if (
        age_days <= 7
        and credentialed_percentage >= 80
        and failed_imports == 0
        and stale_scopes == 0
    ):
        return "healthy"
    if age_days <= 30 and credentialed_percentage >= 50:
        return "attention"
    return "critical"

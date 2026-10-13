import csv
import io
from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import CurrentUserDep, SessionDep

router = APIRouter()

SeverityFilter = Literal["critical", "high", "medium", "low"]

SEVERITY_NUMBER: dict[SeverityFilter, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


class MonthlyReportPoint(BaseModel):
    month: date
    scans: int
    new_findings: int
    resolved_findings: int
    reopened_findings: int
    net_change: int
    backlog: int


class MonthlyReportSummary(BaseModel):
    period_start: date
    period_end: date
    scans: int
    months_with_scans: int
    new_findings: int
    resolved_findings: int
    reopened_findings: int
    net_change: int
    current_backlog: int
    correction_ratio: float | None


class MonthlyReportResponse(BaseModel):
    months: int
    severity: SeverityFilter | None
    summary: MonthlyReportSummary
    timeline: list[MonthlyReportPoint]


@router.get("/monthly", response_model=MonthlyReportResponse)
async def get_monthly_report(
    current_user: CurrentUserDep,
    session: SessionDep,
    months: Annotated[int, Query(ge=3, le=24)] = 12,
    severity: SeverityFilter | None = None,
) -> MonthlyReportResponse:
    return await _build_monthly_report(
        session=session,
        client_id=current_user.client_id,
        months=months,
        severity=severity,
    )


@router.get("/monthly.csv")
async def export_monthly_report(
    current_user: CurrentUserDep,
    session: SessionDep,
    months: Annotated[int, Query(ge=3, le=24)] = 12,
    severity: SeverityFilter | None = None,
) -> Response:
    report = await _build_monthly_report(
        session=session,
        client_id=current_user.client_id,
        months=months,
        severity=severity,
    )
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=";")
    writer.writerow(
        [
            "Mês",
            "Scans",
            "Novas",
            "Corrigidas",
            "Reabertas",
            "Saldo líquido",
            "Backlog ao final do mês",
        ]
    )
    for point in report.timeline:
        writer.writerow(
            [
                point.month.strftime("%Y-%m"),
                point.scans,
                point.new_findings,
                point.resolved_findings,
                point.reopened_findings,
                point.net_change,
                point.backlog,
            ]
        )

    filename = f"wvm-evolucao-{report.summary.period_end:%Y-%m-%d}.csv"
    return Response(
        content="\ufeff" + stream.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def _build_monthly_report(
    *,
    session: AsyncSession,
    client_id: int,
    months: int,
    severity: SeverityFilter | None,
) -> MonthlyReportResponse:
    result = await session.execute(
        text(
            """
            WITH month_series AS (
                SELECT generate_series(
                    date_trunc('month', now()) - make_interval(months => :months - 1),
                    date_trunc('month', now()),
                    interval '1 month'
                ) AS month_start
            ),
            workflow_base AS (
                SELECT
                    workflow.id,
                    workflow.primeiro_detectado_em
                FROM app.vulnerabilidade_tratamento workflow
                JOIN vm.achado latest_finding
                  ON latest_finding.id = workflow.ultimo_achado_id
                WHERE workflow.cliente_id = :client_id
                  AND workflow.primeiro_detectado_em IS NOT NULL
                  AND (
                      CAST(:severity AS integer) IS NULL
                      OR latest_finding.severidade = CAST(:severity AS integer)
                  )
            ),
            scan_counts AS (
                SELECT
                    date_trunc(
                        'month',
                        coalesce(scan.concluido_em, scan.importado_em)
                    ) AS month_start,
                    count(*)::integer AS total
                FROM vm.scan scan
                WHERE scan.cliente_id = :client_id
                  AND scan.status = 'concluido'
                GROUP BY 1
            ),
            lifecycle_events AS (
                SELECT
                    workflow.id AS workflow_id,
                    audit.acao AS action,
                    coalesce(
                        scan.concluido_em,
                        scan.importado_em,
                        audit.criado_em
                    ) AS occurred_at
                FROM app.evento_auditoria audit
                JOIN workflow_base workflow
                  ON workflow.id::text = audit.recurso_id
                LEFT JOIN vm.scan scan
                  ON scan.id::text = audit.detalhes ->> 'scan_id'
                 AND scan.cliente_id = :client_id
                WHERE audit.cliente_id = :client_id
                  AND audit.recurso = 'vulnerability_workflow'
                  AND audit.acao IN (
                      'workflow.auto_resolved',
                      'workflow.auto_reopened'
                  )
            )
            SELECT
                series.month_start::date AS month,
                coalesce(scans.total, 0)::integer AS scans,
                (
                    SELECT count(*)::integer
                    FROM workflow_base workflow
                    WHERE workflow.primeiro_detectado_em >= series.month_start
                      AND workflow.primeiro_detectado_em < series.month_start + interval '1 month'
                ) AS new_findings,
                (
                    SELECT count(*)::integer
                    FROM lifecycle_events event
                    WHERE event.action = 'workflow.auto_resolved'
                      AND event.occurred_at >= series.month_start
                      AND event.occurred_at < series.month_start + interval '1 month'
                ) AS resolved_findings,
                (
                    SELECT count(*)::integer
                    FROM lifecycle_events event
                    WHERE event.action = 'workflow.auto_reopened'
                      AND event.occurred_at >= series.month_start
                      AND event.occurred_at < series.month_start + interval '1 month'
                ) AS reopened_findings,
                (
                    SELECT count(*)::integer
                    FROM workflow_base workflow
                    WHERE workflow.primeiro_detectado_em < series.month_start + interval '1 month'
                      AND coalesce(
                          (
                              SELECT event.action
                              FROM lifecycle_events event
                              WHERE event.workflow_id = workflow.id
                                AND event.occurred_at < series.month_start + interval '1 month'
                              ORDER BY event.occurred_at DESC, event.action DESC
                              LIMIT 1
                          ),
                          'active'
                      ) <> 'workflow.auto_resolved'
                ) AS backlog
            FROM month_series series
            LEFT JOIN scan_counts scans
              ON scans.month_start = series.month_start
            ORDER BY series.month_start
            """
        ),
        {
            "client_id": client_id,
            "months": months,
            "severity": SEVERITY_NUMBER.get(severity) if severity else None,
        },
    )
    points = [
        MonthlyReportPoint(
            month=row["month"],
            scans=row["scans"],
            new_findings=row["new_findings"],
            resolved_findings=row["resolved_findings"],
            reopened_findings=row["reopened_findings"],
            net_change=(
                row["new_findings"] + row["reopened_findings"] - row["resolved_findings"]
            ),
            backlog=row["backlog"],
        )
        for row in result.mappings().all()
    ]

    total_new = sum(point.new_findings for point in points)
    total_resolved = sum(point.resolved_findings for point in points)
    total_reopened = sum(point.reopened_findings for point in points)
    total_entered = total_new + total_reopened
    correction_ratio = (
        round(100 * total_resolved / total_entered, 1) if total_entered > 0 else None
    )
    today = date.today()
    return MonthlyReportResponse(
        months=months,
        severity=severity,
        summary=MonthlyReportSummary(
            period_start=points[0].month,
            period_end=today,
            scans=sum(point.scans for point in points),
            months_with_scans=sum(1 for point in points if point.scans > 0),
            new_findings=total_new,
            resolved_findings=total_resolved,
            reopened_findings=total_reopened,
            net_change=total_entered - total_resolved,
            current_backlog=points[-1].backlog,
            correction_ratio=correction_ratio,
        ),
        timeline=points,
    )

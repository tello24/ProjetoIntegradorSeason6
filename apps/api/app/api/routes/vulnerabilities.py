import json
from collections.abc import Mapping
from datetime import date, datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from fastapi import status as http_status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import (
    AI_GENERATION_ROLES,
    OPERATIONAL_ROLES,
    CurrentUser,
    CurrentUserDep,
    SessionDep,
    require_role,
)
from app.core.config import settings
from app.services.remediation import (
    RemediationContext,
    RemediationDraft,
    RemediationPlan,
    generate_remediation_plan,
    remediation_input_signature,
)
from app.services.risk import (
    NEO_SCORE_SQL,
    Priority,
    calculate_neo_score,
    priority_for_score,
)

router = APIRouter()

Severity = Literal["critical", "high", "medium", "low", "info"]
WorkflowStatus = Literal[
    "open",
    "triage",
    "in_progress",
    "validation",
    "accepted_risk",
    "resolved",
    "reopened",
]
EditableWorkflowStatus = Literal[
    "open",
    "triage",
    "in_progress",
    "validation",
    "accepted_risk",
    "reopened",
]
LifecycleView = Literal["active", "resolved", "accepted_risk", "reopened", "all"]
QueueFocus = Literal[
    "all",
    "act_now",
    "overdue",
    "due_soon",
    "unassigned",
    "reopened",
    "quick_wins",
]
QueueReason = Literal[
    "overdue",
    "reopened",
    "act_now",
    "unassigned",
    "due_soon",
    "prioritized",
]
DueSource = Literal["manual", "sla"]


class VulnerabilityListItem(BaseModel):
    id: int
    severity: Severity
    title: str
    asset: str
    status: WorkflowStatus
    assignee_name: str | None
    due_date: date | None
    cvss: float | None
    neo_score: int
    priority: Priority
    discovered_at: datetime
    last_observed_at: datetime
    resolved_at: datetime | None
    reopened_at: datetime | None
    cves: list[str]


class VulnerabilityListSummary(BaseModel):
    active: int
    resolved: int
    accepted_risk: int
    reopened: int
    total: int


class VulnerabilityListResponse(BaseModel):
    items: list[VulnerabilityListItem]
    total: int
    summary: VulnerabilityListSummary


class RemediationQueueItem(BaseModel):
    id: int
    workflow_id: UUID
    plugin_id: int
    severity: Severity
    title: str
    asset: str
    status: WorkflowStatus
    assignee_id: UUID | None
    assignee_name: str | None
    due_date: date | None
    effective_due_date: date
    due_source: DueSource
    sla_days: int
    age_days: int
    neo_score: int
    priority: Priority
    reason: QueueReason
    occurrence_count: int
    cves: list[str]
    first_detected_at: datetime
    last_detected_at: datetime


class RemediationQueueSummary(BaseModel):
    total_active: int
    act_now: int
    overdue: int
    due_soon: int
    unassigned: int
    reopened: int
    quick_wins: int


class RemediationQueueResponse(BaseModel):
    items: list[RemediationQueueItem]
    total: int
    limit: int
    offset: int
    can_edit: bool
    can_accept_risk: bool
    summary: RemediationQueueSummary


class VulnerabilityAsset(BaseModel):
    id: int
    address: str
    fqdn: str | None
    operating_system: str | None
    credentialed: bool


class NeoScoreBreakdown(BaseModel):
    version: str = "1.0"
    total: int
    priority: Priority
    cvss_component: float
    epss_component: float
    exploit_component: float
    vpr_component: float
    factors: list[str]


class WorkflowAssignee(BaseModel):
    id: UUID
    name: str
    email: str


class WorkflowState(BaseModel):
    id: UUID | None
    status: WorkflowStatus
    assignee: WorkflowAssignee | None
    due_date: date | None
    note: str | None
    updated_at: datetime | None
    first_detected_at: datetime | None
    last_detected_at: datetime | None
    resolved_at: datetime | None
    reopened_at: datetime | None
    resolution_count: int
    reopen_count: int
    last_scan_id: int | None
    can_edit: bool
    can_accept_risk: bool


class WorkflowUpdate(BaseModel):
    status: EditableWorkflowStatus
    assignee_id: UUID | None = None
    due_date: date | None = None
    note: str | None = Field(default=None, max_length=2000)


class WorkflowHistoryItem(BaseModel):
    id: int
    action: str
    user_name: str | None
    details: dict[str, object]
    created_at: datetime


class WorkflowHistoryResponse(BaseModel):
    items: list[WorkflowHistoryItem]


class RemediationHistoryResponse(BaseModel):
    items: list[RemediationPlan]


class VulnerabilityDetail(BaseModel):
    id: int
    title: str
    severity: Severity
    status: WorkflowStatus
    family: str | None
    synopsis: str | None
    description: str | None
    solution: str | None
    plugin_output: str | None
    cves: list[str]
    asset: VulnerabilityAsset
    protocol: str
    port: int
    service: str | None
    risk_factor: str | None
    cvss2: float | None
    cvss3: float | None
    cvss4: float | None
    cvss3_vector: str | None
    vpr: float | None
    epss: float | None
    exploitable: bool
    exploit_maturity: str | None
    discovered_at: datetime
    observed_at: datetime
    neo_score: NeoScoreBreakdown
    workflow: WorkflowState
    can_generate_ai: bool


_REMEDIATION_QUEUE_CTE = f"""
WITH queue_base AS (
    SELECT
        finding.id,
        workflow.id AS workflow_id,
        finding.plugin_id,
        finding.severidade,
        finding.titulo,
        coalesce(finding.fqdn, finding.endereco) AS ativo,
        finding.cves,
        workflow.status,
        workflow.responsavel_id,
        assignee.nome AS responsavel_nome,
        workflow.prazo,
        coalesce(
            workflow.primeiro_detectado_em,
            finding.descoberto_em,
            finding.observado_em,
            now()
        ) AS primeiro_detectado_em,
        coalesce(
            workflow.ultimo_detectado_em,
            finding.observado_em,
            finding.descoberto_em,
            now()
        ) AS ultimo_detectado_em,
        count(*) OVER (PARTITION BY finding.plugin_id)::integer AS ocorrencias,
        {NEO_SCORE_SQL} AS neo_score
    FROM app.vulnerabilidade_tratamento workflow
    JOIN vm.vw_achado finding ON finding.id = workflow.ultimo_achado_id
    LEFT JOIN app.usuario assignee ON assignee.id = workflow.responsavel_id
    WHERE workflow.cliente_id = :client_id
      AND workflow.status IN ('open', 'triage', 'in_progress', 'validation', 'reopened')
),
queue_enriched AS (
    SELECT
        queue_base.*,
        CASE severidade
            WHEN 4 THEN 7
            WHEN 3 THEN 15
            WHEN 2 THEN 30
            WHEN 1 THEN 60
            ELSE 90
        END::integer AS sla_dias,
        coalesce(
            prazo,
            primeiro_detectado_em::date + CASE severidade
                WHEN 4 THEN 7
                WHEN 3 THEN 15
                WHEN 2 THEN 30
                WHEN 1 THEN 60
                ELSE 90
            END
        ) AS prazo_efetivo,
        CASE WHEN prazo IS NULL THEN 'sla' ELSE 'manual' END AS origem_prazo,
        greatest(current_date - primeiro_detectado_em::date, 0)::integer AS idade_dias
    FROM queue_base
),
queue_ready AS (
    SELECT
        queue_enriched.*,
        CASE
            WHEN prazo_efetivo < current_date THEN 'overdue'
            WHEN status = 'reopened' THEN 'reopened'
            WHEN neo_score >= 80 THEN 'act_now'
            WHEN responsavel_id IS NULL THEN 'unassigned'
            WHEN prazo_efetivo <= current_date + 7 THEN 'due_soon'
            ELSE 'prioritized'
        END AS motivo_fila
    FROM queue_enriched
)
"""


@router.get("", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    current_user: CurrentUserDep,
    session: SessionDep,
    search: str | None = Query(default=None, max_length=200),
    severity: Severity | None = None,
    status: WorkflowStatus | None = None,
    view: LifecycleView = "active",
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> VulnerabilityListResponse:
    severity_value = _severity_to_number(severity)
    normalized_search = f"%{search.strip()}%" if search and search.strip() else None
    result = await session.execute(
        text(
            f"""
            WITH prioritized AS (
            SELECT
                finding.id,
                finding.severidade,
                finding.titulo,
                coalesce(finding.fqdn, finding.endereco) AS ativo,
                coalesce(finding.cvss4, finding.cvss3, finding.cvss2) AS cvss,
                coalesce(
                    workflow.primeiro_detectado_em,
                    finding.descoberto_em,
                    finding.observado_em,
                    now()
                ) AS descoberto_em,
                coalesce(
                    workflow.ultimo_detectado_em,
                    finding.observado_em,
                    finding.descoberto_em,
                    now()
                ) AS observado_em,
                finding.cves,
                workflow.status AS workflow_status,
                assignee.nome AS responsavel_nome,
                workflow.prazo,
                workflow.resolvido_em,
                workflow.reaberto_em,
                {NEO_SCORE_SQL} AS neo_score
            FROM app.vulnerabilidade_tratamento workflow
            JOIN vm.vw_achado finding ON finding.id = workflow.ultimo_achado_id
            LEFT JOIN app.usuario assignee ON assignee.id = workflow.responsavel_id
            WHERE workflow.cliente_id = :client_id
              AND (
                  CAST(:view_filter AS text) = 'all'
                  OR (
                      CAST(:view_filter AS text) = 'active'
                      AND workflow.status IN (
                          'open', 'triage', 'in_progress', 'validation', 'reopened'
                      )
                  )
                  OR (
                      CAST(:view_filter AS text) = 'resolved'
                      AND workflow.status = 'resolved'
                  )
                  OR (
                      CAST(:view_filter AS text) = 'accepted_risk'
                      AND workflow.status = 'accepted_risk'
                  )
                  OR (
                      CAST(:view_filter AS text) = 'reopened'
                      AND workflow.status = 'reopened'
                  )
              )
              AND (
                  CAST(:severity AS integer) IS NULL
                  OR finding.severidade = CAST(:severity AS integer)
              )
              AND (
                  CAST(:status_filter AS text) IS NULL
                  OR workflow.status = CAST(:status_filter AS text)
              )
              AND (
                  CAST(:search AS text) IS NULL
                  OR finding.titulo ILIKE CAST(:search AS text)
                  OR finding.endereco ILIKE CAST(:search AS text)
                  OR coalesce(finding.fqdn, '') ILIKE CAST(:search AS text)
                  OR array_to_string(finding.cves, ',') ILIKE CAST(:search AS text)
              )
            )
            SELECT *, count(*) OVER () AS total
            FROM prioritized
            ORDER BY
                neo_score DESC,
                severidade DESC,
                coalesce(cvss, 0) DESC,
                coalesce(resolvido_em, reaberto_em, observado_em) DESC,
                id
            LIMIT :limit OFFSET :offset
            """
        ),
        {
            "client_id": current_user.client_id,
            "severity": severity_value,
            "status_filter": status,
            "view_filter": view,
            "search": normalized_search,
            "limit": limit,
            "offset": offset,
        },
    )
    rows = result.mappings().all()
    items = [
        VulnerabilityListItem(
            id=row["id"],
            severity=_number_to_severity(row["severidade"]),
            title=row["titulo"],
            asset=row["ativo"],
            status=row["workflow_status"],
            assignee_name=row["responsavel_nome"],
            due_date=row["prazo"],
            cvss=float(row["cvss"]) if row["cvss"] is not None else None,
            neo_score=row["neo_score"],
            priority=priority_for_score(row["neo_score"]),
            discovered_at=row["descoberto_em"],
            last_observed_at=row["observado_em"],
            resolved_at=row["resolvido_em"],
            reopened_at=row["reaberto_em"],
            cves=list(row["cves"] or []),
        )
        for row in rows
    ]
    total = int(rows[0]["total"]) if rows else 0
    summary_result = await session.execute(
        text(
            """
            SELECT
                count(*) FILTER (
                    WHERE status IN ('open', 'triage', 'in_progress', 'validation', 'reopened')
                )::integer AS active,
                count(*) FILTER (WHERE status = 'resolved')::integer AS resolved,
                count(*) FILTER (WHERE status = 'accepted_risk')::integer AS accepted_risk,
                count(*) FILTER (WHERE status = 'reopened')::integer AS reopened,
                count(*)::integer AS total
            FROM app.vulnerabilidade_tratamento
            WHERE cliente_id = :client_id
              AND ultimo_achado_id IS NOT NULL
            """
        ),
        {"client_id": current_user.client_id},
    )
    summary = summary_result.mappings().one()
    return VulnerabilityListResponse(
        items=items,
        total=total,
        summary=VulnerabilityListSummary(**summary),
    )


@router.get("/assignees", response_model=list[WorkflowAssignee])
async def list_workflow_assignees(
    current_user: CurrentUserDep,
    session: SessionDep,
) -> list[WorkflowAssignee]:
    result = await session.execute(
        text(
            """
            SELECT u.id, u.nome, u.email
            FROM app.usuario u
            JOIN app.usuario_cliente membership ON membership.usuario_id = u.id
            WHERE membership.cliente_id = :client_id
              AND membership.ativo = true
              AND membership.papel IN ('administrador', 'gestor', 'analista')
              AND u.ativo = true
            ORDER BY u.nome, u.email
            """
        ),
        {"client_id": current_user.client_id},
    )
    return [
        WorkflowAssignee(id=row["id"], name=row["nome"], email=row["email"])
        for row in result.mappings().all()
    ]


@router.get("/queue", response_model=RemediationQueueResponse)
async def get_remediation_queue(
    current_user: CurrentUserDep,
    session: SessionDep,
    search: str | None = Query(default=None, max_length=200),
    focus: QueueFocus = "all",
    severity: Severity | None = None,
    status: WorkflowStatus | None = None,
    assignee_id: UUID | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> RemediationQueueResponse:
    normalized_search = f"%{search.strip()}%" if search and search.strip() else None
    severity_value = _severity_to_number(severity)
    parameters = {
        "client_id": current_user.client_id,
        "search": normalized_search,
        "focus": focus,
        "severity": severity_value,
        "status": status,
        "assignee_id": assignee_id,
        "limit": limit,
        "offset": offset,
    }

    summary_result = await session.execute(
        text(
            _REMEDIATION_QUEUE_CTE
            + """
            SELECT
                count(*)::integer AS total_active,
                count(*) FILTER (WHERE neo_score >= 80)::integer AS act_now,
                count(*) FILTER (WHERE prazo_efetivo < current_date)::integer AS overdue,
                count(*) FILTER (
                    WHERE prazo_efetivo BETWEEN current_date AND current_date + 7
                )::integer AS due_soon,
                count(*) FILTER (WHERE responsavel_id IS NULL)::integer AS unassigned,
                count(*) FILTER (WHERE status = 'reopened')::integer AS reopened,
                count(*) FILTER (WHERE ocorrencias >= 2)::integer AS quick_wins
            FROM queue_ready
            """
        ),
        {"client_id": current_user.client_id},
    )
    summary = summary_result.mappings().one()

    queue_result = await session.execute(
        text(
            _REMEDIATION_QUEUE_CTE
            + """
            SELECT *, count(*) OVER ()::integer AS filtered_total
            FROM queue_ready
            WHERE (
                CAST(:search AS text) IS NULL
                OR titulo ILIKE CAST(:search AS text)
                OR ativo ILIKE CAST(:search AS text)
                OR array_to_string(cves, ',') ILIKE CAST(:search AS text)
            )
              AND (
                CAST(:severity AS integer) IS NULL
                OR severidade = CAST(:severity AS integer)
              )
              AND (
                CAST(:status AS text) IS NULL
                OR status = CAST(:status AS text)
              )
              AND (
                CAST(:assignee_id AS uuid) IS NULL
                OR responsavel_id = CAST(:assignee_id AS uuid)
              )
              AND (
                CAST(:focus AS text) = 'all'
                OR (CAST(:focus AS text) = 'act_now' AND neo_score >= 80)
                OR (CAST(:focus AS text) = 'overdue' AND prazo_efetivo < current_date)
                OR (
                    CAST(:focus AS text) = 'due_soon'
                    AND prazo_efetivo BETWEEN current_date AND current_date + 7
                )
                OR (CAST(:focus AS text) = 'unassigned' AND responsavel_id IS NULL)
                OR (CAST(:focus AS text) = 'reopened' AND status = 'reopened')
                OR (CAST(:focus AS text) = 'quick_wins' AND ocorrencias >= 2)
              )
            ORDER BY
                CASE motivo_fila
                    WHEN 'overdue' THEN 1
                    WHEN 'reopened' THEN 2
                    WHEN 'act_now' THEN 3
                    WHEN 'unassigned' THEN 4
                    WHEN 'due_soon' THEN 5
                    ELSE 6
                END,
                neo_score DESC,
                prazo_efetivo,
                idade_dias DESC,
                id
            LIMIT :limit OFFSET :offset
            """
        ),
        parameters,
    )
    rows = queue_result.mappings().all()
    items = [
        RemediationQueueItem(
            id=row["id"],
            workflow_id=row["workflow_id"],
            plugin_id=row["plugin_id"],
            severity=_number_to_severity(row["severidade"]),
            title=row["titulo"],
            asset=row["ativo"],
            status=row["status"],
            assignee_id=row["responsavel_id"],
            assignee_name=row["responsavel_nome"],
            due_date=row["prazo"],
            effective_due_date=row["prazo_efetivo"],
            due_source=row["origem_prazo"],
            sla_days=row["sla_dias"],
            age_days=row["idade_dias"],
            neo_score=row["neo_score"],
            priority=priority_for_score(row["neo_score"]),
            reason=row["motivo_fila"],
            occurrence_count=row["ocorrencias"],
            cves=list(row["cves"] or []),
            first_detected_at=row["primeiro_detectado_em"],
            last_detected_at=row["ultimo_detectado_em"],
        )
        for row in rows
    ]
    return RemediationQueueResponse(
        items=items,
        total=int(rows[0]["filtered_total"]) if rows else 0,
        limit=limit,
        offset=offset,
        can_edit=current_user.role in OPERATIONAL_ROLES,
        can_accept_risk=current_user.role in {"administrador", "gestor"},
        summary=RemediationQueueSummary(**summary),
    )


@router.patch("/{finding_id}/workflow", response_model=WorkflowState)
async def update_vulnerability_workflow(
    finding_id: int,
    update: WorkflowUpdate,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> WorkflowState:
    require_role(current_user, OPERATIONAL_ROLES)
    if update.status == "accepted_risk" and current_user.role not in {
        "administrador",
        "gestor",
    }:
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Somente administradores e gestores podem aceitar formalmente um risco.",
        )

    finding = await _get_finding_identity(
        session=session,
        finding_id=finding_id,
        client_id=current_user.client_id,
    )
    if finding is None:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail="Vulnerabilidade não encontrada.",
        )

    if update.assignee_id is not None:
        assignee_result = await session.execute(
            text(
                """
                SELECT 1
                FROM app.usuario u
                JOIN app.usuario_cliente membership ON membership.usuario_id = u.id
                WHERE u.id = :assignee_id
                  AND membership.cliente_id = :client_id
                  AND membership.ativo = true
                  AND membership.papel IN ('administrador', 'gestor', 'analista')
                  AND u.ativo = true
                """
            ),
            {
                "assignee_id": update.assignee_id,
                "client_id": current_user.client_id,
            },
        )
        if assignee_result.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="O responsável selecionado não pertence a este ambiente.",
            )

    previous_result = await session.execute(
        text(
            """
            SELECT id, status, responsavel_id, prazo, observacao_atual
            FROM app.vulnerabilidade_tratamento
            WHERE cliente_id = :client_id
              AND host_id = :host_id
              AND plugin_id = :plugin_id
              AND protocolo = :protocol
              AND porta = :port
            """
        ),
        finding,
    )
    previous = previous_result.mappings().one_or_none()
    if previous is not None and previous["status"] == "resolved":
        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT,
            detail=(
                "A vulnerabilidade já foi resolvida por evidência de scan. "
                "Ela será reaberta automaticamente se voltar a aparecer."
            ),
        )
    note = update.note.strip() if update.note and update.note.strip() else None

    workflow_result = await session.execute(
        text(
            """
            INSERT INTO app.vulnerabilidade_tratamento (
                cliente_id,
                host_id,
                plugin_id,
                protocolo,
                porta,
                status,
                responsavel_id,
                prazo,
                observacao_atual,
                criado_por,
                atualizado_por
            )
            VALUES (
                :client_id,
                :host_id,
                :plugin_id,
                :protocol,
                :port,
                :workflow_status,
                CAST(:assignee_id AS uuid),
                CAST(:due_date AS date),
                CAST(:note AS text),
                :user_id,
                :user_id
            )
            ON CONFLICT (cliente_id, host_id, plugin_id, protocolo, porta)
            DO UPDATE SET
                status = EXCLUDED.status,
                responsavel_id = EXCLUDED.responsavel_id,
                prazo = EXCLUDED.prazo,
                observacao_atual = EXCLUDED.observacao_atual,
                atualizado_por = EXCLUDED.atualizado_por,
                atualizado_em = now()
            RETURNING id
            """
        ),
        {
            **finding,
            "workflow_status": update.status,
            "assignee_id": update.assignee_id,
            "due_date": update.due_date,
            "note": note,
            "user_id": current_user.id,
        },
    )
    workflow_id = workflow_result.scalar_one()
    current = await _get_workflow_by_id(session=session, workflow_id=workflow_id)

    details = {
        "finding_id": finding_id,
        "before": _workflow_snapshot(previous),
        "after": _workflow_snapshot(current),
        "note": note,
    }
    await session.execute(
        text(
            """
            INSERT INTO app.evento_auditoria (
                cliente_id,
                usuario_id,
                acao,
                recurso,
                recurso_id,
                detalhes
            )
            VALUES (
                :client_id,
                :user_id,
                :action,
                'vulnerability_workflow',
                :resource_id,
                CAST(:details AS jsonb)
            )
            """
        ),
        {
            "client_id": current_user.client_id,
            "user_id": current_user.id,
            "action": "workflow.created" if previous is None else "workflow.updated",
            "resource_id": str(workflow_id),
            "details": json.dumps(details, ensure_ascii=False),
        },
    )
    await session.commit()
    return _workflow_state(
        current,
        can_edit=True,
        can_accept_risk=current_user.role in {"administrador", "gestor"},
    )


@router.get("/{finding_id}/history", response_model=WorkflowHistoryResponse)
async def get_vulnerability_history(
    finding_id: int,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> WorkflowHistoryResponse:
    finding = await _get_finding_identity(
        session=session,
        finding_id=finding_id,
        client_id=current_user.client_id,
    )
    if finding is None:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail="Vulnerabilidade não encontrada.",
        )

    workflow_result = await session.execute(
        text(
            """
            SELECT id
            FROM app.vulnerabilidade_tratamento
            WHERE cliente_id = :client_id
              AND host_id = :host_id
              AND plugin_id = :plugin_id
              AND protocolo = :protocol
              AND porta = :port
            """
        ),
        finding,
    )
    workflow_id = workflow_result.scalar_one_or_none()
    if workflow_id is None:
        return WorkflowHistoryResponse(items=[])

    history_result = await session.execute(
        text(
            """
            SELECT
                event.id,
                event.acao,
                actor.nome AS usuario_nome,
                event.detalhes,
                event.criado_em
            FROM app.evento_auditoria event
            LEFT JOIN app.usuario actor ON actor.id = event.usuario_id
            WHERE event.cliente_id = :client_id
              AND event.recurso = 'vulnerability_workflow'
              AND event.recurso_id = :workflow_id
            ORDER BY event.criado_em DESC, event.id DESC
            LIMIT 50
            """
        ),
        {"client_id": current_user.client_id, "workflow_id": str(workflow_id)},
    )
    return WorkflowHistoryResponse(
        items=[
            WorkflowHistoryItem(
                id=row["id"],
                action=row["acao"],
                user_name=row["usuario_nome"],
                details=row["detalhes"],
                created_at=row["criado_em"],
            )
            for row in history_result.mappings().all()
        ]
    )


@router.get("/{finding_id}/remediation", response_model=RemediationPlan | None)
async def get_remediation_plan(
    finding_id: int,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> RemediationPlan | None:
    workflow_id, context = await _get_remediation_context(
        session=session,
        finding_id=finding_id,
        client_id=current_user.client_id,
    )
    return await _get_saved_remediation(
        session=session,
        workflow_id=workflow_id,
        input_signature=remediation_input_signature(context),
        can_regenerate=current_user.role == "administrador",
    )


@router.get("/{finding_id}/remediation/history", response_model=RemediationHistoryResponse)
async def get_remediation_history(
    finding_id: int,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> RemediationHistoryResponse:
    workflow_id, context = await _get_remediation_context(
        session=session,
        finding_id=finding_id,
        client_id=current_user.client_id,
    )
    result = await session.execute(
        text(
            """
            SELECT
                analysis.geracao,
                analysis.provedor,
                analysis.modelo,
                analysis.versao_prompt,
                analysis.assinatura_entrada,
                analysis.conteudo,
                analysis.tokens_entrada,
                analysis.tokens_saida,
                analysis.tokens_total,
                analysis.custo_estimado_usd,
                analysis.criado_em
            FROM app.vulnerabilidade_analise_ia analysis
            WHERE analysis.tratamento_id = :workflow_id
              AND analysis.ativa = false
            ORDER BY analysis.geracao DESC
            LIMIT 20
            """
        ),
        {"workflow_id": workflow_id},
    )
    input_signature = remediation_input_signature(context)
    items = [
        _remediation_from_row(
            row,
            input_signature=input_signature,
            previous_versions=0,
            can_regenerate=False,
        )
        for row in result.mappings().all()
    ]
    return RemediationHistoryResponse(items=items)


@router.post("/{finding_id}/remediation", response_model=RemediationPlan)
async def create_remediation_plan(
    finding_id: int,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> RemediationPlan:
    return await _generate_or_reuse_remediation(
        finding_id=finding_id,
        current_user=current_user,
        session=session,
        regenerate=False,
    )


@router.post("/{finding_id}/remediation/regenerate", response_model=RemediationPlan)
async def regenerate_remediation_plan(
    finding_id: int,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> RemediationPlan:
    if current_user.role != "administrador":
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Somente administradores podem gerar uma nova versão da análise.",
        )
    return await _generate_or_reuse_remediation(
        finding_id=finding_id,
        current_user=current_user,
        session=session,
        regenerate=True,
    )


async def _generate_or_reuse_remediation(
    *,
    finding_id: int,
    current_user: CurrentUser,
    session: AsyncSession,
    regenerate: bool,
) -> RemediationPlan:
    require_role(
        current_user,
        AI_GENERATION_ROLES,
        detail="Somente administradores e analistas podem solicitar uma análise da IA.",
    )

    workflow_id, context = await _get_remediation_context(
        session=session,
        finding_id=finding_id,
        client_id=current_user.client_id,
    )
    input_signature = remediation_input_signature(context)

    await session.execute(
        text(
            "SELECT pg_advisory_xact_lock("
            "hashtextextended(CAST(:workflow_id AS text), 0)"
            ")"
        ),
        {"workflow_id": str(workflow_id)},
    )
    saved = await _get_saved_remediation(
        session=session,
        workflow_id=workflow_id,
        input_signature=input_signature,
        can_regenerate=current_user.role == "administrador",
    )
    if saved is not None and not regenerate:
        return saved

    generated = await generate_remediation_plan(context, config=settings.active_ai)
    if generated.source == "scanner_template":
        if saved is not None:
            return saved.model_copy(
                update={
                    "warning": (
                        "A nova geração falhou ou a IA não está configurada. Mantivemos a versão "
                        "salva, sem substituir o histórico."
                    )
                }
            )
        return generated.model_copy(
            update={"can_regenerate": current_user.role == "administrador"}
        )

    next_version = (saved.version if saved is not None and saved.version is not None else 0) + 1
    if regenerate:
        await session.execute(
            text(
                """
                UPDATE app.vulnerabilidade_analise_ia
                SET ativa = false
                WHERE tratamento_id = :workflow_id AND ativa = true
                """
            ),
            {"workflow_id": workflow_id},
        )

    content = RemediationDraft.model_validate(
        generated.model_dump(include=set(RemediationDraft.model_fields))
    ).model_dump(mode="json")
    insert_result = await session.execute(
        text(
            """
            INSERT INTO app.vulnerabilidade_analise_ia (
                cliente_id,
                tratamento_id,
                geracao,
                provedor,
                modelo,
                versao_prompt,
                assinatura_entrada,
                conteudo,
                tokens_entrada,
                tokens_saida,
                tokens_total,
                custo_estimado_usd,
                motivo_geracao,
                criado_por
            )
            VALUES (
                :client_id,
                :workflow_id,
                :generation,
                :provider,
                :model,
                :prompt_version,
                :input_signature,
                CAST(:content AS jsonb),
                :input_tokens,
                :output_tokens,
                :total_tokens,
                :estimated_cost_usd,
                :reason,
                :user_id
            )
            RETURNING id, criado_em
            """
        ),
        {
            "client_id": current_user.client_id,
            "workflow_id": workflow_id,
            "generation": next_version,
            "provider": generated.source,
            "model": generated.model,
            "prompt_version": generated.prompt_version,
            "input_signature": input_signature,
            "content": json.dumps(content, ensure_ascii=False),
            "input_tokens": generated.input_tokens or 0,
            "output_tokens": generated.output_tokens or 0,
            "total_tokens": generated.total_tokens or 0,
            "estimated_cost_usd": generated.estimated_cost_usd or 0,
            "reason": "manual_regeneration" if regenerate else "initial",
            "user_id": current_user.id,
        },
    )
    inserted = insert_result.mappings().one()
    await session.execute(
        text(
            """
            INSERT INTO app.evento_auditoria (
                cliente_id,
                usuario_id,
                acao,
                recurso,
                recurso_id,
                detalhes
            )
            VALUES (
                :client_id,
                :user_id,
                :action,
                'vulnerability_ai_analysis',
                :resource_id,
                CAST(:details AS jsonb)
            )
            """
        ),
        {
            "client_id": current_user.client_id,
            "user_id": current_user.id,
            "action": "ai_analysis.regenerated" if regenerate else "ai_analysis.generated",
            "resource_id": str(inserted["id"]),
            "details": json.dumps(
                {
                    "finding_id": finding_id,
                    "workflow_id": str(workflow_id),
                    "generation": next_version,
                    "provider": generated.source,
                    "model": generated.model,
                    "prompt_version": generated.prompt_version,
                    "input_tokens": generated.input_tokens,
                    "output_tokens": generated.output_tokens,
                    "total_tokens": generated.total_tokens,
                    "estimated_cost_usd": generated.estimated_cost_usd,
                },
                ensure_ascii=False,
            ),
        },
    )
    await session.commit()
    return generated.model_copy(
        update={
            "cached": False,
            "version": next_version,
            "previous_versions": next_version - 1,
            "generated_at": inserted["criado_em"],
            "stale": False,
            "can_regenerate": current_user.role == "administrador",
        }
    )


async def _get_remediation_context(
    *,
    session: AsyncSession,
    finding_id: int,
    client_id: int,
) -> tuple[UUID, RemediationContext]:
    result = await session.execute(
        text(
            f"""
            SELECT
                finding.plugin_id,
                finding.titulo,
                finding.familia,
                finding.sistema_operacional,
                finding.credenciado,
                finding.severidade,
                finding.risco,
                finding.cves,
                finding.sinopse,
                finding.descricao,
                finding.solucao,
                finding.saida_plugin,
                finding.protocolo,
                finding.porta,
                finding.servico,
                finding.cvss2,
                finding.cvss3,
                finding.cvss4,
                finding.cvss3_vetor,
                finding.epss,
                finding.exploravel,
                finding.maturidade_exploit,
                finding.vpr,
                (
                    SELECT plugin.referencias
                    FROM vm.plugin plugin
                    WHERE plugin.plugin_id = finding.plugin_id
                ) AS referencias,
                workflow.id AS workflow_id,
                {NEO_SCORE_SQL} AS neo_score
            FROM vm.vw_achado finding
            JOIN app.vulnerabilidade_tratamento workflow
              ON workflow.cliente_id = finding.cliente_id
             AND workflow.host_id = finding.host_id
             AND workflow.plugin_id = finding.plugin_id
             AND workflow.protocolo = finding.protocolo
             AND workflow.porta = finding.porta
            WHERE finding.id = :finding_id AND finding.cliente_id = :client_id
            """
        ),
        {"finding_id": finding_id, "client_id": client_id},
    )
    row = result.mappings().one_or_none()
    if row is None:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail="Vulnerabilidade não encontrada.",
        )

    score = int(row["neo_score"])
    return row["workflow_id"], RemediationContext(
        plugin_id=row["plugin_id"],
        title=row["titulo"],
        family=row["familia"],
        operating_system=row["sistema_operacional"],
        credentialed_scan=bool(row["credenciado"]),
        severity=_number_to_severity(row["severidade"]),
        risk_factor=row["risco"],
        cves=list(row["cves"] or []),
        synopsis=row["sinopse"],
        description=row["descricao"],
        scanner_solution=row["solucao"],
        scanner_evidence=row["saida_plugin"],
        scanner_references=_split_reference_text(row["referencias"]),
        protocol=row["protocolo"],
        port=row["porta"],
        service=row["servico"],
        cvss=_best_cvss(row),
        cvss3_vector=row["cvss3_vetor"],
        vpr=_optional_float(row["vpr"]),
        epss=_optional_float(row["epss"]),
        exploitable=bool(row["exploravel"]),
        exploit_maturity=row["maturidade_exploit"],
        neo_score=score,
        priority=priority_for_score(score),
    )


async def _get_saved_remediation(
    *,
    session: AsyncSession,
    workflow_id: UUID,
    input_signature: str,
    can_regenerate: bool,
) -> RemediationPlan | None:
    result = await session.execute(
        text(
            """
            SELECT
                analysis.geracao,
                analysis.provedor,
                analysis.modelo,
                analysis.versao_prompt,
                analysis.assinatura_entrada,
                analysis.conteudo,
                analysis.tokens_entrada,
                analysis.tokens_saida,
                analysis.tokens_total,
                analysis.custo_estimado_usd,
                analysis.criado_em,
                history.total_versions
            FROM app.vulnerabilidade_analise_ia analysis
            CROSS JOIN LATERAL (
                SELECT count(*)::integer AS total_versions
                FROM app.vulnerabilidade_analise_ia previous
                WHERE previous.tratamento_id = analysis.tratamento_id
            ) history
            WHERE analysis.tratamento_id = :workflow_id
              AND analysis.ativa = true
            """
        ),
        {"workflow_id": workflow_id},
    )
    row = result.mappings().one_or_none()
    if row is None:
        return None

    total_versions = int(row["total_versions"])
    return _remediation_from_row(
        row,
        input_signature=input_signature,
        previous_versions=max(total_versions - 1, 0),
        can_regenerate=can_regenerate,
    )


def _remediation_from_row(
    row: Mapping[str, object],
    *,
    input_signature: str,
    previous_versions: int,
    can_regenerate: bool,
) -> RemediationPlan:
    draft = RemediationDraft.model_validate(row["conteudo"])
    return RemediationPlan(
        **draft.model_dump(),
        source=row["provedor"],
        model=row["modelo"],
        prompt_version=row["versao_prompt"],
        cached=True,
        version=row["geracao"],
        previous_versions=previous_versions,
        generated_at=row["criado_em"],
        input_tokens=row["tokens_entrada"],
        output_tokens=row["tokens_saida"],
        total_tokens=row["tokens_total"],
        estimated_cost_usd=float(row["custo_estimado_usd"]),
        stale=(
            row["assinatura_entrada"].strip() != input_signature
            or row["versao_prompt"] != settings.ai_prompt_version
        ),
        can_regenerate=can_regenerate,
    )


@router.get("/{finding_id}", response_model=VulnerabilityDetail)
async def get_vulnerability(
    finding_id: int,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> VulnerabilityDetail:
    result = await session.execute(
        text(
            f"""
            SELECT
                finding.id,
                finding.host_id,
                finding.plugin_id,
                finding.endereco,
                finding.fqdn,
                finding.sistema_operacional,
                finding.credenciado,
                finding.titulo,
                finding.familia,
                finding.sinopse,
                finding.descricao,
                finding.solucao,
                finding.saida_plugin,
                finding.cves,
                finding.protocolo,
                finding.porta,
                finding.servico,
                finding.severidade,
                finding.risco,
                finding.cvss2,
                finding.cvss3,
                finding.cvss4,
                finding.cvss3_vetor,
                finding.vpr,
                finding.epss,
                finding.exploravel,
                finding.maturidade_exploit,
                coalesce(
                    finding.descoberto_em,
                    finding.observado_em,
                    now()
                ) AS descoberto_em,
                coalesce(
                    finding.observado_em,
                    finding.descoberto_em,
                    now()
                ) AS observado_em,
                workflow.id AS workflow_id,
                coalesce(workflow.status, 'open') AS workflow_status,
                workflow.prazo AS workflow_due_date,
                workflow.observacao_atual AS workflow_note,
                workflow.atualizado_em AS workflow_updated_at,
                workflow.primeiro_detectado_em AS workflow_first_detected_at,
                workflow.ultimo_detectado_em AS workflow_last_detected_at,
                workflow.resolvido_em AS workflow_resolved_at,
                workflow.reaberto_em AS workflow_reopened_at,
                workflow.total_resolucoes AS workflow_resolution_count,
                workflow.total_reaberturas AS workflow_reopen_count,
                workflow.ultimo_scan_id AS workflow_last_scan_id,
                assignee.id AS assignee_id,
                assignee.nome AS assignee_name,
                assignee.email AS assignee_email,
                {NEO_SCORE_SQL} AS neo_score
            FROM vm.vw_achado finding
            LEFT JOIN app.vulnerabilidade_tratamento workflow
              ON workflow.cliente_id = finding.cliente_id
             AND workflow.host_id = finding.host_id
             AND workflow.plugin_id = finding.plugin_id
             AND workflow.protocolo = finding.protocolo
             AND workflow.porta = finding.porta
            LEFT JOIN app.usuario assignee ON assignee.id = workflow.responsavel_id
            WHERE finding.id = :finding_id AND finding.cliente_id = :client_id
            """
        ),
        {"finding_id": finding_id, "client_id": current_user.client_id},
    )
    row = result.mappings().one_or_none()
    if row is None:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail="Vulnerabilidade não encontrada.",
        )

    score = calculate_neo_score(
        severity=row["severidade"],
        cvss2=_optional_float(row["cvss2"]),
        cvss3=_optional_float(row["cvss3"]),
        cvss4=_optional_float(row["cvss4"]),
        epss=_optional_float(row["epss"]),
        exploitable=row["exploravel"],
        vpr=_optional_float(row["vpr"]),
    )
    return VulnerabilityDetail(
        id=row["id"],
        title=row["titulo"],
        severity=_number_to_severity(row["severidade"]),
        status=row["workflow_status"],
        family=row["familia"],
        synopsis=row["sinopse"],
        description=row["descricao"],
        solution=row["solucao"],
        plugin_output=row["saida_plugin"],
        cves=list(row["cves"] or []),
        asset=VulnerabilityAsset(
            id=row["host_id"],
            address=row["endereco"],
            fqdn=row["fqdn"],
            operating_system=row["sistema_operacional"],
            credentialed=row["credenciado"],
        ),
        protocol=row["protocolo"],
        port=row["porta"],
        service=row["servico"],
        risk_factor=row["risco"],
        cvss2=_optional_float(row["cvss2"]),
        cvss3=_optional_float(row["cvss3"]),
        cvss4=_optional_float(row["cvss4"]),
        cvss3_vector=row["cvss3_vetor"],
        vpr=_optional_float(row["vpr"]),
        epss=_optional_float(row["epss"]),
        exploitable=row["exploravel"],
        exploit_maturity=row["maturidade_exploit"],
        discovered_at=row["descoberto_em"],
        observed_at=row["observado_em"],
        neo_score=NeoScoreBreakdown(
            total=score.total,
            priority=score.priority,
            cvss_component=score.cvss_component,
            epss_component=score.epss_component,
            exploit_component=score.exploit_component,
            vpr_component=score.vpr_component,
            factors=list(score.factors),
        ),
        workflow=_workflow_state(
            {
                "id": row["workflow_id"],
                "status": row["workflow_status"],
                "responsavel_id": row["assignee_id"],
                "responsavel_nome": row["assignee_name"],
                "responsavel_email": row["assignee_email"],
                "prazo": row["workflow_due_date"],
                "observacao_atual": row["workflow_note"],
                "atualizado_em": row["workflow_updated_at"],
                "primeiro_detectado_em": row["workflow_first_detected_at"],
                "ultimo_detectado_em": row["workflow_last_detected_at"],
                "resolvido_em": row["workflow_resolved_at"],
                "reaberto_em": row["workflow_reopened_at"],
                "total_resolucoes": row["workflow_resolution_count"],
                "total_reaberturas": row["workflow_reopen_count"],
                "ultimo_scan_id": row["workflow_last_scan_id"],
            },
            can_edit=(
                current_user.role in OPERATIONAL_ROLES
                and row["workflow_status"] != "resolved"
            ),
            can_accept_risk=current_user.role in {"administrador", "gestor"},
        ),
        can_generate_ai=current_user.role in AI_GENERATION_ROLES,
    )


def _severity_to_number(severity: Severity | None) -> int | None:
    if severity is None:
        return None
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[severity]


def _number_to_severity(severity: int) -> Severity:
    return {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}[severity]


def _optional_float(value: object) -> float | None:
    return float(value) if value is not None else None


def _split_reference_text(value: object) -> list[str]:
    if not isinstance(value, str):
        return []
    return [line.strip() for line in value.splitlines() if line.strip()]


def _best_cvss(row: object) -> float | None:
    for field in ("cvss4", "cvss3", "cvss2"):
        value = row[field]  # type: ignore[index]
        if value is not None:
            return float(value)
    return None


async def _get_finding_identity(
    *,
    session: AsyncSession,
    finding_id: int,
    client_id: int,
) -> dict[str, object] | None:
    result = await session.execute(
        text(
            """
            SELECT
                cliente_id AS client_id,
                host_id,
                plugin_id,
                protocolo AS protocol,
                porta AS port
            FROM vm.vw_achado
            WHERE id = :finding_id AND cliente_id = :client_id
            """
        ),
        {"finding_id": finding_id, "client_id": client_id},
    )
    row = result.mappings().one_or_none()
    return dict(row) if row is not None else None


async def _get_workflow_by_id(
    *,
    session: AsyncSession,
    workflow_id: UUID,
) -> Mapping[str, object]:
    result = await session.execute(
        text(
            """
            SELECT
                workflow.id,
                workflow.status,
                workflow.responsavel_id,
                workflow.prazo,
                workflow.observacao_atual,
                workflow.atualizado_em,
                workflow.primeiro_detectado_em,
                workflow.ultimo_detectado_em,
                workflow.resolvido_em,
                workflow.reaberto_em,
                workflow.total_resolucoes,
                workflow.total_reaberturas,
                workflow.ultimo_scan_id,
                assignee.nome AS responsavel_nome,
                assignee.email AS responsavel_email
            FROM app.vulnerabilidade_tratamento workflow
            LEFT JOIN app.usuario assignee ON assignee.id = workflow.responsavel_id
            WHERE workflow.id = :workflow_id
            """
        ),
        {"workflow_id": workflow_id},
    )
    return result.mappings().one()


def _workflow_state(
    row: Mapping[str, object],
    *,
    can_edit: bool,
    can_accept_risk: bool,
) -> WorkflowState:
    assignee_id = row.get("responsavel_id")
    assignee = None
    if assignee_id is not None:
        assignee = WorkflowAssignee(
            id=assignee_id,  # type: ignore[arg-type]
            name=str(row.get("responsavel_nome") or "Usuário"),
            email=str(row.get("responsavel_email") or ""),
        )
    return WorkflowState(
        id=row.get("id"),  # type: ignore[arg-type]
        status=str(row.get("status") or "open"),  # type: ignore[arg-type]
        assignee=assignee,
        due_date=row.get("prazo"),  # type: ignore[arg-type]
        note=str(row["observacao_atual"]) if row.get("observacao_atual") else None,
        updated_at=row.get("atualizado_em"),  # type: ignore[arg-type]
        first_detected_at=row.get("primeiro_detectado_em"),  # type: ignore[arg-type]
        last_detected_at=row.get("ultimo_detectado_em"),  # type: ignore[arg-type]
        resolved_at=row.get("resolvido_em"),  # type: ignore[arg-type]
        reopened_at=row.get("reaberto_em"),  # type: ignore[arg-type]
        resolution_count=int(row.get("total_resolucoes") or 0),
        reopen_count=int(row.get("total_reaberturas") or 0),
        last_scan_id=row.get("ultimo_scan_id"),  # type: ignore[arg-type]
        can_edit=can_edit,
        can_accept_risk=can_accept_risk,
    )


def _workflow_snapshot(row: Mapping[str, object] | None) -> dict[str, object] | None:
    if row is None:
        return None
    return {
        "status": row.get("status"),
        "assignee_id": str(row["responsavel_id"]) if row.get("responsavel_id") else None,
        "due_date": str(row["prazo"]) if row.get("prazo") else None,
    }

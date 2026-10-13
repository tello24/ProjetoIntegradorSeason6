import json
from collections.abc import Mapping
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import OPERATIONAL_ROLES, CurrentUserDep, SessionDep, require_role
from app.core.config import settings
from app.services.risk import NEO_SCORE_SQL
from app.services.ticketing import JiraClient, TicketDraft, TicketProviderError

router = APIRouter()


class VulnerabilityTicket(BaseModel):
    id: UUID
    provider: str
    status: str
    external_key: str | None
    external_url: str | None
    summary: str
    error: str | None
    created_at: datetime
    updated_at: datetime


class TicketIntegrationState(BaseModel):
    provider: str
    enabled: bool
    can_create: bool
    ticket: VulnerabilityTicket | None


@router.get(
    "/vulnerabilities/{finding_id}/ticket",
    response_model=TicketIntegrationState,
)
async def get_vulnerability_ticket(
    finding_id: int,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> TicketIntegrationState:
    context = await _get_ticket_context(
        session=session,
        finding_id=finding_id,
        client_id=current_user.client_id,
    )
    ticket = await _get_ticket(
        session=session,
        workflow_id=context.get("workflow_id"),
        provider="jira",
    )
    return _integration_state(
        ticket=ticket,
        workflow_status=str(context.get("workflow_status") or "open"),
        can_edit=current_user.role in OPERATIONAL_ROLES,
    )


@router.post(
    "/vulnerabilities/{finding_id}/ticket",
    response_model=TicketIntegrationState,
)
async def create_vulnerability_ticket(
    finding_id: int,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> TicketIntegrationState:
    require_role(current_user, OPERATIONAL_ROLES)
    config = settings.active_jira
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "A integração com Jira não está pronta. Confira TICKET_PROVIDER, URL, "
                "projeto, e-mail e token da API."
            ),
        )

    context = await _get_ticket_context(
        session=session,
        finding_id=finding_id,
        client_id=current_user.client_id,
    )
    workflow_id = context.get("workflow_id")
    if workflow_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="O fluxo de tratamento ainda não foi criado para esta vulnerabilidade.",
        )
    if context.get("workflow_status") == "resolved":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A vulnerabilidade já foi resolvida por evidência de scan.",
        )

    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
        {"lock_key": f"ticket:jira:{workflow_id}"},
    )
    existing = await _get_ticket(
        session=session,
        workflow_id=workflow_id,
        provider="jira",
    )
    if existing is not None and existing.status == "created":
        return _integration_state(ticket=existing, workflow_status="open", can_edit=True)
    if existing is not None and existing.status == "creating":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A criação do ticket já está em andamento.",
        )

    draft = _ticket_draft(
        context,
        finding_id=finding_id,
        include_asset_details=config.include_asset_details,
        app_public_url=config.app_public_url,
    )
    if existing is None:
        reservation_result = await session.execute(
            text(
                """
                INSERT INTO app.vulnerabilidade_ticket (
                    cliente_id,
                    tratamento_id,
                    provedor,
                    status,
                    resumo,
                    criado_por
                )
                VALUES (
                    :client_id,
                    :workflow_id,
                    'jira',
                    'creating',
                    :summary,
                    :user_id
                )
                RETURNING id
                """
            ),
            {
                "client_id": current_user.client_id,
                "workflow_id": workflow_id,
                "summary": draft.summary,
                "user_id": current_user.id,
            },
        )
        ticket_id = reservation_result.scalar_one()
    else:
        ticket_id = existing.id
        await session.execute(
            text(
                """
                UPDATE app.vulnerabilidade_ticket
                SET status = 'creating', ultimo_erro = NULL, atualizado_em = now()
                WHERE id = :ticket_id
                """
            ),
            {"ticket_id": ticket_id},
        )
    # Persist the reservation before the external request. This avoids duplicate Jira
    # issues if two users click at the same time.
    await session.commit()

    try:
        created = await run_in_threadpool(JiraClient(config).create_issue, draft)
    except TicketProviderError as exc:
        await _mark_ticket_failed(session=session, ticket_id=ticket_id, message=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        message = "Falha inesperada ao criar o ticket no Jira. Tente novamente."
        await _mark_ticket_failed(session=session, ticket_id=ticket_id, message=message)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=message) from exc

    await session.execute(
        text(
            """
            UPDATE app.vulnerabilidade_ticket
            SET
                status = 'created',
                chave_externa = :external_key,
                url_externa = :external_url,
                ultimo_erro = NULL,
                atualizado_em = now()
            WHERE id = :ticket_id
            """
        ),
        {
            "ticket_id": ticket_id,
            "external_key": created.external_key,
            "external_url": created.external_url,
        },
    )
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
                'ticket.created',
                'vulnerability_ticket',
                :resource_id,
                CAST(:details AS jsonb)
            )
            """
        ),
        {
            "client_id": current_user.client_id,
            "user_id": current_user.id,
            "resource_id": str(ticket_id),
            "details": json.dumps(
                {
                    "finding_id": finding_id,
                    "workflow_id": str(workflow_id),
                    "provider": "jira",
                    "external_key": created.external_key,
                }
            ),
        },
    )
    await session.commit()
    saved = await _get_ticket(session=session, workflow_id=workflow_id, provider="jira")
    return _integration_state(ticket=saved, workflow_status="open", can_edit=True)


async def _get_ticket_context(
    *,
    session: AsyncSession,
    finding_id: int,
    client_id: int,
) -> Mapping[str, object]:
    result = await session.execute(
        text(
            f"""
            SELECT
                finding.titulo,
                finding.severidade,
                finding.endereco,
                finding.fqdn,
                finding.cves,
                finding.protocolo,
                finding.porta,
                finding.servico,
                finding.cvss2,
                finding.cvss3,
                finding.cvss4,
                finding.solucao,
                workflow.id AS workflow_id,
                coalesce(workflow.status, 'open') AS workflow_status,
                analysis.conteudo AS ai_content,
                {NEO_SCORE_SQL} AS neo_score
            FROM vm.vw_achado finding
            LEFT JOIN app.vulnerabilidade_tratamento workflow
              ON workflow.cliente_id = finding.cliente_id
             AND workflow.host_id = finding.host_id
             AND workflow.plugin_id = finding.plugin_id
             AND workflow.protocolo = finding.protocolo
             AND workflow.porta = finding.porta
            LEFT JOIN app.vulnerabilidade_analise_ia analysis
              ON analysis.tratamento_id = workflow.id
             AND analysis.ativa = true
            WHERE finding.id = :finding_id AND finding.cliente_id = :client_id
            """
        ),
        {"finding_id": finding_id, "client_id": client_id},
    )
    row = result.mappings().one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerabilidade não encontrada.",
        )
    return row


async def _get_ticket(
    *,
    session: AsyncSession,
    workflow_id: object,
    provider: str,
) -> VulnerabilityTicket | None:
    if workflow_id is None:
        return None
    result = await session.execute(
        text(
            """
            SELECT
                id,
                provedor,
                status,
                chave_externa,
                url_externa,
                resumo,
                ultimo_erro,
                criado_em,
                atualizado_em
            FROM app.vulnerabilidade_ticket
            WHERE tratamento_id = :workflow_id AND provedor = :provider
            """
        ),
        {"workflow_id": workflow_id, "provider": provider},
    )
    row = result.mappings().one_or_none()
    if row is None:
        return None
    return VulnerabilityTicket(
        id=row["id"],
        provider=row["provedor"],
        status=row["status"],
        external_key=row["chave_externa"],
        external_url=row["url_externa"],
        summary=row["resumo"],
        error=row["ultimo_erro"],
        created_at=row["criado_em"],
        updated_at=row["atualizado_em"],
    )


async def _mark_ticket_failed(
    *,
    session: AsyncSession,
    ticket_id: UUID,
    message: str,
) -> None:
    await session.execute(
        text(
            """
            UPDATE app.vulnerabilidade_ticket
            SET status = 'failed', ultimo_erro = :message, atualizado_em = now()
            WHERE id = :ticket_id
            """
        ),
        {"ticket_id": ticket_id, "message": message[:500]},
    )
    await session.commit()


def _ticket_draft(
    context: Mapping[str, object],
    *,
    finding_id: int,
    include_asset_details: bool,
    app_public_url: str,
) -> TicketDraft:
    severity = _severity_label(int(context["severidade"]))
    title = str(context["titulo"])
    cves = ", ".join(str(item) for item in (context.get("cves") or [])) or "Não informado"
    cvss = next(
        (
            float(context[field])
            for field in ("cvss4", "cvss3", "cvss2")
            if context.get(field) is not None
        ),
        None,
    )
    asset = (
        str(context.get("fqdn") or context.get("endereco") or "Não identificado")
        if include_asset_details
        else "Omitido pela política de integração"
    )
    lines = [
        f"Vulnerabilidade: {title}",
        f"Severidade: {severity}",
        f"WVM Score: {context['neo_score']}/100",
        f"CVSS: {cvss:.1f}" if cvss is not None else "CVSS: Não informado",
        f"CVEs: {cves}",
        f"Ativo: {asset}",
        f"Exposição: {str(context['protocolo']).upper()}/{context['porta']}"
        + (f" ({context['servico']})" if context.get("servico") else ""),
    ]
    ai_content = context.get("ai_content")
    if isinstance(ai_content, dict):
        if ai_content.get("why_it_matters"):
            lines.append(f"Por que isso importa: {ai_content['why_it_matters']}")
        if ai_content.get("summary"):
            lines.append(f"Plano de correção: {ai_content['summary']}")
        steps = ai_content.get("steps")
        if isinstance(steps, list):
            lines.extend(
                f"Passo {index}: {step}"
                for index, step in enumerate(steps[:10], start=1)
            )
    elif context.get("solucao"):
        lines.append(f"Recomendação do scanner: {context['solucao']}")
    lines.append(f"Abrir no WVM: {app_public_url}/vulnerabilities/{finding_id}")

    return TicketDraft(
        summary=f"[WVM][{severity.upper()}] {title}"[:255],
        description_lines=tuple(lines),
        stable_label=f"wvm-{context['workflow_id']}",
    )


def _integration_state(
    *,
    ticket: VulnerabilityTicket | None,
    workflow_status: str,
    can_edit: bool,
) -> TicketIntegrationState:
    enabled = settings.active_jira is not None
    can_create = (
        enabled
        and can_edit
        and workflow_status != "resolved"
        and (ticket is None or ticket.status == "failed")
    )
    return TicketIntegrationState(
        provider=settings.ticket_provider,
        enabled=enabled,
        can_create=can_create,
        ticket=ticket,
    )


def _severity_label(severity: int) -> str:
    return {4: "Crítica", 3: "Alta", 2: "Média", 1: "Baixa"}.get(
        severity,
        "Informativa",
    )

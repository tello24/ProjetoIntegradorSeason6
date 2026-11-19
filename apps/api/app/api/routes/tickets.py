import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import OPERATIONAL_ROLES, CurrentUserDep, SessionDep, require_role
from app.core.config import settings
from app.services.risk import NEO_SCORE_SQL
from app.services.ticketing import JiraClient, TicketDraft, TicketProviderError
from app.services.ticketing.configuration import (
    configuration_row,
    configured,
    provider_config,
    tenant_lock,
)

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
    provider: str = "jira"
    enabled: bool
    can_create: bool
    can_reconcile: bool = False
    ticket: VulnerabilityTicket | None


class CreateTicketInput(BaseModel):
    preview_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")


async def _context_and_state(finding_id, current_user, session):
    context = await _get_ticket_context(
        session=session, finding_id=finding_id, client_id=current_user.client_id
    )
    ticket = await _get_ticket(
        session=session, workflow_id=context.get("workflow_id"), client_id=current_user.client_id
    )
    config_row = await configuration_row(session, current_user.client_id)
    return context, ticket, config_row


def _state(context, ticket, row, user):
    enabled = configured(row)
    editable = user.role in OPERATIONAL_ROLES
    reconcilable = bool(
        ticket
        and (
            ticket.status == "uncertain"
            or ticket.status == "creating"
            and ticket.updated_at < datetime.now(UTC) - timedelta(seconds=120)
        )
    )
    return TicketIntegrationState(
        enabled=enabled,
        ticket=ticket,
        can_create=enabled
        and editable
        and context.get("workflow_status") != "resolved"
        and bool(context.get("workflow_id"))
        and (ticket is None or ticket.status == "failed"),
        can_reconcile=enabled and editable and reconcilable,
    )


def _preview(context, finding_id, row):
    # Preview is local, does not decrypt credentials and never calls Jira or AI.
    draft = _ticket_draft(
        context,
        finding_id=finding_id,
        include_asset_details=row["incluir_ativos"],
        app_public_url=settings.app_public_url.rstrip("/"),
    )
    content = {
        "summary": draft.summary,
        "description_lines": list(draft.description_lines),
        "site_url": row["site_url"],
        "project_key": row["projeto"],
        "issue_type": row["tipo_item"],
        "version": row["versao"],
    }
    fingerprint = hashlib.sha256(
        json.dumps(content, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()
    return draft, {**content, "fingerprint": fingerprint}


@router.get("/vulnerabilities/{finding_id}/ticket", response_model=TicketIntegrationState)
async def get_vulnerability_ticket(
    finding_id: int, current_user: CurrentUserDep, session: SessionDep
):
    context, ticket, row = await _context_and_state(finding_id, current_user, session)
    return _state(context, ticket, row, current_user)


@router.get("/vulnerabilities/{finding_id}/ticket/preview")
async def preview_ticket(finding_id: int, current_user: CurrentUserDep, session: SessionDep):
    require_role(current_user, OPERATIONAL_ROLES)
    context, ticket, row = await _context_and_state(finding_id, current_user, session)
    if not _state(context, ticket, row, current_user).can_create:
        raise HTTPException(
            409, "A criação não está disponível. Confira a configuração ou o ticket existente."
        )
    return _preview(context, finding_id, row)[1]


@router.post("/vulnerabilities/{finding_id}/ticket", response_model=TicketIntegrationState)
async def create_vulnerability_ticket(
    finding_id: int,
    body: CreateTicketInput,
    current_user: CurrentUserDep,
    session: SessionDep,
):
    require_role(current_user, OPERATIONAL_ROLES)
    cid = current_user.client_id
    await tenant_lock(session, cid)
    context, ticket, row = await _context_and_state(finding_id, current_user, session)
    if ticket and ticket.status == "created":
        return _state(context, ticket, row, current_user)
    if not _state(context, ticket, row, current_user).can_create:
        raise HTTPException(
            409,
            "Criação bloqueada. Configure o Jira ou confira a tentativa já registrada; "
            "não será criado outro ticket.",
        )
    draft, preview = _preview(context, finding_id, row)
    if body.preview_fingerprint != preview["fingerprint"]:
        raise HTTPException(
            409, "O conteúdo ou destino mudou. Abra novamente a prévia antes de confirmar."
        )
    try:
        config = provider_config(row)
    except TicketProviderError as exc:
        raise HTTPException(503, str(exc)) from None
    result = await session.execute(
        text("""
        INSERT INTO app.vulnerabilidade_ticket
            (cliente_id,tratamento_id,provedor,status,resumo,criado_por,site_url,projeto)
        VALUES (:client,:workflow,'jira','creating',:summary,:user,:site,:project)
        ON CONFLICT (tratamento_id,provedor) DO UPDATE SET status='creating',
            resumo=excluded.resumo,site_url=excluded.site_url,projeto=excluded.projeto,
            ultimo_erro=NULL,codigo_erro=NULL,atualizado_em=now()
        RETURNING id
    """),
        {
            "client": cid,
            "workflow": context["workflow_id"],
            "summary": draft.summary,
            "user": current_user.id,
            "site": config.base_url,
            "project": config.project_key,
        },
    )
    ticket_id = result.scalar_one()
    await _audit(session, current_user, ticket_id, "ticket.requested")
    # Durable reservation: interrupted requests cannot be silently retried.
    await session.commit()
    try:
        created = await run_in_threadpool(JiraClient(config).create_issue, draft)
    except TicketProviderError as exc:
        await _mark_ticket_failed(session, ticket_id, cid, exc)
        raise HTTPException(502, str(exc)) from None
    except Exception:
        error = TicketProviderError("connection", uncertain=True)
        await _mark_ticket_failed(session, ticket_id, cid, error)
        raise HTTPException(502, str(error)) from None
    await _save_created(session, current_user, ticket_id, created, "ticket.created")
    return await get_vulnerability_ticket(finding_id, current_user, session)


@router.post(
    "/vulnerabilities/{finding_id}/ticket/reconcile", response_model=TicketIntegrationState
)
async def reconcile_ticket(finding_id: int, current_user: CurrentUserDep, session: SessionDep):
    require_role(current_user, OPERATIONAL_ROLES)
    cid = current_user.client_id
    await tenant_lock(session, cid)
    context, ticket, row = await _context_and_state(finding_id, current_user, session)
    if ticket and ticket.status == "created":
        return _state(context, ticket, row, current_user)
    if not _state(context, ticket, row, current_user).can_reconcile:
        raise HTTPException(
            409, "Aguarde a tentativa em andamento ou ative a integração antes de verificar."
        )
    target = (
        (
            await session.execute(
                text("""SELECT site_url,projeto
        FROM app.vulnerabilidade_ticket WHERE id=:id AND cliente_id=:client"""),
                {"id": ticket.id, "client": cid},
            )
        )
        .mappings()
        .one()
    )
    if target["site_url"] != row["site_url"] or target["projeto"] != row["projeto"]:
        raise HTTPException(
            409, "O destino original não foi confirmado. Confira o vínculo diretamente no Jira."
        )
    try:
        config = provider_config(row)
    except TicketProviderError as exc:
        raise HTTPException(503, str(exc)) from None
    await session.execute(
        text("""UPDATE app.vulnerabilidade_ticket SET status='uncertain',
        atualizado_em=now() WHERE id=:id AND cliente_id=:client"""),
        {"id": ticket.id, "client": cid},
    )
    await session.commit()
    try:
        created = await run_in_threadpool(
            JiraClient(config).find_issue, f"wvm-{context['workflow_id']}"
        )
    except TicketProviderError as exc:
        # A failed search does not prove that the original creation failed.
        await _mark_ticket_failed(
            session, ticket.id, cid, TicketProviderError(exc.code, uncertain=True)
        )
        raise HTTPException(502, str(exc)) from None
    except Exception:
        error = TicketProviderError("connection", uncertain=True)
        await _mark_ticket_failed(session, ticket.id, cid, error)
        raise HTTPException(502, str(error)) from None
    await _save_created(session, current_user, ticket.id, created, "ticket.reconciled")
    return await get_vulnerability_ticket(finding_id, current_user, session)


async def _audit(session, user, ticket_id, action):
    await session.execute(
        text("""
        INSERT INTO app.evento_auditoria (cliente_id,usuario_id,acao,recurso,recurso_id,detalhes)
        VALUES (:client,:user,:action,'vulnerability_ticket',:resource,'{}'::jsonb)
    """),
        {"client": user.client_id, "user": user.id, "action": action, "resource": str(ticket_id)},
    )


async def _save_created(session, user, ticket_id, created, action):
    await session.execute(
        text("""
        UPDATE app.vulnerabilidade_ticket SET status='created',chave_externa=:key,
            url_externa=:url,ultimo_erro=NULL,codigo_erro=NULL,atualizado_em=now()
        WHERE id=:id AND cliente_id=:client
    """),
        {
            "id": ticket_id,
            "client": user.client_id,
            "key": created.external_key,
            "url": created.external_url,
        },
    )
    await _audit(session, user, ticket_id, action)
    await session.commit()


async def _mark_ticket_failed(session, ticket_id, client_id, error):
    await session.execute(
        text("""
        UPDATE app.vulnerabilidade_ticket SET status=:status,ultimo_erro=:message,
            codigo_erro=:code,atualizado_em=now() WHERE id=:id AND cliente_id=:client
    """),
        {
            "id": ticket_id,
            "client": client_id,
            "message": str(error),
            "code": error.code,
            "status": "uncertain" if error.uncertain else "failed",
        },
    )
    await session.commit()


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
                workflow.prazo, workflow.observacao_atual, assignee.nome AS responsavel_nome,
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
            LEFT JOIN app.usuario assignee ON assignee.id = workflow.responsavel_id
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
    client_id: int,
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
            WHERE tratamento_id = :workflow_id AND provedor = 'jira' AND cliente_id = :client_id
            """
        ),
        {"workflow_id": workflow_id, "client_id": client_id},
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
    stages = {
        "open": "Aberta",
        "triage": "Em triagem",
        "in_progress": "Em correção",
        "pending_validation": "Aguardando validação",
        "accepted_risk": "Risco aceito",
        "resolved": "Corrigida",
    }
    stage = str(context.get("workflow_status") or "open")
    lines.extend(
        [
            f"Etapa no WVM: {stages.get(stage, stage)}",
            f"Responsável no WVM: {context.get('responsavel_nome') or 'Não atribuído'}",
            f"Prazo no WVM: {context.get('prazo') or 'Não definido manualmente'}",
        ]
    )
    if context.get("observacao_atual"):
        lines.append(f"Observação operacional: {context['observacao_atual']}")
    ai_content = context.get("ai_content")
    if isinstance(ai_content, dict):
        if ai_content.get("why_it_matters"):
            lines.append(f"Por que isso importa: {ai_content['why_it_matters']}")
        if ai_content.get("summary"):
            lines.append(f"Plano de correção: {ai_content['summary']}")
        steps = ai_content.get("steps")
        if isinstance(steps, list):
            lines.extend(f"Passo {index}: {step}" for index, step in enumerate(steps[:10], start=1))
        for key, label in (
            ("prerequisites", "Antes de começar"),
            ("validation", "Validação"),
            ("rollback", "Reversão"),
            ("cautions", "Cuidados"),
        ):
            values = ai_content.get(key)
            if isinstance(values, list):
                lines.extend(f"{label}: {value}" for value in values[:5])
    elif context.get("solucao"):
        lines.append(f"Recomendação do scanner: {context['solucao']}")

    # Filter known asset identifiers everywhere, not just in the dedicated asset field.
    # This is not a promise to anonymize arbitrary free text; users review the preview.
    def clean(value: str) -> str:
        if not include_asset_details:
            for identifier in (context.get("fqdn"), context.get("endereco")):
                if identifier:
                    value = value.replace(str(identifier), "[ativo omitido]")
        return value

    lines = [clean(line)[:3000] for line in lines[:59]]
    lines.append(f"Abrir no WVM: {app_public_url}/vulnerabilities/{finding_id}"[:3000])

    return TicketDraft(
        summary=clean(f"[WVM][{severity.upper()}] {title}")[:255],
        description_lines=tuple(lines),
        stable_label=f"wvm-{context['workflow_id']}",
    )


def _severity_label(severity: int) -> str:
    return {4: "Crítica", 3: "Alta", 2: "Média", 1: "Baixa"}.get(
        severity,
        "Informativa",
    )

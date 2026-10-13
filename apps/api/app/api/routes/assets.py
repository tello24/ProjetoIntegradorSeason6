import json
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException
from fastapi import status as http_status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import (
    CurrentUserDep,
    SessionDep,
    UserRole,
    require_role,
)
from app.services.risk import NEO_SCORE_SQL, Priority, priority_for_score

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

ACTIVE_WORKFLOW_STATUSES = "'open', 'triage', 'in_progress', 'validation', 'reopened'"
BUSINESS_CONTEXT_EDIT_ROLES: frozenset[UserRole] = frozenset(
    {"administrador", "gestor"}
)
BusinessEnvironment = Literal[
    "producao",
    "homologacao",
    "desenvolvimento",
    "laboratorio",
    "corporativo",
    "outro",
]
BusinessCriticality = Literal["critica", "alta", "media", "baixa"]


class AssetListItem(BaseModel):
    id: int
    name: str
    address: str
    fqdn: str | None
    operating_system: str | None
    credentialed: bool
    vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    risk_score: int
    priority: Priority
    last_seen: datetime
    environment: BusinessEnvironment | None
    business_criticality: BusinessCriticality | None
    business_owner_name: str | None
    responsible_team: str | None
    business_service: str | None
    internet_exposed: bool | None


class AssetListSummary(BaseModel):
    total: int
    critical_exposure: int
    credentialed: int
    uncredentialed: int
    clean: int
    critical_business_assets: int
    critical_business_exposure: int
    production_uncredentialed: int
    without_owner: int


class AssetListResponse(BaseModel):
    items: list[AssetListItem]
    summary: AssetListSummary


class AssetFacts(BaseModel):
    netbios: str | None
    mac: str | None
    system_type: str | None
    bios_uuid: str | None
    cpes: list[str]
    operating_system_confidence: int | None
    operating_system_method: str | None


class AssetScanCoverage(BaseModel):
    credentialed: bool
    local_checks_protocol: str | None
    scan_started_at: datetime | None
    scan_ended_at: datetime | None
    duration_seconds: int | None
    last_authenticated_results_at: datetime | None
    last_unauthenticated_results_at: datetime | None
    policy_used: str | None


class AssetInventorySummary(BaseModel):
    first_seen: datetime
    last_seen: datetime
    scans_observed: int
    observed_services: int
    services_with_findings: int
    patch_summary_total_cves: int | None


class AssetServiceReference(BaseModel):
    protocol: str
    port: int
    service: str | None


class AssetChangeSummary(BaseModel):
    available: bool
    previous_scan_name: str | None
    previous_scan_at: datetime | None
    new_findings: int
    corrected_findings: int
    persistent_findings: int
    reopened_findings: int
    vulnerability_delta: int
    risk_delta: int
    ports_added: list[AssetServiceReference]
    ports_removed: list[AssetServiceReference]
    operating_system_changed: bool
    credentialed_changed: bool


class AssetBusinessOwner(BaseModel):
    id: UUID
    name: str
    email: str


class AssetBusinessContext(BaseModel):
    environment: BusinessEnvironment | None
    business_criticality: BusinessCriticality | None
    owner: AssetBusinessOwner | None
    responsible_team: str | None
    business_service: str | None
    business_unit: str | None
    internet_exposed: bool | None
    maintenance_window: str | None
    tags: list[str]
    notes: str | None
    updated_at: datetime | None
    updated_by_name: str | None
    can_edit: bool


class AssetBusinessContextUpdate(BaseModel):
    environment: BusinessEnvironment | None = None
    business_criticality: BusinessCriticality | None = None
    owner_id: UUID | None = None
    responsible_team: str | None = Field(default=None, max_length=120)
    business_service: str | None = Field(default=None, max_length=160)
    business_unit: str | None = Field(default=None, max_length=120)
    internet_exposed: bool | None = None
    maintenance_window: str | None = Field(default=None, max_length=200)
    tags: list[str] = Field(default_factory=list, max_length=20)
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator(
        "responsible_team",
        "business_service",
        "business_unit",
        "maintenance_window",
        "notes",
        mode="before",
    )
    @classmethod
    def normalize_optional_text(cls, value):
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized or None

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            tag = value.strip()
            if not tag:
                continue
            if len(tag) > 40:
                raise ValueError("Cada tag pode ter no máximo 40 caracteres.")
            key = tag.casefold()
            if key not in seen:
                normalized.append(tag)
                seen.add(key)
        return normalized


class AssetContextOption(BaseModel):
    id: UUID
    name: str
    email: str
    role: UserRole


class AssetContextOptions(BaseModel):
    owners: list[AssetContextOption]


class AssetVulnerabilityItem(BaseModel):
    id: int
    title: str
    severity: Severity
    status: WorkflowStatus
    cvss: float | None
    neo_score: int
    priority: Priority
    protocol: str
    port: int
    service: str | None
    cves: list[str]


class AssetServiceItem(BaseModel):
    protocol: str
    port: int
    service: str | None
    vulnerabilities: int
    highest_severity: Severity
    risk_score: int
    observed_at: datetime | None


class AssetScanHistoryItem(BaseModel):
    scan_id: int
    name: str
    scanner: str
    observed_at: datetime
    credentialed: bool
    operating_system: str | None
    vulnerabilities: int
    critical: int
    high: int
    risk_score: int


class AssetDetail(AssetListItem):
    facts: AssetFacts
    coverage: AssetScanCoverage
    inventory: AssetInventorySummary
    changes: AssetChangeSummary
    business_context: AssetBusinessContext
    services: list[AssetServiceItem]
    vulnerabilities_list: list[AssetVulnerabilityItem]
    scan_history: list[AssetScanHistoryItem]


@router.get("", response_model=AssetListResponse)
async def list_assets(
    current_user: CurrentUserDep,
    session: SessionDep,
) -> AssetListResponse:
    rows = await _get_asset_rows(session=session, client_id=current_user.client_id)
    items = [_asset_list_item(row) for row in rows]
    return AssetListResponse(
        items=items,
        summary=AssetListSummary(
            total=len(items),
            critical_exposure=sum(item.critical > 0 for item in items),
            credentialed=sum(item.credentialed for item in items),
            uncredentialed=sum(not item.credentialed for item in items),
            clean=sum(item.vulnerabilities == 0 for item in items),
            critical_business_assets=sum(
                item.business_criticality == "critica" for item in items
            ),
            critical_business_exposure=sum(
                item.business_criticality == "critica" and item.vulnerabilities > 0
                for item in items
            ),
            production_uncredentialed=sum(
                item.environment == "producao" and not item.credentialed
                for item in items
            ),
            without_owner=sum(item.business_owner_name is None for item in items),
        ),
    )


@router.get("/context-options", response_model=AssetContextOptions)
async def get_asset_context_options(
    current_user: CurrentUserDep,
    session: SessionDep,
) -> AssetContextOptions:
    result = await session.execute(
        text(
            """
            SELECT
                user_account.id,
                user_account.nome,
                user_account.email,
                membership.papel
            FROM app.usuario_cliente membership
            JOIN app.usuario user_account ON user_account.id = membership.usuario_id
            WHERE membership.cliente_id = :client_id
              AND membership.ativo = true
              AND user_account.ativo = true
            ORDER BY user_account.nome, user_account.email
            """
        ),
        {"client_id": current_user.client_id},
    )
    return AssetContextOptions(
        owners=[
            AssetContextOption(
                id=row["id"],
                name=row["nome"],
                email=row["email"],
                role=row["papel"],
            )
            for row in result.mappings().all()
        ]
    )


@router.get("/{asset_id}", response_model=AssetDetail)
async def get_asset(
    asset_id: int,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> AssetDetail:
    rows = await _get_asset_rows(
        session=session,
        client_id=current_user.client_id,
        asset_id=asset_id,
    )
    if not rows:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail="Ativo não encontrado no inventário atual.",
        )

    row = rows[0]
    item = _asset_list_item(row)
    vulnerabilities = await _get_asset_vulnerabilities(
        session=session,
        client_id=current_user.client_id,
        asset_id=asset_id,
    )
    services = await _get_asset_services(
        session=session,
        client_id=current_user.client_id,
        asset_id=asset_id,
    )
    history = await _get_asset_history(
        session=session,
        client_id=current_user.client_id,
        asset_id=asset_id,
    )
    inventory_history = await _get_asset_inventory_history(
        session=session,
        client_id=current_user.client_id,
        asset_id=asset_id,
    )
    changes = await _get_asset_changes(
        session=session,
        client_id=current_user.client_id,
        asset_id=asset_id,
    )
    business_context_row = await _get_asset_business_context_row(
        session=session,
        client_id=current_user.client_id,
        asset_id=asset_id,
    )
    scan_started_at = row["scan_iniciado_em"]
    scan_ended_at = row["scan_concluido_em"]
    duration_seconds = None
    if scan_started_at is not None and scan_ended_at is not None:
        duration_seconds = max(int((scan_ended_at - scan_started_at).total_seconds()), 0)
    metadata = row["metadados"] or {}
    return AssetDetail(
        **item.model_dump(),
        facts=AssetFacts(
            netbios=row["netbios"],
            mac=row["mac"],
            system_type=row["tipo_sistema"],
            bios_uuid=row["bios_uuid"],
            cpes=list(row["cpes"] or []),
            operating_system_confidence=row["confianca_sistema"],
            operating_system_method=row["metodo_sistema"],
        ),
        coverage=AssetScanCoverage(
            credentialed=row["credenciado"],
            local_checks_protocol=row["protocolo_verificacao_local"],
            scan_started_at=scan_started_at,
            scan_ended_at=scan_ended_at,
            duration_seconds=duration_seconds,
            last_authenticated_results_at=row["ultimo_resultado_autenticado_em"],
            last_unauthenticated_results_at=row[
                "ultimo_resultado_nao_autenticado_em"
            ],
            policy_used=metadata.get("policy_used"),
        ),
        inventory=AssetInventorySummary(
            first_seen=inventory_history["first_seen"],
            last_seen=inventory_history["last_seen"],
            scans_observed=inventory_history["scans_observed"],
            observed_services=sum(service.observed_at is not None for service in services),
            services_with_findings=sum(service.vulnerabilities > 0 for service in services),
            patch_summary_total_cves=row["total_cves_patches"],
        ),
        changes=changes,
        business_context=_asset_business_context(
            business_context_row,
            can_edit=current_user.role in BUSINESS_CONTEXT_EDIT_ROLES,
        ),
        services=services,
        vulnerabilities_list=vulnerabilities,
        scan_history=history,
    )


@router.patch("/{asset_id}/business-context", response_model=AssetBusinessContext)
async def update_asset_business_context(
    asset_id: int,
    payload: AssetBusinessContextUpdate,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> AssetBusinessContext:
    require_role(
        current_user,
        BUSINESS_CONTEXT_EDIT_ROLES,
        detail="Somente administradores e gestores alteram o contexto de negócio.",
    )
    host_result = await session.execute(
        text(
            """
            SELECT id
            FROM vm.host
            WHERE id = :asset_id AND cliente_id = :client_id
            """
        ),
        {"asset_id": asset_id, "client_id": current_user.client_id},
    )
    if host_result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail="Ativo não encontrado.",
        )

    previous = await _get_asset_business_context_row(
        session=session,
        client_id=current_user.client_id,
        asset_id=asset_id,
    )
    previous_owner_id = previous["responsavel_id"] if previous is not None else None
    if payload.owner_id is not None and payload.owner_id != previous_owner_id:
        owner_result = await session.execute(
            text(
                """
                SELECT 1
                FROM app.usuario_cliente membership
                JOIN app.usuario user_account
                  ON user_account.id = membership.usuario_id
                 AND user_account.ativo = true
                WHERE membership.cliente_id = :client_id
                  AND membership.usuario_id = :owner_id
                  AND membership.ativo = true
                """
            ),
            {"client_id": current_user.client_id, "owner_id": payload.owner_id},
        )
        if owner_result.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="O responsável precisa possuir acesso ativo a este ambiente.",
            )

    previous_audit_values = _business_context_audit_values(previous)
    next_values = {
        **previous_audit_values,
        **payload.model_dump(exclude_unset=True),
    }
    current_audit_values = {
        key: str(value) if isinstance(value, UUID) else value
        for key, value in next_values.items()
    }
    if current_audit_values == previous_audit_values:
        return _asset_business_context(previous, can_edit=True)

    await session.execute(
        text(
            """
            INSERT INTO app.ativo_contexto (
                cliente_id,
                host_id,
                ambiente,
                criticidade_negocio,
                responsavel_id,
                equipe_responsavel,
                servico_negocio,
                unidade_negocio,
                exposto_internet,
                janela_manutencao,
                tags,
                observacoes,
                atualizado_por
            )
            VALUES (
                :client_id,
                :asset_id,
                :environment,
                :business_criticality,
                :owner_id,
                :responsible_team,
                :business_service,
                :business_unit,
                :internet_exposed,
                :maintenance_window,
                CAST(:tags AS text[]),
                :notes,
                :actor_id
            )
            ON CONFLICT (cliente_id, host_id)
            DO UPDATE SET
                ambiente = EXCLUDED.ambiente,
                criticidade_negocio = EXCLUDED.criticidade_negocio,
                responsavel_id = EXCLUDED.responsavel_id,
                equipe_responsavel = EXCLUDED.equipe_responsavel,
                servico_negocio = EXCLUDED.servico_negocio,
                unidade_negocio = EXCLUDED.unidade_negocio,
                exposto_internet = EXCLUDED.exposto_internet,
                janela_manutencao = EXCLUDED.janela_manutencao,
                tags = EXCLUDED.tags,
                observacoes = EXCLUDED.observacoes,
                atualizado_por = EXCLUDED.atualizado_por,
                atualizado_em = now()
            """
        ),
        {
            "client_id": current_user.client_id,
            "asset_id": asset_id,
            "actor_id": current_user.id,
            **next_values,
        },
    )
    await _audit_asset_context_change(
        session=session,
        client_id=current_user.client_id,
        actor_id=current_user.id,
        asset_id=asset_id,
        previous=previous_audit_values,
        current=current_audit_values,
    )
    await session.commit()
    updated = await _get_asset_business_context_row(
        session=session,
        client_id=current_user.client_id,
        asset_id=asset_id,
    )
    return _asset_business_context(updated, can_edit=True)


async def _get_asset_rows(
    *,
    session: AsyncSession,
    client_id: int,
    asset_id: int | None = None,
):
    result = await session.execute(
        text(
            f"""
            WITH current_hosts AS (
                SELECT DISTINCT scan_host.host_id
                FROM vm.vw_scan_mais_recente recent_scan
                JOIN vm.scan_host scan_host ON scan_host.scan_id = recent_scan.id
                WHERE recent_scan.cliente_id = :client_id
            ),
            asset_snapshots AS (
                SELECT
                    host.id AS host_id,
                    host.endereco,
                    snapshot.fqdn,
                    snapshot.netbios,
                    snapshot.sistema_operacional,
                    snapshot.mac,
                    snapshot.tipo_sistema,
                    snapshot.credenciado,
                    snapshot.observado_em,
                    snapshot.bios_uuid,
                    snapshot.cpes,
                    snapshot.confianca_sistema,
                    snapshot.metodo_sistema,
                    snapshot.protocolo_verificacao_local,
                    snapshot.scan_iniciado_em,
                    snapshot.scan_concluido_em,
                    snapshot.ultimo_resultado_autenticado_em,
                    snapshot.ultimo_resultado_nao_autenticado_em,
                    snapshot.total_cves_patches,
                    snapshot.metadados,
                    business_context.ambiente,
                    business_context.criticidade_negocio,
                    business_owner.nome AS responsavel_nome,
                    business_context.equipe_responsavel,
                    business_context.servico_negocio,
                    business_context.exposto_internet
                FROM current_hosts
                JOIN vm.host host
                  ON host.id = current_hosts.host_id
                 AND host.cliente_id = :client_id
                JOIN LATERAL (
                    SELECT
                        scan_host.fqdn,
                        scan_host.netbios,
                        scan_host.sistema_operacional,
                        scan_host.mac,
                        scan_host.tipo_sistema,
                        scan_host.credenciado,
                        scan_host.bios_uuid,
                        scan_host.cpes,
                        scan_host.confianca_sistema,
                        scan_host.metodo_sistema,
                        scan_host.protocolo_verificacao_local,
                        scan_host.scan_iniciado_em,
                        scan_host.scan_concluido_em,
                        scan_host.ultimo_resultado_autenticado_em,
                        scan_host.ultimo_resultado_nao_autenticado_em,
                        scan_host.total_cves_patches,
                        scan_host.metadados,
                        coalesce(
                            scan_host.observado_em,
                            scan.concluido_em,
                            scan.importado_em
                        ) AS observado_em
                    FROM vm.scan_host scan_host
                    JOIN vm.scan scan ON scan.id = scan_host.scan_id
                    WHERE scan_host.host_id = host.id
                      AND scan.cliente_id = :client_id
                      AND scan.status = 'concluido'
                    ORDER BY
                        coalesce(scan.concluido_em, scan.importado_em) DESC,
                        scan.id DESC
                    LIMIT 1
                ) snapshot ON true
                LEFT JOIN app.ativo_contexto business_context
                  ON business_context.host_id = host.id
                 AND business_context.cliente_id = :client_id
                LEFT JOIN app.usuario business_owner
                  ON business_owner.id = business_context.responsavel_id
                WHERE CAST(:asset_id AS bigint) IS NULL
                   OR host.id = CAST(:asset_id AS bigint)
            ),
            active_findings AS (
                SELECT
                    workflow.host_id,
                    finding.severidade,
                    finding.cvss2,
                    finding.cvss3,
                    finding.cvss4,
                    finding.epss,
                    finding.exploravel,
                    finding.vpr
                FROM app.vulnerabilidade_tratamento workflow
                JOIN vm.vw_achado finding ON finding.id = workflow.ultimo_achado_id
                WHERE workflow.cliente_id = :client_id
                  AND workflow.status IN ({ACTIVE_WORKFLOW_STATUSES})
                  AND (
                      CAST(:asset_id AS bigint) IS NULL
                      OR workflow.host_id = CAST(:asset_id AS bigint)
                  )
            ),
            scored_findings AS (
                SELECT active_findings.*, ({NEO_SCORE_SQL}) AS neo_score
                FROM active_findings
            )
            SELECT
                snapshot.*,
                count(finding.host_id)::integer AS vulnerabilidades,
                count(*) FILTER (WHERE finding.severidade = 4)::integer AS criticas,
                count(*) FILTER (WHERE finding.severidade = 3)::integer AS altas,
                count(*) FILTER (WHERE finding.severidade = 2)::integer AS medias,
                count(*) FILTER (WHERE finding.severidade = 1)::integer AS baixas,
                coalesce(max(finding.neo_score), 0)::integer AS risco
            FROM asset_snapshots snapshot
            LEFT JOIN scored_findings finding ON finding.host_id = snapshot.host_id
            GROUP BY
                snapshot.host_id,
                snapshot.endereco,
                snapshot.fqdn,
                snapshot.netbios,
                snapshot.sistema_operacional,
                snapshot.mac,
                snapshot.tipo_sistema,
                snapshot.credenciado,
                snapshot.observado_em,
                snapshot.bios_uuid,
                snapshot.cpes,
                snapshot.confianca_sistema,
                snapshot.metodo_sistema,
                snapshot.protocolo_verificacao_local,
                snapshot.scan_iniciado_em,
                snapshot.scan_concluido_em,
                snapshot.ultimo_resultado_autenticado_em,
                snapshot.ultimo_resultado_nao_autenticado_em,
                snapshot.total_cves_patches,
                snapshot.metadados,
                snapshot.ambiente,
                snapshot.criticidade_negocio,
                snapshot.responsavel_nome,
                snapshot.equipe_responsavel,
                snapshot.servico_negocio,
                snapshot.exposto_internet
            ORDER BY risco DESC, criticas DESC, altas DESC, snapshot.endereco
            """
        ),
        {"client_id": client_id, "asset_id": asset_id},
    )
    return result.mappings().all()


async def _get_asset_vulnerabilities(
    *,
    session: AsyncSession,
    client_id: int,
    asset_id: int,
) -> list[AssetVulnerabilityItem]:
    result = await session.execute(
        text(
            f"""
            WITH selected AS (
                SELECT
                    finding.id,
                    finding.titulo,
                    finding.severidade,
                    workflow.status,
                    coalesce(finding.cvss4, finding.cvss3, finding.cvss2) AS cvss,
                    finding.cvss2,
                    finding.cvss3,
                    finding.cvss4,
                    finding.epss,
                    finding.exploravel,
                    finding.vpr,
                    finding.protocolo,
                    finding.porta,
                    finding.servico,
                    finding.cves
                FROM app.vulnerabilidade_tratamento workflow
                JOIN vm.vw_achado finding ON finding.id = workflow.ultimo_achado_id
                WHERE workflow.cliente_id = :client_id
                  AND workflow.host_id = :asset_id
                  AND workflow.status IN ({ACTIVE_WORKFLOW_STATUSES})
            )
            SELECT selected.*, ({NEO_SCORE_SQL}) AS neo_score
            FROM selected
            ORDER BY neo_score DESC, severidade DESC, titulo
            """
        ),
        {"client_id": client_id, "asset_id": asset_id},
    )
    return [
        AssetVulnerabilityItem(
            id=row["id"],
            title=row["titulo"],
            severity=_number_to_severity(row["severidade"]),
            status=row["status"],
            cvss=float(row["cvss"]) if row["cvss"] is not None else None,
            neo_score=row["neo_score"],
            priority=priority_for_score(row["neo_score"]),
            protocol=row["protocolo"],
            port=row["porta"],
            service=row["servico"],
            cves=list(row["cves"] or []),
        )
        for row in result.mappings().all()
    ]


async def _get_asset_services(
    *,
    session: AsyncSession,
    client_id: int,
    asset_id: int,
) -> list[AssetServiceItem]:
    result = await session.execute(
        text(
            f"""
            WITH latest_scan AS (
                SELECT
                    scan.id,
                    coalesce(
                        scan_host.observado_em,
                        scan.concluido_em,
                        scan.importado_em
                    ) AS observado_em
                FROM vm.scan scan
                JOIN vm.scan_host scan_host
                  ON scan_host.scan_id = scan.id
                 AND scan_host.host_id = :asset_id
                WHERE scan.cliente_id = :client_id
                  AND scan.status = 'concluido'
                ORDER BY
                    coalesce(scan.concluido_em, scan.importado_em) DESC,
                    scan.id DESC
                LIMIT 1
            ),
            observed_services AS (
                SELECT
                    service.protocolo,
                    service.porta,
                    service.servico,
                    service.observado_em
                FROM latest_scan
                JOIN vm.scan_servico service
                  ON service.scan_id = latest_scan.id
                 AND service.host_id = :asset_id
            ),
            selected_findings AS (
                SELECT
                    finding.protocolo,
                    finding.porta,
                    finding.servico,
                    finding.severidade,
                    finding.cvss2,
                    finding.cvss3,
                    finding.cvss4,
                    finding.epss,
                    finding.exploravel,
                    finding.vpr
                FROM app.vulnerabilidade_tratamento workflow
                JOIN vm.vw_achado finding ON finding.id = workflow.ultimo_achado_id
                WHERE workflow.cliente_id = :client_id
                  AND workflow.host_id = :asset_id
                  AND workflow.status IN ({ACTIVE_WORKFLOW_STATUSES})
            ),
            scored AS (
                SELECT selected_findings.*, ({NEO_SCORE_SQL}) AS neo_score
                FROM selected_findings
            ),
            vulnerable_services AS (
                SELECT
                    protocolo,
                    porta,
                    max(servico) AS servico,
                    count(*)::integer AS vulnerabilidades,
                    max(severidade)::integer AS maior_severidade,
                    max(neo_score)::integer AS risco
                FROM scored
                GROUP BY protocolo, porta
            ),
            service_keys AS (
                SELECT protocolo, porta FROM observed_services
                UNION
                SELECT protocolo, porta FROM vulnerable_services
            )
            SELECT
                service_keys.protocolo,
                service_keys.porta,
                coalesce(observed.servico, vulnerable.servico) AS servico,
                coalesce(vulnerable.vulnerabilidades, 0)::integer AS vulnerabilidades,
                coalesce(vulnerable.maior_severidade, 0)::integer AS maior_severidade,
                coalesce(vulnerable.risco, 0)::integer AS risco,
                observed.observado_em
            FROM service_keys
            LEFT JOIN observed_services observed
              ON observed.protocolo = service_keys.protocolo
             AND observed.porta = service_keys.porta
            LEFT JOIN vulnerable_services vulnerable
              ON vulnerable.protocolo = service_keys.protocolo
             AND vulnerable.porta = service_keys.porta
            ORDER BY risco DESC, maior_severidade DESC, porta
            """
        ),
        {"client_id": client_id, "asset_id": asset_id},
    )
    return [
        AssetServiceItem(
            protocol=row["protocolo"],
            port=row["porta"],
            service=row["servico"],
            vulnerabilities=row["vulnerabilidades"],
            highest_severity=_number_to_severity(row["maior_severidade"]),
            risk_score=row["risco"],
            observed_at=row["observado_em"],
        )
        for row in result.mappings().all()
    ]


async def _get_asset_inventory_history(
    *,
    session: AsyncSession,
    client_id: int,
    asset_id: int,
):
    result = await session.execute(
        text(
            """
            SELECT
                min(coalesce(
                    scan_host.observado_em,
                    scan.concluido_em,
                    scan.importado_em
                )) AS first_seen,
                max(coalesce(
                    scan_host.observado_em,
                    scan.concluido_em,
                    scan.importado_em
                )) AS last_seen,
                count(DISTINCT scan.id)::integer AS scans_observed
            FROM vm.scan scan
            JOIN vm.scan_host scan_host
              ON scan_host.scan_id = scan.id
             AND scan_host.host_id = :asset_id
            WHERE scan.cliente_id = :client_id
              AND scan.status = 'concluido'
            """
        ),
        {"client_id": client_id, "asset_id": asset_id},
    )
    return result.mappings().one()


async def _get_asset_changes(
    *,
    session: AsyncSession,
    client_id: int,
    asset_id: int,
) -> AssetChangeSummary:
    scan_result = await session.execute(
        text(
            """
            WITH current_scan AS (
                SELECT
                    scan.id,
                    scan.nome,
                    scan.escopo_chave,
                    coalesce(scan.concluido_em, scan.importado_em) AS observado_em,
                    scan_host.sistema_operacional,
                    scan_host.credenciado
                FROM vm.scan scan
                JOIN vm.scan_host scan_host
                  ON scan_host.scan_id = scan.id
                 AND scan_host.host_id = :asset_id
                WHERE scan.cliente_id = :client_id
                  AND scan.status = 'concluido'
                ORDER BY
                    coalesce(scan.concluido_em, scan.importado_em) DESC,
                    scan.id DESC
                LIMIT 1
            ),
            previous_scan AS (
                SELECT
                    scan.id,
                    scan.nome,
                    coalesce(scan.concluido_em, scan.importado_em) AS observado_em,
                    scan_host.sistema_operacional,
                    scan_host.credenciado
                FROM current_scan current
                JOIN vm.scan scan
                  ON scan.cliente_id = :client_id
                 AND scan.escopo_chave = current.escopo_chave
                 AND scan.status = 'concluido'
                 AND (
                     coalesce(scan.concluido_em, scan.importado_em),
                     scan.id
                 ) < (current.observado_em, current.id)
                JOIN vm.scan_host scan_host
                  ON scan_host.scan_id = scan.id
                 AND scan_host.host_id = :asset_id
                ORDER BY
                    coalesce(scan.concluido_em, scan.importado_em) DESC,
                    scan.id DESC
                LIMIT 1
            )
            SELECT
                current.id AS current_id,
                current.sistema_operacional AS current_os,
                current.credenciado AS current_credentialed,
                previous.id AS previous_id,
                previous.nome AS previous_name,
                previous.observado_em AS previous_at,
                previous.sistema_operacional AS previous_os,
                previous.credenciado AS previous_credentialed
            FROM current_scan current
            LEFT JOIN previous_scan previous ON true
            """
        ),
        {"client_id": client_id, "asset_id": asset_id},
    )
    scan_row = scan_result.mappings().one()
    previous_scan_id = scan_row["previous_id"]
    if previous_scan_id is None:
        return _empty_asset_changes()

    current_scan_id = scan_row["current_id"]
    finding_result = await session.execute(
        text(
            f"""
            WITH selected AS (
                SELECT
                    finding.scan_id,
                    finding.plugin_id,
                    finding.protocolo,
                    finding.porta,
                    finding.cvss2,
                    finding.cvss3,
                    finding.cvss4,
                    finding.epss,
                    finding.exploravel,
                    finding.vpr,
                    finding.severidade
                FROM vm.achado finding
                WHERE finding.host_id = :asset_id
                  AND finding.severidade > 0
                  AND finding.scan_id IN (:current_scan_id, :previous_scan_id)
            )
            SELECT selected.*, ({NEO_SCORE_SQL}) AS neo_score
            FROM selected
            """
        ),
        {
            "asset_id": asset_id,
            "current_scan_id": current_scan_id,
            "previous_scan_id": previous_scan_id,
        },
    )
    findings = finding_result.mappings().all()
    current_findings = {
        (row["plugin_id"], row["protocolo"], row["porta"])
        for row in findings
        if row["scan_id"] == current_scan_id
    }
    previous_findings = {
        (row["plugin_id"], row["protocolo"], row["porta"])
        for row in findings
        if row["scan_id"] == previous_scan_id
    }
    current_risk = max(
        (row["neo_score"] for row in findings if row["scan_id"] == current_scan_id),
        default=0,
    )
    previous_risk = max(
        (row["neo_score"] for row in findings if row["scan_id"] == previous_scan_id),
        default=0,
    )

    service_result = await session.execute(
        text(
            """
            SELECT scan_id, protocolo, porta, servico
            FROM vm.scan_servico
            WHERE host_id = :asset_id
              AND scan_id IN (:current_scan_id, :previous_scan_id)
            """
        ),
        {
            "asset_id": asset_id,
            "current_scan_id": current_scan_id,
            "previous_scan_id": previous_scan_id,
        },
    )
    current_services: dict[tuple[str, int], str | None] = {}
    previous_services: dict[tuple[str, int], str | None] = {}
    for service in service_result.mappings().all():
        target = (
            current_services
            if service["scan_id"] == current_scan_id
            else previous_services
        )
        target[(service["protocolo"], service["porta"])] = service["servico"]

    reopened_result = await session.execute(
        text(
            """
            SELECT count(*)::integer
            FROM app.vulnerabilidade_tratamento
            WHERE cliente_id = :client_id
              AND host_id = :asset_id
              AND status = 'reopened'
              AND ultimo_scan_id = :current_scan_id
            """
        ),
        {
            "client_id": client_id,
            "asset_id": asset_id,
            "current_scan_id": current_scan_id,
        },
    )
    ports_added = current_services.keys() - previous_services.keys()
    ports_removed = previous_services.keys() - current_services.keys()
    return AssetChangeSummary(
        available=True,
        previous_scan_name=scan_row["previous_name"],
        previous_scan_at=scan_row["previous_at"],
        new_findings=len(current_findings - previous_findings),
        corrected_findings=len(previous_findings - current_findings),
        persistent_findings=len(current_findings & previous_findings),
        reopened_findings=reopened_result.scalar_one(),
        vulnerability_delta=len(current_findings) - len(previous_findings),
        risk_delta=current_risk - previous_risk,
        ports_added=[
            _asset_service_reference(key, current_services[key])
            for key in sorted(ports_added)
        ],
        ports_removed=[
            _asset_service_reference(key, previous_services[key])
            for key in sorted(ports_removed)
        ],
        operating_system_changed=(
            scan_row["current_os"] != scan_row["previous_os"]
        ),
        credentialed_changed=(
            scan_row["current_credentialed"] != scan_row["previous_credentialed"]
        ),
    )


def _asset_service_reference(
    key: tuple[str, int],
    service: str | None,
) -> AssetServiceReference:
    return AssetServiceReference(protocol=key[0], port=key[1], service=service)


def _empty_asset_changes() -> AssetChangeSummary:
    return AssetChangeSummary(
        available=False,
        previous_scan_name=None,
        previous_scan_at=None,
        new_findings=0,
        corrected_findings=0,
        persistent_findings=0,
        reopened_findings=0,
        vulnerability_delta=0,
        risk_delta=0,
        ports_added=[],
        ports_removed=[],
        operating_system_changed=False,
        credentialed_changed=False,
    )


async def _get_asset_history(
    *,
    session: AsyncSession,
    client_id: int,
    asset_id: int,
) -> list[AssetScanHistoryItem]:
    result = await session.execute(
        text(
            f"""
            WITH historical_findings AS (
                SELECT
                    scan.id AS scan_id,
                    scan.nome,
                    scan.scanner,
                    scan_host.credenciado,
                    scan_host.sistema_operacional,
                    coalesce(
                        scan_host.observado_em,
                        scan.concluido_em,
                        scan.importado_em
                    ) AS observado_em,
                    finding.id AS finding_id,
                    finding.severidade,
                    finding.cvss2,
                    finding.cvss3,
                    finding.cvss4,
                    finding.epss,
                    finding.exploravel,
                    finding.vpr
                FROM vm.scan scan
                JOIN vm.scan_host scan_host
                  ON scan_host.scan_id = scan.id
                 AND scan_host.host_id = :asset_id
                LEFT JOIN vm.achado finding
                  ON finding.scan_id = scan.id
                 AND finding.host_id = scan_host.host_id
                 AND finding.severidade > 0
                WHERE scan.cliente_id = :client_id
                  AND scan.status = 'concluido'
            ),
            scored AS (
                SELECT historical_findings.*, ({NEO_SCORE_SQL}) AS neo_score
                FROM historical_findings
            )
            SELECT
                scan_id,
                nome,
                scanner,
                credenciado,
                sistema_operacional,
                observado_em,
                count(finding_id)::integer AS vulnerabilidades,
                count(*) FILTER (WHERE severidade = 4)::integer AS criticas,
                count(*) FILTER (WHERE severidade = 3)::integer AS altas,
                coalesce(max(neo_score), 0)::integer AS risco
            FROM scored
            GROUP BY
                scan_id,
                nome,
                scanner,
                credenciado,
                sistema_operacional,
                observado_em
            ORDER BY observado_em DESC, scan_id DESC
            LIMIT 20
            """
        ),
        {"client_id": client_id, "asset_id": asset_id},
    )
    return [
        AssetScanHistoryItem(
            scan_id=row["scan_id"],
            name=row["nome"],
            scanner=row["scanner"],
            observed_at=row["observado_em"],
            credentialed=row["credenciado"],
            operating_system=row["sistema_operacional"],
            vulnerabilities=row["vulnerabilidades"],
            critical=row["criticas"],
            high=row["altas"],
            risk_score=row["risco"],
        )
        for row in result.mappings().all()
    ]


async def _get_asset_business_context_row(
    *,
    session: AsyncSession,
    client_id: int,
    asset_id: int,
):
    result = await session.execute(
        text(
            """
            SELECT
                business_context.ambiente,
                business_context.criticidade_negocio,
                business_context.responsavel_id,
                business_owner.nome AS responsavel_nome,
                business_owner.email AS responsavel_email,
                business_context.equipe_responsavel,
                business_context.servico_negocio,
                business_context.unidade_negocio,
                business_context.exposto_internet,
                business_context.janela_manutencao,
                business_context.tags,
                business_context.observacoes,
                business_context.atualizado_em AS contexto_atualizado_em,
                business_updater.nome AS contexto_atualizado_por_nome
            FROM app.ativo_contexto business_context
            LEFT JOIN app.usuario business_owner
              ON business_owner.id = business_context.responsavel_id
            LEFT JOIN app.usuario business_updater
              ON business_updater.id = business_context.atualizado_por
            WHERE business_context.cliente_id = :client_id
              AND business_context.host_id = :asset_id
            """
        ),
        {"client_id": client_id, "asset_id": asset_id},
    )
    return result.mappings().one_or_none()


def _asset_business_context(row, *, can_edit: bool) -> AssetBusinessContext:
    if row is None:
        return AssetBusinessContext(
            environment=None,
            business_criticality=None,
            owner=None,
            responsible_team=None,
            business_service=None,
            business_unit=None,
            internet_exposed=None,
            maintenance_window=None,
            tags=[],
            notes=None,
            updated_at=None,
            updated_by_name=None,
            can_edit=can_edit,
        )
    owner = None
    if row["responsavel_id"] is not None:
        owner = AssetBusinessOwner(
            id=row["responsavel_id"],
            name=row["responsavel_nome"],
            email=row["responsavel_email"],
        )
    return AssetBusinessContext(
        environment=row["ambiente"],
        business_criticality=row["criticidade_negocio"],
        owner=owner,
        responsible_team=row["equipe_responsavel"],
        business_service=row["servico_negocio"],
        business_unit=row["unidade_negocio"],
        internet_exposed=row["exposto_internet"],
        maintenance_window=row["janela_manutencao"],
        tags=list(row["tags"] or []),
        notes=row["observacoes"],
        updated_at=row["contexto_atualizado_em"],
        updated_by_name=row["contexto_atualizado_por_nome"],
        can_edit=can_edit,
    )


def _business_context_audit_values(row) -> dict[str, object]:
    if row is None:
        return {
            "environment": None,
            "business_criticality": None,
            "owner_id": None,
            "responsible_team": None,
            "business_service": None,
            "business_unit": None,
            "internet_exposed": None,
            "maintenance_window": None,
            "tags": [],
            "notes": None,
        }
    return {
        "environment": row["ambiente"],
        "business_criticality": row["criticidade_negocio"],
        "owner_id": (
            str(row["responsavel_id"])
            if row["responsavel_id"] is not None
            else None
        ),
        "responsible_team": row["equipe_responsavel"],
        "business_service": row["servico_negocio"],
        "business_unit": row["unidade_negocio"],
        "internet_exposed": row["exposto_internet"],
        "maintenance_window": row["janela_manutencao"],
        "tags": list(row["tags"] or []),
        "notes": row["observacoes"],
    }


async def _audit_asset_context_change(
    *,
    session: AsyncSession,
    client_id: int,
    actor_id: UUID,
    asset_id: int,
    previous: dict[str, object],
    current: dict[str, object],
) -> None:
    changed_fields = sorted(
        key for key, value in current.items() if previous.get(key) != value
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
                :actor_id,
                'asset.business_context_updated',
                'asset_business_context',
                :asset_id,
                CAST(:details AS jsonb)
            )
            """
        ),
        {
            "client_id": client_id,
            "actor_id": actor_id,
            "asset_id": str(asset_id),
            "details": json.dumps(
                {
                    "changed_fields": changed_fields,
                    "before": previous,
                    "after": current,
                },
                ensure_ascii=False,
            ),
        },
    )


def _asset_list_item(row) -> AssetListItem:
    score = int(row["risco"])
    return AssetListItem(
        id=row["host_id"],
        name=row["fqdn"] or row["endereco"],
        address=row["endereco"],
        fqdn=row["fqdn"],
        operating_system=row["sistema_operacional"],
        credentialed=row["credenciado"],
        vulnerabilities=row["vulnerabilidades"],
        critical=row["criticas"],
        high=row["altas"],
        medium=row["medias"],
        low=row["baixas"],
        risk_score=score,
        priority=priority_for_score(score),
        last_seen=row["observado_em"],
        environment=row["ambiente"],
        business_criticality=row["criticidade_negocio"],
        business_owner_name=row["responsavel_nome"],
        responsible_team=row["equipe_responsavel"],
        business_service=row["servico_negocio"],
        internet_exposed=row["exposto_internet"],
    )


def _number_to_severity(value: int) -> Severity:
    return {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(value, "info")

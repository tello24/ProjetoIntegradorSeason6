import hashlib
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from fastapi import (
    APIRouter,
    BackgroundTasks,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from pydantic import BaseModel
from sqlalchemy import text

from app.api.dependencies import (
    SCAN_IMPORT_ROLES,
    CurrentUserDep,
    SessionDep,
    require_role,
)
from app.core.config import settings
from app.services.nessus.importer import process_import
from app.services.risk import NEO_SCORE_SQL
from app.services.scanners.registry import list_scanner_sources, resolve_scanner_adapter

router = APIRouter()


class ScanListItem(BaseModel):
    id: int
    name: str
    scanner: str
    status: str
    assets: int
    vulnerabilities: int
    imported_at: datetime
    scope_key: str


class ScanListResponse(BaseModel):
    items: list[ScanListItem]
    total: int
    can_import: bool


class ScannerSourceResponse(BaseModel):
    key: str
    display_name: str
    extensions: list[str]


class ImportAcceptedResponse(BaseModel):
    id: UUID
    status: str
    filename: str


class ImportStatusResponse(BaseModel):
    id: UUID
    scan_id: int | None
    filename: str
    status: str
    assets: int
    findings: int
    resolved: int
    reopened: int
    message: str | None
    started_at: datetime
    completed_at: datetime | None


ComparisonCategory = Literal["new", "resolved", "reopened", "persistent"]
SeverityName = Literal["critical", "high", "medium", "low"]


class ScanComparisonFinding(BaseModel):
    finding_id: int
    category: ComparisonCategory
    plugin_id: int
    title: str
    cves: list[str]
    asset: str
    address: str
    protocol: str
    port: int
    service: str | None
    severity: SeverityName
    severity_before: SeverityName | None
    severity_after: SeverityName | None
    cvss: float | None
    neo_score: int
    neo_score_before: int | None
    neo_score_after: int | None


class ScanSeverityComparison(BaseModel):
    severity: SeverityName
    new_findings: int
    reopened_findings: int
    resolved_findings: int
    persistent_findings: int


class ScanAssetChange(BaseModel):
    host_id: int
    asset: str
    address: str
    previous_findings: int
    current_findings: int
    previous_risk: int
    current_risk: int
    risk_delta: int
    direction: Literal["improved", "worsened", "stable"]


class ScanComparisonResponse(BaseModel):
    current_scan_id: int
    current_scan_name: str
    current_imported_at: datetime
    previous_scan_id: int | None
    previous_scan_name: str | None
    previous_imported_at: datetime | None
    current_findings: int
    previous_findings: int
    new_findings: int
    reopened_findings: int
    resolved_findings: int
    persistent_findings: int
    current_risk_score: int
    previous_risk_score: int
    risk_delta: int
    direction: Literal["baseline", "worsened", "improved", "stable"]
    assets_improved: int
    assets_worsened: int
    assets_stable: int
    severity_breakdown: list[ScanSeverityComparison]
    asset_changes: list[ScanAssetChange]
    items: list[ScanComparisonFinding]
    filtered_total: int
    page: int
    page_size: int


_COMPARISON_CTE = f"""
WITH current_items AS (
    SELECT
        finding.id AS finding_id,
        finding.host_id,
        host.endereco AS address,
        coalesce(scan_host.fqdn, host.endereco) AS asset,
        finding.plugin_id,
        plugin.nome AS title,
        ARRAY(
            SELECT plugin_cve.cve
            FROM vm.plugin_cve plugin_cve
            WHERE plugin_cve.plugin_id = finding.plugin_id
            ORDER BY plugin_cve.cve
        ) AS cves,
        finding.protocolo AS protocol,
        finding.porta AS port,
        finding.servico AS service,
        finding.severidade AS severity,
        coalesce(finding.cvss4, finding.cvss3, finding.cvss2) AS cvss,
        ({NEO_SCORE_SQL}) AS neo_score,
        CASE finding.severidade
            WHEN 4 THEN 10
            WHEN 3 THEN 5
            WHEN 2 THEN 2
            WHEN 1 THEN 1
            ELSE 0
        END AS risk_weight
    FROM vm.achado finding
    JOIN vm.host host ON host.id = finding.host_id
    JOIN vm.scan_host scan_host
      ON scan_host.scan_id = finding.scan_id
     AND scan_host.host_id = finding.host_id
    JOIN vm.plugin plugin ON plugin.plugin_id = finding.plugin_id
    WHERE finding.scan_id = :current_scan_id
      AND finding.severidade > 0
),
previous_items AS (
    SELECT
        finding.id AS finding_id,
        finding.host_id,
        host.endereco AS address,
        coalesce(scan_host.fqdn, host.endereco) AS asset,
        finding.plugin_id,
        plugin.nome AS title,
        ARRAY(
            SELECT plugin_cve.cve
            FROM vm.plugin_cve plugin_cve
            WHERE plugin_cve.plugin_id = finding.plugin_id
            ORDER BY plugin_cve.cve
        ) AS cves,
        finding.protocolo AS protocol,
        finding.porta AS port,
        finding.servico AS service,
        finding.severidade AS severity,
        coalesce(finding.cvss4, finding.cvss3, finding.cvss2) AS cvss,
        ({NEO_SCORE_SQL}) AS neo_score,
        CASE finding.severidade
            WHEN 4 THEN 10
            WHEN 3 THEN 5
            WHEN 2 THEN 2
            WHEN 1 THEN 1
            ELSE 0
        END AS risk_weight
    FROM vm.achado finding
    JOIN vm.host host ON host.id = finding.host_id
    JOIN vm.scan_host scan_host
      ON scan_host.scan_id = finding.scan_id
     AND scan_host.host_id = finding.host_id
    JOIN vm.plugin plugin ON plugin.plugin_id = finding.plugin_id
    WHERE finding.scan_id = :previous_scan_id
      AND finding.severidade > 0
),
historical_items AS (
    SELECT DISTINCT
        finding.host_id,
        finding.plugin_id,
        finding.protocolo AS protocol,
        finding.porta AS port
    FROM vm.scan historical_scan
    JOIN vm.achado finding ON finding.scan_id = historical_scan.id
    WHERE historical_scan.cliente_id = :client_id
      AND historical_scan.escopo_chave = :scope_key
      AND historical_scan.status = 'concluido'
      AND finding.severidade > 0
      AND :previous_scan_id IS NOT NULL
      AND (
          historical_scan.importado_em < CAST(:previous_imported_at AS timestamptz)
          OR (
              historical_scan.importado_em = CAST(:previous_imported_at AS timestamptz)
              AND historical_scan.id < :previous_scan_id
          )
      )
),
paired_items AS (
    SELECT
        current_item.finding_id AS current_finding_id,
        previous_item.finding_id AS previous_finding_id,
        coalesce(current_item.host_id, previous_item.host_id) AS host_id,
        coalesce(current_item.address, previous_item.address) AS address,
        coalesce(current_item.asset, previous_item.asset) AS asset,
        coalesce(current_item.plugin_id, previous_item.plugin_id) AS plugin_id,
        coalesce(current_item.title, previous_item.title) AS title,
        coalesce(current_item.cves, previous_item.cves, ARRAY[]::text[]) AS cves,
        coalesce(current_item.protocol, previous_item.protocol) AS protocol,
        coalesce(current_item.port, previous_item.port) AS port,
        coalesce(current_item.service, previous_item.service) AS service,
        previous_item.severity AS previous_severity,
        current_item.severity AS current_severity,
        coalesce(current_item.severity, previous_item.severity) AS severity,
        coalesce(current_item.cvss, previous_item.cvss) AS cvss,
        previous_item.neo_score AS previous_neo_score,
        current_item.neo_score AS current_neo_score,
        previous_item.risk_weight AS previous_risk_weight,
        current_item.risk_weight AS current_risk_weight
    FROM current_items current_item
    FULL OUTER JOIN previous_items previous_item
      ON previous_item.host_id = current_item.host_id
     AND previous_item.plugin_id = current_item.plugin_id
     AND previous_item.protocol = current_item.protocol
     AND previous_item.port = current_item.port
),
categorized AS (
    SELECT
        paired_item.*,
        CASE
            WHEN paired_item.current_finding_id IS NULL THEN 'resolved'
            WHEN paired_item.previous_finding_id IS NOT NULL THEN 'persistent'
            WHEN EXISTS (
                SELECT 1
                FROM historical_items historical_item
                WHERE historical_item.host_id = paired_item.host_id
                  AND historical_item.plugin_id = paired_item.plugin_id
                  AND historical_item.protocol = paired_item.protocol
                  AND historical_item.port = paired_item.port
            ) THEN 'reopened'
            ELSE 'new'
        END AS category
    FROM paired_items paired_item
)
"""


@router.get("", response_model=ScanListResponse)
async def list_scans(
    current_user: CurrentUserDep,
    session: SessionDep,
) -> ScanListResponse:
    result = await session.execute(
        text(
            """
            SELECT
                scan_list.id,
                scan_list.nome,
                scan_list.scanner,
                scan_list.status,
                scan_list.ativos,
                scan_list.vulnerabilidades,
                scan_list.importado_em,
                scan.escopo_chave
            FROM vm.vw_scan_lista scan_list
            JOIN vm.scan scan ON scan.id = scan_list.id
            WHERE scan_list.cliente_id = :client_id
            ORDER BY scan_list.importado_em DESC, scan_list.id DESC
            """
        ),
        {"client_id": current_user.client_id},
    )
    rows = result.mappings().all()
    items = [
        ScanListItem(
            id=row["id"],
            name=row["nome"],
            scanner=row["scanner"],
            status=row["status"],
            assets=row["ativos"],
            vulnerabilities=row["vulnerabilidades"],
            imported_at=row["importado_em"],
            scope_key=row["escopo_chave"],
        )
        for row in rows
    ]
    return ScanListResponse(
        items=items,
        total=len(items),
        can_import=current_user.role in SCAN_IMPORT_ROLES,
    )


@router.get("/sources", response_model=list[ScannerSourceResponse])
async def list_scan_sources(_: CurrentUserDep) -> list[ScannerSourceResponse]:
    return [
        ScannerSourceResponse(
            key=source.key,
            display_name=source.display_name,
            extensions=list(source.extensions),
        )
        for source in list_scanner_sources()
    ]


@router.post(
    "/import",
    response_model=ImportAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def import_scan(
    background_tasks: BackgroundTasks,
    file: Annotated[UploadFile, File()],
    current_user: CurrentUserDep,
    session: SessionDep,
) -> ImportAcceptedResponse:
    require_role(
        current_user,
        SCAN_IMPORT_ROLES,
        detail="Somente administradores e analistas podem importar scans.",
    )
    filename = Path(file.filename or "").name
    adapter = resolve_scanner_adapter(filename)
    if adapter is None:
        supported = ", ".join(
            extension
            for source in list_scanner_sources()
            for extension in source.extensions
        )
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Formato não suportado. Envie uma exportação: {supported}.",
        )

    temp_path, size, source_hash = await _save_upload(file, suffix=Path(filename).suffix.lower())
    try:
        result = await session.execute(
            text(
                """
                INSERT INTO vm.importacao (
                    cliente_id,
                    usuario_id,
                    arquivo,
                    tamanho_bytes,
                    status
                )
                VALUES (:client_id, :user_id, :filename, :size, 'recebido')
                RETURNING id
                """
            ),
            {
                "client_id": current_user.client_id,
                "user_id": current_user.id,
                "filename": filename,
                "size": size,
            },
        )
        import_id = result.scalar_one()
        await session.commit()
    except Exception:
        Path(temp_path).unlink(missing_ok=True)
        raise

    background_tasks.add_task(
        process_import,
        import_id=import_id,
        client_id=current_user.client_id,
        file_path=temp_path,
        original_filename=filename,
        source_hash=source_hash,
        scanner_key=adapter.key,
    )
    return ImportAcceptedResponse(id=import_id, status="recebido", filename=filename)


@router.get("/imports/{import_id}", response_model=ImportStatusResponse)
async def get_import_status(
    import_id: UUID,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> ImportStatusResponse:
    result = await session.execute(
        text(
            """
            SELECT
                id,
                scan_id,
                arquivo,
                status,
                linhas,
                achados,
                resolvidos,
                reabertos,
                mensagem,
                iniciado_em,
                concluido_em
            FROM vm.importacao
            WHERE id = :import_id AND cliente_id = :client_id
            """
        ),
        {"import_id": import_id, "client_id": current_user.client_id},
    )
    row = result.mappings().one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Importação não encontrada.",
        )
    return ImportStatusResponse(
        id=row["id"],
        scan_id=row["scan_id"],
        filename=row["arquivo"],
        status=row["status"],
        assets=row["linhas"],
        findings=row["achados"],
        resolved=row["resolvidos"],
        reopened=row["reabertos"],
        message=row["mensagem"],
        started_at=row["iniciado_em"],
        completed_at=row["concluido_em"],
    )


@router.get("/{scan_id}/comparison", response_model=ScanComparisonResponse)
async def compare_scan(
    scan_id: int,
    current_user: CurrentUserDep,
    session: SessionDep,
    baseline_scan_id: Annotated[int | None, Query(ge=1)] = None,
    category: ComparisonCategory | None = None,
    severity: SeverityName | None = None,
    search: Annotated[str | None, Query(max_length=120)] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=10, le=100)] = 50,
) -> ScanComparisonResponse:
    current_scan = await _get_completed_scan(
        session=session,
        scan_id=scan_id,
        client_id=current_user.client_id,
    )
    if current_scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan concluído não encontrado.",
        )

    if baseline_scan_id is None:
        baseline_scan = await _get_previous_scan(
            session=session,
            current_scan=current_scan,
        )
    else:
        baseline_scan = await _get_completed_scan(
            session=session,
            scan_id=baseline_scan_id,
            client_id=current_user.client_id,
        )
        if baseline_scan is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan-base concluído não encontrado.",
            )
        if baseline_scan["escopo_chave"] != current_scan["escopo_chave"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Os scans possuem coberturas diferentes. Escolha dois scans do mesmo escopo "
                    "para evitar considerar ativos não verificados como corrigidos."
                ),
            )
        if not _scan_is_before(baseline_scan, current_scan):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="O scan-base precisa ser anterior ao scan atual.",
            )

    parameters = {
        "current_scan_id": current_scan["id"],
        "previous_scan_id": baseline_scan["id"] if baseline_scan else None,
        "previous_imported_at": baseline_scan["importado_em"] if baseline_scan else None,
        "client_id": current_scan["cliente_id"],
        "scope_key": current_scan["escopo_chave"],
        "category": category,
        "severity": _severity_value(severity),
        "search": search.strip() if search and search.strip() else None,
        "search_pattern": f"%{search.strip()}%" if search and search.strip() else None,
        "limit": page_size,
        "offset": (page - 1) * page_size,
    }
    counts_result = await session.execute(
        text(
            _COMPARISON_CTE
            + """
            SELECT
                (SELECT count(*) FROM current_items)::integer AS current_findings,
                (SELECT count(*) FROM previous_items)::integer AS previous_findings,
                count(*) FILTER (WHERE category = 'new')::integer AS new_findings,
                count(*) FILTER (WHERE category = 'reopened')::integer AS reopened_findings,
                count(*) FILTER (WHERE category = 'resolved')::integer AS resolved_findings,
                count(*) FILTER (WHERE category = 'persistent')::integer AS persistent_findings,
                (
                    SELECT least(
                        100,
                        coalesce(
                            round(
                                sum(risk_weight)::numeric
                                / greatest(count(DISTINCT host_id), 1)
                            ),
                            0
                        )
                    )::integer
                    FROM current_items
                ) AS current_risk_score,
                (
                    SELECT least(
                        100,
                        coalesce(
                            round(
                                sum(risk_weight)::numeric
                                / greatest(count(DISTINCT host_id), 1)
                            ),
                            0
                        )
                    )::integer
                    FROM previous_items
                ) AS previous_risk_score,
                count(*) FILTER (
                    WHERE (
                          CAST(:category AS text) IS NULL
                          OR category = CAST(:category AS text)
                      )
                      AND (
                          CAST(:severity AS integer) IS NULL
                          OR severity = CAST(:severity AS integer)
                      )
                      AND (
                          CAST(:search AS text) IS NULL
                          OR title ILIKE :search_pattern
                          OR asset ILIKE :search_pattern
                          OR address ILIKE :search_pattern
                          OR plugin_id::text ILIKE :search_pattern
                          OR array_to_string(cves, ' ') ILIKE :search_pattern
                      )
                )::integer AS filtered_total
            FROM categorized
            """
        ),
        parameters,
    )
    counts = counts_result.mappings().one()

    severity_result = await session.execute(
        text(
            _COMPARISON_CTE
            + """
            SELECT
                severity,
                count(*) FILTER (WHERE category = 'new')::integer AS new_findings,
                count(*) FILTER (WHERE category = 'reopened')::integer AS reopened_findings,
                count(*) FILTER (WHERE category = 'resolved')::integer AS resolved_findings,
                count(*) FILTER (WHERE category = 'persistent')::integer AS persistent_findings
            FROM categorized
            GROUP BY severity
            ORDER BY severity DESC
            """
        ),
        parameters,
    )
    severity_rows = {row["severity"]: row for row in severity_result.mappings().all()}
    severity_breakdown = [
        ScanSeverityComparison(
            severity=severity_name,
            new_findings=severity_rows.get(severity_value, {}).get("new_findings", 0),
            reopened_findings=severity_rows.get(severity_value, {}).get(
                "reopened_findings", 0
            ),
            resolved_findings=severity_rows.get(severity_value, {}).get(
                "resolved_findings", 0
            ),
            persistent_findings=severity_rows.get(severity_value, {}).get(
                "persistent_findings", 0
            ),
        )
        for severity_name, severity_value in (
            ("critical", 4),
            ("high", 3),
            ("medium", 2),
            ("low", 1),
        )
    ]

    details_result = await session.execute(
        text(
            _COMPARISON_CTE
            + """
            SELECT
                coalesce(current_finding_id, previous_finding_id) AS finding_id,
                category,
                plugin_id,
                title,
                cves,
                asset,
                address,
                protocol,
                port,
                service,
                severity,
                previous_severity,
                current_severity,
                cvss,
                coalesce(current_neo_score, previous_neo_score) AS neo_score,
                previous_neo_score,
                current_neo_score
            FROM categorized
            WHERE (
                  CAST(:category AS text) IS NULL
                  OR category = CAST(:category AS text)
              )
              AND (
                  CAST(:severity AS integer) IS NULL
                  OR severity = CAST(:severity AS integer)
              )
              AND (
                  CAST(:search AS text) IS NULL
                  OR title ILIKE :search_pattern
                  OR asset ILIKE :search_pattern
                  OR address ILIKE :search_pattern
                  OR plugin_id::text ILIKE :search_pattern
                  OR array_to_string(cves, ' ') ILIKE :search_pattern
              )
            ORDER BY
                CASE category
                    WHEN 'reopened' THEN 1
                    WHEN 'new' THEN 2
                    WHEN 'resolved' THEN 3
                    ELSE 4
                END,
                severity DESC,
                coalesce(current_neo_score, previous_neo_score) DESC,
                title,
                asset
            LIMIT :limit OFFSET :offset
            """
        ),
        parameters,
    )
    items = [
        ScanComparisonFinding(
            finding_id=row["finding_id"],
            category=row["category"],
            plugin_id=row["plugin_id"],
            title=row["title"],
            cves=list(row["cves"] or []),
            asset=row["asset"],
            address=row["address"],
            protocol=row["protocol"],
            port=row["port"],
            service=row["service"],
            severity=_severity_name(row["severity"]),
            severity_before=_optional_severity_name(row["previous_severity"]),
            severity_after=_optional_severity_name(row["current_severity"]),
            cvss=float(row["cvss"]) if row["cvss"] is not None else None,
            neo_score=row["neo_score"],
            neo_score_before=row["previous_neo_score"],
            neo_score_after=row["current_neo_score"],
        )
        for row in details_result.mappings().all()
    ]

    asset_result = await session.execute(
        text(
            _COMPARISON_CTE
            + """
            , current_assets AS (
                SELECT
                    host_id,
                    max(asset) AS asset,
                    max(address) AS address,
                    count(*)::integer AS findings,
                    coalesce(sum(risk_weight), 0)::integer AS risk
                FROM current_items
                GROUP BY host_id
            ),
            previous_assets AS (
                SELECT
                    host_id,
                    max(asset) AS asset,
                    max(address) AS address,
                    count(*)::integer AS findings,
                    coalesce(sum(risk_weight), 0)::integer AS risk
                FROM previous_items
                GROUP BY host_id
            )
            SELECT
                coalesce(current_asset.host_id, previous_asset.host_id) AS host_id,
                coalesce(current_asset.asset, previous_asset.asset) AS asset,
                coalesce(current_asset.address, previous_asset.address) AS address,
                coalesce(previous_asset.findings, 0)::integer AS previous_findings,
                coalesce(current_asset.findings, 0)::integer AS current_findings,
                coalesce(previous_asset.risk, 0)::integer AS previous_risk,
                coalesce(current_asset.risk, 0)::integer AS current_risk
            FROM current_assets current_asset
            FULL OUTER JOIN previous_assets previous_asset
              ON previous_asset.host_id = current_asset.host_id
            """
        ),
        parameters,
    )
    all_asset_changes = [_asset_change(row) for row in asset_result.mappings().all()]
    all_asset_changes.sort(
        key=lambda asset: (
            -abs(asset.risk_delta),
            -abs(asset.current_findings - asset.previous_findings),
            asset.asset.lower(),
        )
    )
    assets_improved = sum(asset.direction == "improved" for asset in all_asset_changes)
    assets_worsened = sum(asset.direction == "worsened" for asset in all_asset_changes)
    assets_stable = sum(asset.direction == "stable" for asset in all_asset_changes)

    current_risk_score = counts["current_risk_score"]
    previous_risk_score = counts["previous_risk_score"]
    risk_delta = current_risk_score - previous_risk_score
    direction = _comparison_direction(
        has_baseline=baseline_scan is not None,
        risk_delta=risk_delta,
        new_findings=counts["new_findings"],
        resolved_findings=counts["resolved_findings"],
    )

    return ScanComparisonResponse(
        current_scan_id=current_scan["id"],
        current_scan_name=current_scan["nome"],
        current_imported_at=current_scan["importado_em"],
        previous_scan_id=baseline_scan["id"] if baseline_scan else None,
        previous_scan_name=baseline_scan["nome"] if baseline_scan else None,
        previous_imported_at=baseline_scan["importado_em"] if baseline_scan else None,
        current_findings=counts["current_findings"],
        previous_findings=counts["previous_findings"],
        new_findings=counts["new_findings"],
        reopened_findings=counts["reopened_findings"],
        resolved_findings=counts["resolved_findings"],
        persistent_findings=counts["persistent_findings"],
        current_risk_score=current_risk_score,
        previous_risk_score=previous_risk_score,
        risk_delta=risk_delta,
        direction=direction,
        assets_improved=assets_improved,
        assets_worsened=assets_worsened,
        assets_stable=assets_stable,
        severity_breakdown=severity_breakdown,
        asset_changes=all_asset_changes[:8],
        items=items,
        filtered_total=counts["filtered_total"],
        page=page,
        page_size=page_size,
    )


async def _get_completed_scan(*, session, scan_id: int, client_id: int):
    result = await session.execute(
        text(
            """
            SELECT id, cliente_id, escopo_chave, nome, importado_em
            FROM vm.scan
            WHERE id = :scan_id
              AND cliente_id = :client_id
              AND status = 'concluido'
            """
        ),
        {"scan_id": scan_id, "client_id": client_id},
    )
    return result.mappings().one_or_none()


async def _get_previous_scan(*, session, current_scan):
    result = await session.execute(
        text(
            """
            SELECT id, cliente_id, escopo_chave, nome, importado_em
            FROM vm.scan
            WHERE cliente_id = :client_id
              AND escopo_chave = :scope_key
              AND status = 'concluido'
              AND (
                  importado_em < :current_imported_at
                  OR (importado_em = :current_imported_at AND id < :current_scan_id)
              )
            ORDER BY importado_em DESC, id DESC
            LIMIT 1
            """
        ),
        {
            "client_id": current_scan["cliente_id"],
            "scope_key": current_scan["escopo_chave"],
            "current_imported_at": current_scan["importado_em"],
            "current_scan_id": current_scan["id"],
        },
    )
    return result.mappings().one_or_none()


def _scan_is_before(baseline_scan, current_scan) -> bool:
    return (baseline_scan["importado_em"], baseline_scan["id"]) < (
        current_scan["importado_em"],
        current_scan["id"],
    )


def _severity_value(severity: SeverityName | None) -> int | None:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity)


def _severity_name(value: int) -> SeverityName:
    return {4: "critical", 3: "high", 2: "medium", 1: "low"}[value]


def _optional_severity_name(value: int | None) -> SeverityName | None:
    return _severity_name(value) if value is not None else None


def _asset_change(row) -> ScanAssetChange:
    previous_risk = row["previous_risk"]
    current_risk = row["current_risk"]
    risk_delta = current_risk - previous_risk
    finding_delta = row["current_findings"] - row["previous_findings"]
    if risk_delta < 0 or (risk_delta == 0 and finding_delta < 0):
        direction = "improved"
    elif risk_delta > 0 or (risk_delta == 0 and finding_delta > 0):
        direction = "worsened"
    else:
        direction = "stable"
    return ScanAssetChange(
        host_id=row["host_id"],
        asset=row["asset"],
        address=row["address"],
        previous_findings=row["previous_findings"],
        current_findings=row["current_findings"],
        previous_risk=previous_risk,
        current_risk=current_risk,
        risk_delta=risk_delta,
        direction=direction,
    )


def _comparison_direction(
    *,
    has_baseline: bool,
    risk_delta: int,
    new_findings: int,
    resolved_findings: int,
) -> Literal["baseline", "worsened", "improved", "stable"]:
    if not has_baseline:
        return "baseline"
    if risk_delta > 0 or (risk_delta == 0 and new_findings > resolved_findings):
        return "worsened"
    if risk_delta < 0 or (risk_delta == 0 and resolved_findings > new_findings):
        return "improved"
    return "stable"


async def _save_upload(file: UploadFile, *, suffix: str) -> tuple[str, int, str]:
    max_bytes = settings.scan_upload_limit_mb * 1024 * 1024
    digest = hashlib.sha256()
    size = 0
    file_descriptor, temp_path = tempfile.mkstemp(prefix="ng-scan-", suffix=suffix)
    try:
        with os.fdopen(file_descriptor, "wb") as destination:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"O arquivo excede o limite de {settings.scan_upload_limit_mb} MB.",
                    )
                digest.update(chunk)
                destination.write(chunk)
        if size == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="O arquivo enviado está vazio.",
            )
        return temp_path, size, digest.hexdigest()
    except Exception:
        Path(temp_path).unlink(missing_ok=True)
        raise
    finally:
        await file.close()

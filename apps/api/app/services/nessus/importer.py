import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from uuid import UUID

from fastapi.concurrency import run_in_threadpool
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import session_factory
from app.services.scanners.base import ScanParseError
from app.services.scanners.models import ScanFinding, ScanParseResult
from app.services.scanners.registry import get_scanner_adapter
from app.services.vulnerability_lifecycle import sync_vulnerability_lifecycle


@dataclass(frozen=True, slots=True)
class ImportOutcome:
    scan_id: int
    assets: int
    findings: int
    resolved: int
    reopened: int


class ScanImporter:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def persist(
        self,
        *,
        parsed: ScanParseResult,
        client_id: int,
        source_hash: str,
        original_filename: str,
        scanner_key: str = "nessus",
    ) -> ImportOutcome:
        scope_key = _scope_key(parsed, scanner_key=scanner_key)
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
            {"lock_key": f"{client_id}:{scope_key}"},
        )

        existing_result = await self.session.execute(
            text(
                """
                SELECT
                    scan.id,
                    count(DISTINCT scan_host.host_id)::integer AS assets,
                    count(finding.id) FILTER (WHERE finding.severidade > 0)::integer AS findings
                FROM vm.scan scan
                LEFT JOIN vm.scan_host scan_host ON scan_host.scan_id = scan.id
                LEFT JOIN vm.achado finding
                  ON finding.scan_id = scan.id
                 AND finding.host_id = scan_host.host_id
                WHERE scan.cliente_id = :client_id
                  AND scan.chave_origem = :source_hash
                  AND scan.status = 'concluido'
                GROUP BY scan.id
                """
            ),
            {"client_id": client_id, "source_hash": source_hash},
        )
        existing = existing_result.mappings().one_or_none()
        if existing is not None:
            await self._persist_asset_inventory(
                scan_id=existing["id"],
                client_id=client_id,
                parsed=parsed,
            )
            return ImportOutcome(
                scan_id=existing["id"],
                assets=existing["assets"],
                findings=existing["findings"],
                resolved=0,
                reopened=0,
            )

        previous_result = await self.session.execute(
            text(
                """
                SELECT id
                FROM vm.scan
                WHERE cliente_id = :client_id
                  AND escopo_chave = :scope_key
                  AND status = 'concluido'
                ORDER BY importado_em DESC, id DESC
                LIMIT 1
                """
            ),
            {"client_id": client_id, "scope_key": scope_key},
        )
        previous_scan_id = previous_result.scalar_one_or_none()

        scan_result = await self.session.execute(
            text(
                """
                INSERT INTO vm.scan (
                    cliente_id,
                    nome,
                    scanner,
                    politica,
                    escopo_chave,
                    status,
                    chave_origem,
                    arquivo,
                    concluido_em
                )
                VALUES (
                    :client_id,
                    :name,
                    :scanner,
                    :policy,
                    :scope_key,
                    'processando',
                    :source_hash,
                    :filename,
                    now()
                )
                ON CONFLICT (cliente_id, chave_origem)
                DO UPDATE SET
                    nome = EXCLUDED.nome,
                    politica = EXCLUDED.politica,
                    escopo_chave = EXCLUDED.escopo_chave,
                    status = 'processando',
                    arquivo = EXCLUDED.arquivo,
                    importado_em = now()
                RETURNING id
                """
            ),
            {
                "client_id": client_id,
                "name": parsed.report_name,
                "policy": parsed.policy_name,
                "scope_key": scope_key,
                "source_hash": source_hash,
                "filename": original_filename,
                "scanner": scanner_key,
            },
        )
        scan_id = scan_result.scalar_one()

        # Rebuild only this idempotent scan inside the current transaction.
        await self.session.execute(
            text("DELETE FROM vm.achado WHERE scan_id = :scan_id"),
            {"scan_id": scan_id},
        )
        await self.session.execute(
            text("DELETE FROM vm.scan_host WHERE scan_id = :scan_id"),
            {"scan_id": scan_id},
        )

        host_ids = await self._persist_asset_inventory(
            scan_id=scan_id,
            client_id=client_id,
            parsed=parsed,
        )

        plugins = _unique_plugins(parsed.findings)
        for finding in plugins.values():
            await self._upsert_plugin(finding)

        for finding in parsed.findings:
            host_id = host_ids.get(finding.host_address)
            if host_id is None:
                continue
            await self._insert_finding(scan_id=scan_id, host_id=host_id, finding=finding)

        await self.session.execute(
            text(
                """
                UPDATE vm.scan
                SET status = 'concluido', concluido_em = now(), importado_em = now()
                WHERE id = :scan_id
                """
            ),
            {"scan_id": scan_id},
        )
        lifecycle = await sync_vulnerability_lifecycle(
            session=self.session,
            client_id=client_id,
            scan_id=scan_id,
            previous_scan_id=previous_scan_id,
        )
        return ImportOutcome(
            scan_id=scan_id,
            assets=len(parsed.hosts),
            findings=len(parsed.findings),
            resolved=lifecycle.resolved,
            reopened=lifecycle.reopened,
        )

    async def _persist_asset_inventory(
        self,
        *,
        scan_id: int,
        client_id: int,
        parsed: ScanParseResult,
    ) -> dict[str, int]:
        host_ids: dict[str, int] = {}
        observed_at_by_address = {host.address: host.scan_ended_at for host in parsed.hosts}
        for host in parsed.hosts:
            host_result = await self.session.execute(
                text(
                    """
                    INSERT INTO vm.host (cliente_id, endereco)
                    VALUES (:client_id, :address)
                    ON CONFLICT (cliente_id, endereco)
                    DO UPDATE SET atualizado_em = now()
                    RETURNING id
                    """
                ),
                {"client_id": client_id, "address": host.address},
            )
            host_id = host_result.scalar_one()
            host_ids[host.address] = host_id
            await self.session.execute(
                text(
                    """
                    INSERT INTO vm.scan_host (
                        scan_id,
                        host_id,
                        fqdn,
                        netbios,
                        sistema_operacional,
                        mac,
                        tipo_sistema,
                        credenciado,
                        observado_em,
                        bios_uuid,
                        cpes,
                        confianca_sistema,
                        metodo_sistema,
                        protocolo_verificacao_local,
                        scan_iniciado_em,
                        scan_concluido_em,
                        ultimo_resultado_autenticado_em,
                        ultimo_resultado_nao_autenticado_em,
                        total_cves_patches,
                        metadados
                    )
                    VALUES (
                        :scan_id,
                        :host_id,
                        :fqdn,
                        :netbios,
                        :operating_system,
                        :mac_address,
                        :system_type,
                        :credentialed,
                        coalesce(CAST(:observed_at AS timestamptz), now()),
                        :bios_uuid,
                        CAST(:cpes AS text[]),
                        :operating_system_confidence,
                        :operating_system_method,
                        :local_checks_protocol,
                        CAST(:scan_started_at AS timestamptz),
                        CAST(:scan_ended_at AS timestamptz),
                        CAST(:last_authenticated_results_at AS timestamptz),
                        CAST(:last_unauthenticated_results_at AS timestamptz),
                        :patch_summary_total_cves,
                        CAST(:metadata AS jsonb)
                    )
                    ON CONFLICT (scan_id, host_id)
                    DO UPDATE SET
                        fqdn = EXCLUDED.fqdn,
                        netbios = EXCLUDED.netbios,
                        sistema_operacional = EXCLUDED.sistema_operacional,
                        mac = EXCLUDED.mac,
                        tipo_sistema = EXCLUDED.tipo_sistema,
                        credenciado = EXCLUDED.credenciado,
                        observado_em = EXCLUDED.observado_em,
                        bios_uuid = EXCLUDED.bios_uuid,
                        cpes = EXCLUDED.cpes,
                        confianca_sistema = EXCLUDED.confianca_sistema,
                        metodo_sistema = EXCLUDED.metodo_sistema,
                        protocolo_verificacao_local = EXCLUDED.protocolo_verificacao_local,
                        scan_iniciado_em = EXCLUDED.scan_iniciado_em,
                        scan_concluido_em = EXCLUDED.scan_concluido_em,
                        ultimo_resultado_autenticado_em =
                            EXCLUDED.ultimo_resultado_autenticado_em,
                        ultimo_resultado_nao_autenticado_em =
                            EXCLUDED.ultimo_resultado_nao_autenticado_em,
                        total_cves_patches = EXCLUDED.total_cves_patches,
                        metadados = EXCLUDED.metadados
                    """
                ),
                {
                    "scan_id": scan_id,
                    "host_id": host_id,
                    "fqdn": host.fqdn,
                    "netbios": host.netbios,
                    "operating_system": host.operating_system,
                    "mac_address": host.mac_address,
                    "system_type": host.system_type,
                    "credentialed": host.credentialed,
                    "observed_at": host.scan_ended_at,
                    "bios_uuid": host.bios_uuid,
                    "cpes": list(host.cpes),
                    "operating_system_confidence": host.operating_system_confidence,
                    "operating_system_method": host.operating_system_method,
                    "local_checks_protocol": host.local_checks_protocol,
                    "scan_started_at": host.scan_started_at,
                    "scan_ended_at": host.scan_ended_at,
                    "last_authenticated_results_at": host.last_authenticated_results_at,
                    "last_unauthenticated_results_at": host.last_unauthenticated_results_at,
                    "patch_summary_total_cves": host.patch_summary_total_cves,
                    "metadata": json.dumps(host.metadata),
                },
            )

        await self.session.execute(
            text("DELETE FROM vm.scan_servico WHERE scan_id = :scan_id"),
            {"scan_id": scan_id},
        )
        for service in parsed.services:
            host_id = host_ids.get(service.host_address)
            if host_id is None:
                continue
            await self.session.execute(
                text(
                    """
                    INSERT INTO vm.scan_servico (
                        scan_id,
                        host_id,
                        protocolo,
                        porta,
                        servico,
                        observado_em
                    )
                    VALUES (
                        :scan_id,
                        :host_id,
                        :protocol,
                        :port,
                        :service,
                        coalesce(CAST(:observed_at AS timestamptz), now())
                    )
                    ON CONFLICT (scan_id, host_id, protocolo, porta)
                    DO UPDATE SET
                        servico = coalesce(EXCLUDED.servico, vm.scan_servico.servico),
                        observado_em = EXCLUDED.observado_em
                    """
                ),
                {
                    "scan_id": scan_id,
                    "host_id": host_id,
                    "protocol": service.protocol,
                    "port": service.port,
                    "service": service.service,
                    "observed_at": observed_at_by_address.get(service.host_address),
                },
            )
        return host_ids

    async def _upsert_plugin(self, finding: ScanFinding) -> None:
        await self.session.execute(
            text(
                """
                INSERT INTO vm.plugin (
                    plugin_id,
                    nome,
                    familia,
                    sinopse,
                    descricao,
                    solucao,
                    referencias
                )
                VALUES (
                    :plugin_id,
                    :name,
                    :family,
                    :synopsis,
                    :description,
                    :solution,
                    :references
                )
                ON CONFLICT (plugin_id)
                DO UPDATE SET
                    nome = EXCLUDED.nome,
                    familia = coalesce(EXCLUDED.familia, vm.plugin.familia),
                    sinopse = coalesce(EXCLUDED.sinopse, vm.plugin.sinopse),
                    descricao = coalesce(EXCLUDED.descricao, vm.plugin.descricao),
                    solucao = coalesce(EXCLUDED.solucao, vm.plugin.solucao),
                    referencias = coalesce(EXCLUDED.referencias, vm.plugin.referencias),
                    atualizado_em = now()
                """
            ),
            {
                "plugin_id": finding.plugin_id,
                "name": finding.plugin_name,
                "family": finding.plugin_family,
                "synopsis": finding.synopsis,
                "description": finding.description,
                "solution": finding.solution,
                "references": "\n".join(finding.references) or None,
            },
        )
        for cve in finding.cves:
            await self.session.execute(
                text(
                    """
                    INSERT INTO vm.plugin_cve (plugin_id, cve)
                    VALUES (:plugin_id, :cve)
                    ON CONFLICT DO NOTHING
                    """
                ),
                {"plugin_id": finding.plugin_id, "cve": cve},
            )

    async def _insert_finding(
        self,
        *,
        scan_id: int,
        host_id: int,
        finding: ScanFinding,
    ) -> None:
        await self.session.execute(
            text(
                """
                INSERT INTO vm.achado (
                    scan_id,
                    host_id,
                    plugin_id,
                    protocolo,
                    porta,
                    servico,
                    severidade,
                    risco,
                    cvss2,
                    cvss3,
                    cvss4,
                    cvss3_vetor,
                    vpr,
                    epss,
                    exploravel,
                    maturidade_exploit,
                    saida_plugin
                )
                VALUES (
                    :scan_id,
                    :host_id,
                    :plugin_id,
                    :protocol,
                    :port,
                    :service,
                    :severity,
                    :risk_factor,
                    :cvss2,
                    :cvss3,
                    :cvss4,
                    :cvss3_vector,
                    :vpr,
                    :epss,
                    :exploitable,
                    :exploit_maturity,
                    :plugin_output
                )
                """
            ),
            {
                "scan_id": scan_id,
                "host_id": host_id,
                "plugin_id": finding.plugin_id,
                "protocol": finding.protocol,
                "port": finding.port,
                "service": finding.service,
                "severity": finding.severity,
                "risk_factor": finding.risk_factor,
                "cvss2": finding.cvss2,
                "cvss3": finding.cvss3,
                "cvss4": finding.cvss4,
                "cvss3_vector": finding.cvss3_vector,
                "vpr": finding.vpr,
                "epss": finding.epss,
                "exploitable": finding.exploitable,
                "exploit_maturity": finding.exploit_maturity,
                "plugin_output": finding.plugin_output,
            },
        )


async def process_import(
    *,
    import_id: UUID,
    client_id: int,
    file_path: str,
    original_filename: str,
    source_hash: str,
    scanner_key: str = "nessus",
) -> None:
    path = Path(file_path)
    try:
        async with session_factory() as session:
            await session.execute(
                text(
                    """
                    UPDATE vm.importacao
                    SET status = 'processando', mensagem = NULL
                    WHERE id = :import_id AND cliente_id = :client_id
                    """
                ),
                {"import_id": import_id, "client_id": client_id},
            )
            await session.commit()

        adapter = get_scanner_adapter(scanner_key)
        parsed = await run_in_threadpool(adapter.parse, path)

        async with session_factory() as session:
            importer = ScanImporter(session)
            outcome = await importer.persist(
                parsed=parsed,
                client_id=client_id,
                source_hash=source_hash,
                original_filename=original_filename,
                scanner_key=scanner_key,
            )
            await session.execute(
                text(
                    """
                    UPDATE vm.importacao
                    SET
                        scan_id = :scan_id,
                        status = 'concluido',
                        linhas = :assets,
                        achados = :findings,
                        resolvidos = :resolved,
                        reabertos = :reopened,
                        concluido_em = now(),
                        mensagem = NULL
                    WHERE id = :import_id AND cliente_id = :client_id
                    """
                ),
                {
                    "scan_id": outcome.scan_id,
                    "assets": outcome.assets,
                    "findings": outcome.findings,
                    "resolved": outcome.resolved,
                    "reopened": outcome.reopened,
                    "import_id": import_id,
                    "client_id": client_id,
                },
            )
            await session.commit()
    except Exception as exc:
        async with session_factory() as session:
            await session.execute(
                text(
                    """
                    UPDATE vm.importacao
                    SET status = 'falhou', mensagem = :message, concluido_em = now()
                    WHERE id = :import_id AND cliente_id = :client_id
                    """
                ),
                {
                    "message": _safe_error_message(exc),
                    "import_id": import_id,
                    "client_id": client_id,
                },
            )
            await session.commit()
    finally:
        path.unlink(missing_ok=True)


def _scope_key(parsed: ScanParseResult, *, scanner_key: str) -> str:
    hosts = "|".join(sorted(host.address for host in parsed.hosts))
    # Keep existing Nessus scope identities stable so historic comparisons remain intact.
    namespace = "" if scanner_key == "nessus" else f"{scanner_key}\0"
    material = f"{namespace}{parsed.policy_name or ''}\0{hosts}".encode()
    return sha256(material).hexdigest()


def _unique_plugins(findings: tuple[ScanFinding, ...]) -> dict[int, ScanFinding]:
    return {finding.plugin_id: finding for finding in findings}


def _safe_error_message(exc: Exception) -> str:
    if isinstance(exc, ScanParseError):
        message = str(exc).strip()
        return message[:500] if message else "O arquivo de scan é inválido."
    return "Falha interna durante o processamento. Tente novamente ou contate o suporte."


# Compatibilidade para imports internos/externos existentes.
NessusImporter = ScanImporter

"""Delete one scan atomically, keeping operational records and the audit trail.

Scanner-derived lifecycle data is replayed from surviving observations and manual
status changes. Superseded automatic events remain in the audit table, and no AI
or ticket provider is contacted.
"""

import json
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.vulnerability_lifecycle import sync_vulnerability_lifecycle


async def lock_scan_changes(session: AsyncSession, client_id: int) -> None:
    # Imports and deletion agree on this lock, including overlapping scopes.
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
        {"lock_key": f"scan-changes:{client_id}"},
    )


async def delete_scan(
    *, session: AsyncSession, client_id: int, user_id: UUID, scan_id: int,
) -> dict:
    await lock_scan_changes(session, client_id)
    params = {"client_id": client_id, "scan_id": scan_id}
    result = await session.execute(text("""
        SELECT id, nome, status FROM vm.scan
        WHERE id = :scan_id AND cliente_id = :client_id FOR UPDATE
    """), params)
    scan = result.mappings().one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan não encontrado.")
    if scan["status"] not in {"concluido", "falhou"}:
        raise HTTPException(
            status_code=409, detail="Aguarde o processamento antes de excluir o scan.",
        )

    # Serialize against workflow/AI writes; never delete the operational records.
    await session.execute(text("""
        SELECT id FROM app.vulnerabilidade_tratamento
        WHERE cliente_id = :client_id ORDER BY id FOR UPDATE
    """), params)
    counts = (await session.execute(text("""
        SELECT
            (SELECT count(*) FROM vm.scan_host WHERE scan_id = :scan_id) AS assets,
            (SELECT count(*) FROM vm.achado WHERE scan_id = :scan_id
                AND severidade > 0) AS findings
    """), params)).mappings().one()
    # Cascades remove this scan's observations/services, not shared hosts/plugins.
    await session.execute(text("""
        DELETE FROM vm.scan WHERE id = :scan_id AND cliente_id = :client_id
    """), params)
    await _rebuild_lifecycle(session=session, client_id=client_id, deleted_scan_id=scan_id)
    await session.execute(text("""
        INSERT INTO app.evento_auditoria
            (cliente_id, usuario_id, acao, recurso, recurso_id, detalhes)
        VALUES (:client_id, :user_id, 'scan.deleted', 'scan', :resource_id,
            CAST(:details AS jsonb))
    """), {
        "client_id": client_id, "user_id": user_id, "resource_id": str(scan_id),
        "details": json.dumps({
            "name": scan["nome"], "assets": counts["assets"],
            "findings": counts["findings"], "lifecycle_recalculated": True,
            "operational_records_preserved": True,
        }),
    })
    await session.commit()
    return {"id": scan_id, "name": scan["nome"], "deleted": True}


async def _rebuild_lifecycle(
    *, session: AsyncSession, client_id: int, deleted_scan_id: int,
) -> None:
    params = {"client_id": client_id, "deleted_scan_id": deleted_scan_id}
    scans = (await session.execute(text("""
        SELECT id, escopo_chave, importado_em,
            coalesce(concluido_em, importado_em) AS occurred_at
        FROM vm.scan WHERE cliente_id = :client_id AND status = 'concluido'
        ORDER BY importado_em, id
    """), params)).mappings().all()
    manual = (await session.execute(text("""
        SELECT id, recurso_id, detalhes, criado_em, usuario_id
        FROM app.evento_auditoria
        WHERE cliente_id = :client_id AND recurso = 'vulnerability_workflow'
          AND acao IN ('workflow.created', 'workflow.updated')
        ORDER BY criado_em, id
    """), params)).mappings().all()

    await session.execute(text("""
        UPDATE app.evento_auditoria
        SET acao = replace(acao, 'workflow.auto_', 'workflow.superseded_auto_'),
            detalhes = detalhes || jsonb_build_object(
                'superseded_by_scan_deletion', CAST(:deleted_scan_id AS bigint))
        WHERE cliente_id = :client_id AND recurso = 'vulnerability_workflow'
          AND acao IN ('workflow.auto_resolved', 'workflow.auto_reopened')
    """), params)
    await session.execute(text("""
        UPDATE app.vulnerabilidade_tratamento
        SET status = 'open', primeiro_detectado_em = NULL, ultimo_detectado_em = NULL,
            ultimo_scan_id = NULL, ultimo_achado_id = NULL, resolvido_em = NULL,
            reaberto_em = NULL, total_resolucoes = 0, total_reaberturas = 0
        WHERE cliente_id = :client_id
    """), params)

    timeline = [(row["importado_em"], 0, row["id"], row) for row in scans]
    timeline += [(row["criado_em"], 1, row["id"], row) for row in manual]
    previous_by_scope: dict[str, int] = {}
    for _, kind, _, event in sorted(timeline, key=lambda item: item[:3]):
        if kind == 0:
            await sync_vulnerability_lifecycle(
                session=session, client_id=client_id, scan_id=event["id"],
                previous_scan_id=previous_by_scope.get(event["escopo_chave"]),
                occurred_at=event["occurred_at"],
            )
            previous_by_scope[event["escopo_chave"]] = event["id"]
        else:
            state = (event["detalhes"].get("after") or {}).get("status")
            if state not in {"open", "triage", "in_progress", "validation",
                             "accepted_risk", "reopened"}:
                continue
            # Manual edits cannot override resolution or restore deleted observations.
            await session.execute(text("""
                UPDATE app.vulnerabilidade_tratamento
                SET status = :state, atualizado_em = :occurred_at, atualizado_por = :user_id
                WHERE cliente_id = :client_id AND id::text = :workflow_id
                  AND ultimo_achado_id IS NOT NULL AND status <> 'resolved'
            """), {
                "client_id": client_id, "workflow_id": event["recurso_id"],
                "state": state, "occurred_at": event["criado_em"],
                "user_id": event["usuario_id"],
            })

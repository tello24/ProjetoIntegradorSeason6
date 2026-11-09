"""Local AI diagnostics. Never persist raw errors, prompts or provider credentials."""

import json
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import AIProvider
from app.services.ai_errors import ERROR_MESSAGES


async def record_ai_failure(
    *,
    session: AsyncSession,
    client_id: int,
    user_id: UUID,
    workflow_id: UUID,
    provider: AIProvider,
    error_code: str | None,
    regenerate: bool,
) -> None:
    code = error_code if error_code in ERROR_MESSAGES else "invalid_response"
    await session.execute(
        text("""
            INSERT INTO app.evento_auditoria
                (cliente_id, usuario_id, acao, recurso, recurso_id, detalhes)
            VALUES (:client_id, :user_id, 'ai_analysis.failed',
                    'vulnerability_ai_analysis', :workflow_id, CAST(:details AS jsonb))
        """),
        {
            "client_id": client_id,
            "user_id": user_id,
            "workflow_id": str(workflow_id),
            "details": json.dumps({
                "provider": provider,
                "error_code": code,
                "regenerate": regenerate,
                # Unknown is not zero: the provider may have processed tokens.
                "cost_status": "not_requested" if code in {"disabled", "missing_key"}
                else "unknown",
            }),
        },
    )

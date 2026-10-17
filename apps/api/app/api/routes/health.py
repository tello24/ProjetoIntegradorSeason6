import asyncio
from typing import Annotated

from asyncpg import PostgresError
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session

router = APIRouter(tags=["health"])


@router.get("/health", summary="Verifica se a API está disponível")
async def healthcheck() -> dict[str, str]:
    return {"status": "ok", "service": "neoguardian-insight-api"}


@router.get("/health/ready", summary="Verifica a conexão e o esquema necessário ao login")
async def readiness(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    # No credentials, SQL errors, counts or customer information are returned publicly.
    checks = {"database": "unavailable", "schema": "unknown"}
    try:
        async with asyncio.timeout(3):
            await session.execute(text("SELECT 1"))
            checks["database"] = "ok"
            # Zero-row queries also verify columns, unlike table-existence checks alone.
            await session.execute(text("""
                SELECT u.ativo, uc.papel, c.ativo, t.total_reaberturas,
                       a.geracao, ticket.provedor, sh.metadados, ctx.ambiente
                FROM app.usuario u, app.usuario_cliente uc, vm.cliente c,
                     app.vulnerabilidade_tratamento t, app.vulnerabilidade_analise_ia a,
                     app.vulnerabilidade_ticket ticket, vm.scan_host sh,
                     app.ativo_contexto ctx
                WHERE false
            """))
            checks["schema"] = "ok"
    except (SQLAlchemyError, PostgresError, OSError, TimeoutError):
        if checks["database"] == "ok":
            checks["schema"] = "unavailable"
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "service": "neoguardian-insight-api", "checks": checks},
            headers={"Cache-Control": "no-store"},
        )
    return JSONResponse(
        content={"status": "ready", "service": "neoguardian-insight-api", "checks": checks},
        headers={"Cache-Control": "no-store"},
    )

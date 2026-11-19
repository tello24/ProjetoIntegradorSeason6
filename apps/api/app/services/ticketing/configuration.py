"""Tenant-bound encryption and explicit credential loading (no legacy env fallback)."""

import json
from collections.abc import Mapping

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import JiraConfig, settings
from app.services.ticketing.jira import TicketProviderError


def _cipher() -> MultiFernet:
    try:
        raw = settings.integration_encryption_keys
        keys = raw.get_secret_value().split(",") if raw else []
        if not keys or len(keys) > 5:
            raise ValueError
        return MultiFernet([Fernet(key.strip().encode()) for key in keys])
    except (ValueError, TypeError):
        raise TicketProviderError("credentials") from None


def encryption_ready() -> bool:
    try:
        _cipher()
        return True
    except TicketProviderError:
        return False


def encrypt_token(client_id: int, token: str) -> str:
    return _cipher().encrypt(json.dumps({"tenant": client_id, "token": token}).encode()).decode()


def decrypt_token(client_id: int, encrypted: str) -> str:
    try:
        payload = json.loads(_cipher().decrypt(encrypted.encode()))
        if payload["tenant"] != client_id or not isinstance(payload["token"], str):
            raise ValueError
        return payload["token"]
    except (InvalidToken, ValueError, KeyError, TypeError):
        raise TicketProviderError("credentials") from None


async def tenant_lock(session: AsyncSession, client_id: int) -> None:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"jira:tenant:{client_id}"},
    )


async def configuration_row(session: AsyncSession, client_id: int) -> Mapping | None:
    return (
        (
            await session.execute(
                text("SELECT * FROM app.jira_integracao WHERE cliente_id=:id"), {"id": client_id}
            )
        )
        .mappings()
        .one_or_none()
    )


def configured(row: Mapping | None) -> bool:
    return bool(
        settings.jira_connections_enabled
        and row
        and row["ativa"]
        and row["teste_ok"]
        and encryption_ready()
    )


def provider_config(row: Mapping | None, *, require_active: bool = True) -> JiraConfig:
    if not row or not settings.jira_connections_enabled or require_active and not configured(row):
        raise TicketProviderError("disabled")
    return JiraConfig(
        base_url=row["site_url"],
        email=row["email"],
        api_token=decrypt_token(row["cliente_id"], row["token_cifrado"]),
        project_key=row["projeto"],
        issue_type=row["tipo_item"],
        cloud_id=str(row["cloud_id"]) if row["cloud_id"] else None,
        timeout_seconds=settings.jira_timeout_seconds,
        include_asset_details=row["incluir_ativos"],
        app_public_url=settings.app_public_url.rstrip("/"),
    )

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, HTTPException, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr
from sqlalchemy import text

from app.api.dependencies import CurrentUserDep, SessionDep, require_role
from app.core.config import settings
from app.services.ticketing.configuration import (
    configuration_row,
    decrypt_token,
    encrypt_token,
    encryption_ready,
    provider_config,
    tenant_lock,
)
from app.services.ticketing.jira import ERRORS, JiraClient, TicketProviderError, validate_cloud_url

router = APIRouter()
ADMIN = frozenset({"administrador"})


class JiraInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = Field(ge=0)
    site_url: str = Field(min_length=1, max_length=255)
    email: EmailStr
    api_token: SecretStr | None = Field(default=None, max_length=4096)
    project_key: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,29}$")
    issue_type: str = Field(min_length=1, max_length=80)
    cloud_id: UUID | None = None
    include_asset_details: bool = False


class VersionInput(BaseModel):
    version: int = Field(ge=1)


def _snapshot(row) -> dict:
    return {
        "configured": row is not None,
        "encryption_ready": encryption_ready(),
        "outbound_enabled": settings.jira_connections_enabled,
        "version": row["versao"] if row else 0,
        "site_url": row["site_url"] if row else "",
        "email": row["email"] if row else "",
        "project_key": row["projeto"] if row else "",
        "issue_type": row["tipo_item"] if row else "Task",
        "cloud_id": str(row["cloud_id"]) if row and row["cloud_id"] else "",
        "include_asset_details": bool(row and row["incluir_ativos"]),
        "has_token": bool(row and row["token_cifrado"]),
        "active": bool(row and row["ativa"]),
        "test_ok": bool(row and row["teste_ok"]),
        "tested_at": row["testado_em"] if row else None,
        "error": ERRORS.get(row["ultimo_erro"]) if row else None,
    }


async def _audit(session, user, action):
    await session.execute(
        text("""
        INSERT INTO app.evento_auditoria (cliente_id,usuario_id,acao,recurso,recurso_id,detalhes)
        VALUES (:client,:user,:action,'jira_integration',:resource,'{}'::jsonb)
    """),
        {
            "client": user.client_id,
            "user": user.id,
            "action": action,
            "resource": str(user.client_id),
        },
    )


@router.get("")
async def get_configuration(current_user: CurrentUserDep, session: SessionDep, response: Response):
    require_role(current_user, ADMIN)
    response.headers["Cache-Control"] = "no-store"
    return _snapshot(await configuration_row(session, current_user.client_id))


@router.patch("")
async def save_configuration(body: JiraInput, current_user: CurrentUserDep, session: SessionDep):
    require_role(current_user, ADMIN)
    cid = current_user.client_id
    await tenant_lock(session, cid)
    row = await configuration_row(session, cid)
    if body.version != (row["versao"] if row else 0):
        raise HTTPException(409, "A configuração mudou. Atualize a página antes de salvar.")
    # A creation already reserved may still be running outside this transaction.
    busy = (
        await session.execute(
            text("""SELECT EXISTS(SELECT 1 FROM app.vulnerabilidade_ticket
        WHERE cliente_id=:id AND status='creating')"""),
            {"id": cid},
        )
    ).scalar_one()
    if busy:
        raise HTTPException(
            409, "Existe uma criação em andamento. Confira o vínculo antes de alterar o Jira."
        )
    try:
        site = validate_cloud_url(body.site_url)
        if row and (site != row["site_url"] or body.project_key != row["projeto"]):
            bound = (
                await session.execute(
                    text("""SELECT EXISTS(SELECT 1 FROM app.vulnerabilidade_ticket
                WHERE cliente_id=:id AND status IN ('created','uncertain'))"""),
                    {"id": cid},
                )
            ).scalar_one()
            if bound:
                raise HTTPException(
                    409,
                    "Esta empresa já possui vínculos com este Jira. A troca de site/projeto "
                    "exige migração dos vínculos; as credenciais ainda podem ser atualizadas.",
                )
        token = body.api_token.get_secret_value().strip() if body.api_token else ""
        if not token:
            if not row:
                raise HTTPException(422, "Informe o token no primeiro cadastro.")
            if (
                site != row["site_url"]
                or str(body.email) != row["email"]
                or str(body.cloud_id or "") != str(row["cloud_id"] or "")
            ):
                raise HTTPException(
                    422, "Ao mudar endereço, e-mail ou Cloud ID, informe um novo token."
                )
            token = decrypt_token(cid, row["token_cifrado"])
        if any(char.isspace() for char in token):
            raise HTTPException(422, "O token não pode conter espaços.")
        encrypted = encrypt_token(cid, token)
    except TicketProviderError as exc:
        raise HTTPException(422, str(exc)) from None
    await session.execute(
        text("""
        INSERT INTO app.jira_integracao (cliente_id,site_url,email,token_cifrado,projeto,tipo_item,
            cloud_id,incluir_ativos,atualizado_por)
        VALUES (:id,:site,:email,:token,:project,:type,:cloud,:assets,:user)
        ON CONFLICT(cliente_id) DO UPDATE SET site_url=excluded.site_url,email=excluded.email,
            token_cifrado=excluded.token_cifrado,projeto=excluded.projeto,tipo_item=excluded.tipo_item,
            cloud_id=excluded.cloud_id,incluir_ativos=excluded.incluir_ativos,ativa=false,teste_ok=false,
            testado_em=NULL,ultimo_erro=NULL,versao=app.jira_integracao.versao+1,
            atualizado_por=excluded.atualizado_por,atualizado_em=now()
    """),
        {
            "id": cid,
            "site": site,
            "email": str(body.email),
            "token": encrypted,
            "project": body.project_key,
            "type": body.issue_type.strip(),
            "cloud": body.cloud_id,
            "assets": body.include_asset_details,
            "user": current_user.id,
        },
    )
    await _audit(session, current_user, "jira.configuration_saved")
    await session.commit()
    return _snapshot(await configuration_row(session, cid))


@router.post("/test")
async def test_configuration(body: VersionInput, current_user: CurrentUserDep, session: SessionDep):
    require_role(current_user, ADMIN)
    cid = current_user.client_id
    await tenant_lock(session, cid)
    row = await configuration_row(session, cid)
    if not row or row["versao"] != body.version:
        raise HTTPException(409, "Salve a configuração atual antes de testar.")
    if row["testado_em"] and row["testado_em"] > datetime.now(UTC) - timedelta(seconds=20):
        raise HTTPException(429, "Aguarde 20 segundos entre testes de conexão.")
    try:
        config = provider_config(row, require_active=False)
    except TicketProviderError as exc:
        raise HTTPException(503, str(exc)) from None
    await session.execute(
        text("""UPDATE app.jira_integracao SET teste_ok=false,ativa=false,
        testado_em=now() WHERE cliente_id=:id"""),
        {"id": cid},
    )
    await session.commit()
    error = None
    try:
        await run_in_threadpool(JiraClient(config).check_connection)
    except TicketProviderError as exc:
        error = exc.code
    except Exception:
        error = "connection"
    result = await session.execute(
        text("""UPDATE app.jira_integracao SET teste_ok=:ok,
        ultimo_erro=:error WHERE cliente_id=:id AND versao=:version RETURNING cliente_id"""),
        {"id": cid, "version": body.version, "ok": error is None, "error": error},
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(409, "A configuração mudou durante o teste. Teste a versão atual.")
    await _audit(session, current_user, "jira.connection_tested")
    await session.commit()
    return _snapshot(await configuration_row(session, cid))


@router.post("/{action}")
async def toggle_configuration(
    action: str, body: VersionInput, current_user: CurrentUserDep, session: SessionDep
):
    require_role(current_user, ADMIN)
    if action not in {"activate", "disable"}:
        raise HTTPException(404, "Ação não encontrada.")
    cid = current_user.client_id
    await tenant_lock(session, cid)
    row = await configuration_row(session, cid)
    if not row or row["versao"] != body.version:
        raise HTTPException(409, "Atualize a página para obter a configuração atual.")
    if action == "activate":
        if (
            not row["teste_ok"]
            or not row["testado_em"]
            or row["testado_em"] < datetime.now(UTC) - timedelta(hours=1)
        ):
            raise HTTPException(409, "Execute um teste de conexão bem-sucedido antes de ativar.")
        try:
            provider_config(row, require_active=False)
        except TicketProviderError as exc:
            raise HTTPException(503, str(exc)) from None
    await session.execute(
        text("""UPDATE app.jira_integracao SET ativa=:active,
        versao=versao+1,atualizado_por=:user,atualizado_em=now() WHERE cliente_id=:id"""),
        {"id": cid, "active": action == "activate", "user": current_user.id},
    )
    await _audit(session, current_user, f"jira.{action}")
    await session.commit()
    return _snapshot(await configuration_row(session, cid))

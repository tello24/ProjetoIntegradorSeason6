import hashlib
import hmac
import secrets

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, EmailStr, Field, SecretStr
from sqlalchemy import text

from app.api.dependencies import CurrentUserDep, SessionDep
from app.core.config import settings
from app.core.database import session_factory
from app.core.security import hash_password, verify_password
from app.services.password_mail import mail_ready, send_password_mail

router = APIRouter()
GENERIC = "Se houver uma conta ativa com esse e-mail, você receberá as instruções de recuperação."


class ForgotPassword(BaseModel):
    email: EmailStr


class NewPassword(BaseModel):
    new_password: SecretStr = Field(min_length=12, max_length=200)


class ChangePassword(NewPassword):
    current_password: SecretStr = Field(min_length=1, max_length=200)


class ResetPassword(NewPassword):
    token: SecretStr = Field(min_length=43, max_length=43)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def allowed(session, namespace: str, identity: str, maximum: int) -> bool:
    key = hmac.new(
        settings.app_secret_key.encode(), f"{namespace}:{identity}".encode(), hashlib.sha256
    ).hexdigest()
    # Persistent quotas work across workers; stale buckets contain no plain email/IP.
    await session.execute(
        text("DELETE FROM app.limite_autenticacao WHERE inicio < now()-interval '1 hour'")
    )
    count = (
        await session.execute(
            text("""
        INSERT INTO app.limite_autenticacao(chave) VALUES (:key)
        ON CONFLICT(chave) DO UPDATE SET tentativas=app.limite_autenticacao.tentativas+1
        RETURNING tentativas
    """),
            {"key": key},
        )
    ).scalar_one()
    await session.commit()
    return count <= maximum


async def deliver(email, token):
    sent = await run_in_threadpool(send_password_mail, email, token)
    if not sent:
        async with session_factory() as session:
            await session.execute(
                text("DELETE FROM app.recuperacao_senha WHERE token_hash=:hash"),
                {"hash": digest(token)},
            )
            await session.commit()


@router.post("/forgot-password")
async def forgot_password(
    body: ForgotPassword,
    request: Request,
    response: Response,
    session: SessionDep,
    background: BackgroundTasks,
):
    response.headers["Cache-Control"] = "no-store"
    if not mail_ready():
        raise HTTPException(
            503, "A recuperação por e-mail ainda não está configurada. Contate o administrador."
        )
    ip = request.client.host if request.client else "unknown"
    if not await allowed(session, "forgot-ip", ip, 10):
        return {"message": GENERIC}
    email = str(body.email).lower()
    if not await allowed(session, "forgot-email", email, 3):
        return {"message": GENERIC}
    await session.execute(text("DELETE FROM app.recuperacao_senha WHERE expira_em < now()"))
    uid = (
        await session.execute(
            text("""SELECT u.id FROM app.usuario u
        WHERE u.email=:email AND u.ativo AND EXISTS(SELECT 1 FROM app.usuario_cliente uc
        JOIN vm.cliente c ON c.id=uc.cliente_id WHERE uc.usuario_id=u.id AND uc.ativo AND c.ativo)
        FOR UPDATE OF u"""),
            {"email": email},
        )
    ).scalar_one_or_none()
    if uid:
        token = secrets.token_urlsafe(32)
        await session.execute(
            text("""INSERT INTO app.recuperacao_senha(token_hash,usuario_id,expira_em)
            VALUES (:hash,:uid,now()+interval '20 minutes')"""),
            {"hash": digest(token), "uid": uid},
        )
        background.add_task(deliver, email, token)
    await session.commit()
    return {"message": GENERIC}


async def replace_password(session, uid, password):
    encoded = await run_in_threadpool(hash_password, password)
    await session.execute(
        text("""UPDATE app.usuario SET senha_hash=:hash, trocar_senha=false,
        versao_sessao=versao_sessao+1,atualizado_em=now() WHERE id=:uid"""),
        {"hash": encoded, "uid": uid},
    )
    await session.execute(
        text("DELETE FROM app.recuperacao_senha WHERE usuario_id=:uid"), {"uid": uid}
    )
    await session.execute(
        text("""INSERT INTO app.evento_auditoria
        (cliente_id,usuario_id,acao,recurso,recurso_id,detalhes)
        SELECT cliente_id,CAST(:uid AS uuid),'account.password_changed','user',
            CAST(CAST(:uid AS uuid) AS text),'{}'::jsonb
        FROM app.usuario_cliente WHERE usuario_id=:uid AND ativo"""),
        {"uid": uid},
    )
    await session.commit()


@router.post("/change-password")
async def change_password(
    body: ChangePassword,
    user: CurrentUserDep,
    session: SessionDep,
    response: Response,
    background: BackgroundTasks,
):
    if not await allowed(session, "change", str(user.id), 10):
        raise HTTPException(429, "Muitas tentativas. Aguarde uma hora antes de tentar novamente.")
    row = (
        (
            await session.execute(
                text("SELECT senha_hash,versao_sessao FROM app.usuario WHERE id=:uid FOR UPDATE"),
                {"uid": user.id},
            )
        )
        .mappings()
        .one()
    )
    current, new = body.current_password.get_secret_value(), body.new_password.get_secret_value()
    if row["versao_sessao"] != user.session_version:
        raise HTTPException(401, "Entre novamente para alterar sua senha.")
    if not await run_in_threadpool(verify_password, current, row["senha_hash"]):
        raise HTTPException(400, "Senha atual incorreta.")
    if new == current:
        raise HTTPException(400, "Escolha uma senha diferente da atual.")
    await replace_password(session, user.id, new)
    response.delete_cookie(
        settings.session_cookie_name,
        path="/",
        secure=settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )
    background.add_task(send_password_mail, user.email)
    return {"message": "Senha alterada. Entre novamente com a nova senha."}


@router.post("/reset-password")
async def reset_password(
    body: ResetPassword,
    request: Request,
    response: Response,
    session: SessionDep,
    background: BackgroundTasks,
):
    if not await allowed(
        session, "reset-ip", request.client.host if request.client else "unknown", 20
    ):
        raise HTTPException(429, "Muitas tentativas. Aguarde uma hora antes de tentar novamente.")
    token_hash = digest(body.token.get_secret_value())
    uid = (
        await session.execute(
            text("SELECT usuario_id FROM app.recuperacao_senha WHERE token_hash=:hash"),
            {"hash": token_hash},
        )
    ).scalar_one_or_none()
    invalid = HTTPException(400, "Link inválido, expirado ou já utilizado. Solicite outro link.")
    if not uid:
        raise invalid
    row = (
        (
            await session.execute(
                text("""SELECT senha_hash,email FROM app.usuario u WHERE id=:uid
        AND ativo AND EXISTS(SELECT 1 FROM app.usuario_cliente uc
        JOIN vm.cliente c ON c.id=uc.cliente_id
        WHERE uc.usuario_id=u.id AND uc.ativo AND c.ativo) FOR UPDATE OF u"""),
                {"uid": uid},
            )
        )
        .mappings()
        .one_or_none()
    )
    valid = (
        await session.execute(
            text("""SELECT token_hash FROM app.recuperacao_senha
        WHERE token_hash=:hash AND expira_em>now()"""),
            {"hash": token_hash},
        )
    ).scalar_one_or_none()
    if not row or not valid:
        raise invalid
    password = body.new_password.get_secret_value()
    if await run_in_threadpool(verify_password, password, row["senha_hash"]):
        raise HTTPException(400, "Escolha uma senha diferente da atual.")
    await replace_password(session, uid, password)
    response.delete_cookie(
        settings.session_cookie_name,
        path="/",
        secure=settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )
    background.add_task(send_password_mail, row["email"])
    return {"message": "Senha redefinida. Entre novamente com a nova senha."}

from dataclasses import dataclass
from typing import Annotated, Literal, cast
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.core.security import SessionTokenError, decode_session_token

UserRole = Literal["administrador", "gestor", "analista", "visualizador"]
OPERATIONAL_ROLES: frozenset[UserRole] = frozenset(
    {"administrador", "gestor", "analista"}
)
SCAN_IMPORT_ROLES: frozenset[UserRole] = frozenset({"administrador", "analista"})
AI_GENERATION_ROLES: frozenset[UserRole] = frozenset({"administrador", "analista"})


@dataclass(frozen=True, slots=True)
class CurrentUser:
    id: UUID
    name: str
    email: str
    client_id: int
    client_name: str
    role: UserRole


async def get_current_user(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> CurrentUser:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise _unauthorized()

    try:
        payload = decode_session_token(token)
        user_id = UUID(str(payload["sub"]))
        client_id = int(payload["client_id"])
    except (SessionTokenError, TypeError, ValueError, KeyError) as exc:
        raise _unauthorized() from exc

    result = await session.execute(
        text(
            """
            SELECT
                u.id,
                u.nome,
                u.email,
                uc.cliente_id,
                c.nome AS cliente_nome,
                uc.papel
            FROM app.usuario u
            JOIN app.usuario_cliente uc ON uc.usuario_id = u.id
            JOIN vm.cliente c ON c.id = uc.cliente_id
            WHERE u.id = :user_id
              AND uc.cliente_id = :client_id
              AND uc.ativo = true
              AND u.ativo = true
              AND c.ativo = true
            """
        ),
        {"user_id": user_id, "client_id": client_id},
    )
    row = result.mappings().one_or_none()
    if row is None:
        raise _unauthorized()

    return CurrentUser(
        id=row["id"],
        name=row["nome"],
        email=row["email"],
        client_id=row["cliente_id"],
        client_name=row["cliente_nome"],
        role=cast(UserRole, row["papel"]),
    )


SessionDep = Annotated[AsyncSession, Depends(get_session)]
CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]


def require_role(
    current_user: CurrentUser,
    allowed_roles: frozenset[UserRole],
    *,
    detail: str = "Seu perfil não possui permissão para realizar esta ação.",
) -> None:
    if current_user.role not in allowed_roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Autenticação necessária.",
        headers={"WWW-Authenticate": "Session"},
    )

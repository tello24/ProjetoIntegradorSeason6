import json
from collections.abc import Mapping
from datetime import datetime
from typing import cast
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field, model_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import CurrentUserDep, SessionDep, UserRole, require_role
from app.core.security import hash_password

router = APIRouter()

ADMIN_ROLES: frozenset[UserRole] = frozenset({"administrador"})


class AccessUser(BaseModel):
    id: UUID
    name: str
    email: str
    role: UserRole
    active: bool
    created_at: datetime
    last_updated_at: datetime
    is_current_user: bool


class AccessUserList(BaseModel):
    items: list[AccessUser]
    total: int


class CreateAccessUser(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    temporary_password: str = Field(min_length=12, max_length=200)
    role: UserRole = "analista"


class UpdateAccessUser(BaseModel):
    role: UserRole | None = None
    active: bool | None = None

    @model_validator(mode="after")
    def require_change(self) -> "UpdateAccessUser":
        if self.role is None and self.active is None:
            raise ValueError("Informe o perfil ou o estado do acesso.")
        return self


@router.get("/users", response_model=AccessUserList)
async def list_access_users(
    current_user: CurrentUserDep,
    session: SessionDep,
) -> AccessUserList:
    require_role(current_user, ADMIN_ROLES, detail="Somente administradores gerenciam acessos.")
    result = await session.execute(
        text(
            """
            SELECT
                user_account.id,
                user_account.nome,
                user_account.email,
                membership.papel,
                membership.ativo,
                membership.criado_em,
                membership.atualizado_em
            FROM app.usuario_cliente membership
            JOIN app.usuario user_account ON user_account.id = membership.usuario_id
            WHERE membership.cliente_id = :client_id
            ORDER BY
                CASE membership.papel
                    WHEN 'administrador' THEN 1
                    WHEN 'gestor' THEN 2
                    WHEN 'analista' THEN 3
                    ELSE 4
                END,
                membership.ativo DESC,
                user_account.nome,
                user_account.email
            """
        ),
        {"client_id": current_user.client_id},
    )
    items = [
        _access_user(row, current_user_id=current_user.id)
        for row in result.mappings().all()
    ]
    return AccessUserList(items=items, total=len(items))


@router.post("/users", response_model=AccessUser, status_code=status.HTTP_201_CREATED)
async def create_access_user(
    payload: CreateAccessUser,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> AccessUser:
    require_role(current_user, ADMIN_ROLES, detail="Somente administradores criam acessos.")
    email = str(payload.email).strip().lower()
    name = payload.name.strip()
    existing_result = await session.execute(
        text("SELECT id FROM app.usuario WHERE email = :email"),
        {"email": email},
    )
    if existing_result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Já existe uma conta cadastrada com este e-mail.",
        )

    user_result = await session.execute(
        text(
            """
            INSERT INTO app.usuario (nome, email, senha_hash)
            VALUES (:name, :email, :password_hash)
            RETURNING id
            """
        ),
        {
            "name": name,
            "email": email,
            "password_hash": hash_password(payload.temporary_password),
        },
    )
    user_id = user_result.scalar_one()
    await session.execute(
        text(
            """
            INSERT INTO app.usuario_cliente (usuario_id, cliente_id, papel)
            VALUES (:user_id, :client_id, :role)
            """
        ),
        {
            "user_id": user_id,
            "client_id": current_user.client_id,
            "role": payload.role,
        },
    )
    await _audit_access_change(
        session=session,
        client_id=current_user.client_id,
        actor_id=current_user.id,
        target_id=user_id,
        action="access.user_created",
        details={"name": name, "email": email, "role": payload.role, "active": True},
    )
    await session.commit()
    return await _get_access_user(
        session=session,
        client_id=current_user.client_id,
        user_id=user_id,
        current_user_id=current_user.id,
    )


@router.patch("/users/{user_id}", response_model=AccessUser)
async def update_access_user(
    user_id: UUID,
    payload: UpdateAccessUser,
    current_user: CurrentUserDep,
    session: SessionDep,
) -> AccessUser:
    require_role(current_user, ADMIN_ROLES, detail="Somente administradores alteram acessos.")
    current_result = await session.execute(
        text(
            """
            SELECT papel, ativo
            FROM app.usuario_cliente
            WHERE usuario_id = :user_id AND cliente_id = :client_id
            """
        ),
        {"user_id": user_id, "client_id": current_user.client_id},
    )
    previous = current_result.mappings().one_or_none()
    if previous is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    next_role = payload.role or previous["papel"]
    next_active = previous["ativo"] if payload.active is None else payload.active
    if user_id == current_user.id and (
        next_role != current_user.role or next_active is False
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Você não pode remover ou rebaixar o próprio acesso administrativo.",
        )

    if previous["papel"] == "administrador" and previous["ativo"] and (
        next_role != "administrador" or not next_active
    ):
        admin_count_result = await session.execute(
            text(
                """
                SELECT count(*)
                FROM app.usuario_cliente
                WHERE cliente_id = :client_id
                  AND papel = 'administrador'
                  AND ativo = true
                """
            ),
            {"client_id": current_user.client_id},
        )
        if int(admin_count_result.scalar_one()) <= 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="O ambiente precisa manter pelo menos um administrador ativo.",
            )

    await session.execute(
        text(
            """
            UPDATE app.usuario_cliente
            SET
                papel = :role,
                ativo = :active,
                atualizado_em = now()
            WHERE usuario_id = :user_id AND cliente_id = :client_id
            """
        ),
        {
            "role": next_role,
            "active": next_active,
            "user_id": user_id,
            "client_id": current_user.client_id,
        },
    )
    await _audit_access_change(
        session=session,
        client_id=current_user.client_id,
        actor_id=current_user.id,
        target_id=user_id,
        action="access.user_updated",
        details={
            "before": {"role": previous["papel"], "active": previous["ativo"]},
            "after": {"role": next_role, "active": next_active},
        },
    )
    await session.commit()
    return await _get_access_user(
        session=session,
        client_id=current_user.client_id,
        user_id=user_id,
        current_user_id=current_user.id,
    )


async def _get_access_user(
    *,
    session: AsyncSession,
    client_id: int,
    user_id: UUID,
    current_user_id: UUID,
) -> AccessUser:
    result = await session.execute(
        text(
            """
            SELECT
                user_account.id,
                user_account.nome,
                user_account.email,
                membership.papel,
                membership.ativo,
                membership.criado_em,
                membership.atualizado_em
            FROM app.usuario_cliente membership
            JOIN app.usuario user_account ON user_account.id = membership.usuario_id
            WHERE membership.cliente_id = :client_id
              AND membership.usuario_id = :user_id
            """
        ),
        {"client_id": client_id, "user_id": user_id},
    )
    row = result.mappings().one()
    return _access_user(row, current_user_id=current_user_id)


def _access_user(row: Mapping[str, object], *, current_user_id: UUID) -> AccessUser:
    return AccessUser(
        id=cast(UUID, row["id"]),
        name=cast(str, row["nome"]),
        email=cast(str, row["email"]),
        role=cast(UserRole, row["papel"]),
        active=cast(bool, row["ativo"]),
        created_at=cast(datetime, row["criado_em"]),
        last_updated_at=cast(datetime, row["atualizado_em"]),
        is_current_user=row["id"] == current_user_id,
    )


async def _audit_access_change(
    *,
    session: AsyncSession,
    client_id: int,
    actor_id: UUID,
    target_id: UUID,
    action: str,
    details: dict[str, object],
) -> None:
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
                :action,
                'access_user',
                :target_id,
                CAST(:details AS jsonb)
            )
            """
        ),
        {
            "client_id": client_id,
            "actor_id": actor_id,
            "action": action,
            "target_id": str(target_id),
            "details": json.dumps(details, ensure_ascii=False),
        },
    )

from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text

from app.api.dependencies import CurrentUserDep, SessionDep, UserRole
from app.core.config import settings
from app.core.security import DUMMY_PASSWORD_HASH, create_session_token, verify_password

router = APIRouter()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)


class UserResponse(BaseModel):
    id: UUID
    name: str
    email: str
    client_id: int
    client_name: str
    role: UserRole


class LoginResponse(BaseModel):
    user: UserResponse


@router.post("/login", response_model=LoginResponse)
async def login(
    credentials: LoginRequest,
    response: Response,
    session: SessionDep,
) -> LoginResponse:
    result = await session.execute(
        text(
            """
            SELECT
                u.id,
                u.nome,
                u.email,
                u.senha_hash,
                uc.cliente_id,
                c.nome AS cliente_nome,
                uc.papel
            FROM app.usuario u
            JOIN app.usuario_cliente uc ON uc.usuario_id = u.id
            JOIN vm.cliente c ON c.id = uc.cliente_id
            WHERE u.email = :email
              AND u.ativo = true
              AND uc.ativo = true
              AND c.ativo = true
            ORDER BY
                CASE uc.papel
                    WHEN 'administrador' THEN 1
                    WHEN 'gestor' THEN 2
                    WHEN 'analista' THEN 3
                    ELSE 4
                END,
                uc.cliente_id
            LIMIT 1
            """
        ),
        {"email": str(credentials.email).lower()},
    )
    row = result.mappings().one_or_none()

    encoded_hash = row["senha_hash"] if row is not None else DUMMY_PASSWORD_HASH
    password_is_valid = verify_password(credentials.password, encoded_hash)
    if row is None or not password_is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou senha inválidos.",
        )

    token = create_session_token(
        user_id=row["id"],
        client_id=row["cliente_id"],
        role=row["papel"],
    )
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        max_age=int(timedelta(hours=settings.session_duration_hours).total_seconds()),
        path="/",
    )

    return LoginResponse(
        user=UserResponse(
            id=row["id"],
            name=row["nome"],
            email=row["email"],
            client_id=row["cliente_id"],
            client_name=row["cliente_nome"],
            role=row["papel"],
        )
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> Response:
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        secure=settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserResponse)
async def me(current_user: CurrentUserDep) -> UserResponse:
    return UserResponse(
        id=current_user.id,
        name=current_user.name,
        email=current_user.email,
        client_id=current_user.client_id,
        client_name=current_user.client_name,
        role=current_user.role,
    )

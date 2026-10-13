from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_password, verify_password


async def ensure_development_bootstrap(session: AsyncSession) -> None:
    """Create an opt-in local admin without embedding credentials in migrations."""
    if (
        not settings.is_development
        or not settings.bootstrap_admin_email
        or not settings.bootstrap_admin_password
    ):
        return

    client_result = await session.execute(
        text(
            """
            INSERT INTO vm.cliente (nome, slug)
            VALUES (:name, :slug)
            ON CONFLICT (slug) DO UPDATE SET nome = EXCLUDED.nome
            RETURNING id
            """
        ),
        {"name": settings.bootstrap_client_name, "slug": settings.bootstrap_client_slug},
    )
    client_id = client_result.scalar_one()

    user_result = await session.execute(
        text("SELECT id, senha_hash FROM app.usuario WHERE email = :email"),
        {"email": settings.bootstrap_admin_email},
    )
    user = user_result.mappings().one_or_none()

    if user is None:
        created_user = await session.execute(
            text(
                """
                INSERT INTO app.usuario (nome, email, senha_hash)
                VALUES (:name, :email, :password_hash)
                RETURNING id
                """
            ),
            {
                "name": settings.bootstrap_admin_name,
                "email": settings.bootstrap_admin_email,
                "password_hash": hash_password(settings.bootstrap_admin_password),
            },
        )
        user_id = created_user.scalar_one()
    else:
        user_id = user["id"]
        if not verify_password(settings.bootstrap_admin_password, user["senha_hash"]):
            await session.execute(
                text(
                    """
                    UPDATE app.usuario
                    SET senha_hash = :password_hash, atualizado_em = now()
                    WHERE id = :user_id
                    """
                ),
                {
                    "password_hash": hash_password(settings.bootstrap_admin_password),
                    "user_id": user_id,
                },
            )

    await session.execute(
        text(
            """
            INSERT INTO app.usuario_cliente (usuario_id, cliente_id, papel)
            VALUES (:user_id, :client_id, 'administrador')
            ON CONFLICT (usuario_id, cliente_id)
            DO UPDATE SET
                papel = EXCLUDED.papel,
                ativo = true,
                atualizado_em = now()
            """
        ),
        {"user_id": user_id, "client_id": client_id},
    )
    await session.commit()

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import jwt
from jwt import InvalidTokenError
from pwdlib import PasswordHash

from app.core.config import settings

ALGORITHM = "HS256"
ISSUER = "neoguardian-insight"
password_hash = PasswordHash.recommended()
DUMMY_PASSWORD_HASH = password_hash.hash("not-a-real-user-password")


class SessionTokenError(ValueError):
    """Raised when a session token is invalid or expired."""


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, encoded_hash: str) -> bool:
    return password_hash.verify(password, encoded_hash)


def create_session_token(*, user_id: UUID, client_id: int, role: str) -> str:
    now = datetime.now(UTC)
    expires_at = now + timedelta(hours=settings.session_duration_hours)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "client_id": client_id,
        "role": role,
        "iss": ISSUER,
        "iat": now,
        "exp": expires_at,
    }
    return jwt.encode(payload, settings.app_secret_key, algorithm=ALGORITHM)


def decode_session_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.app_secret_key,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={"require": ["sub", "client_id", "role", "exp", "iat"]},
        )
    except InvalidTokenError as exc:
        raise SessionTokenError("Sessão inválida ou expirada.") from exc

    try:
        UUID(str(payload["sub"]))
        payload["client_id"] = int(payload["client_id"])
    except (TypeError, ValueError, KeyError) as exc:
        raise SessionTokenError("Sessão inválida.") from exc
    return payload

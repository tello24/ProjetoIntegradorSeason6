from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.api import dependencies


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"])
async def test_viewer_is_readonly_even_with_stale_admin_token(monkeypatch, method):
    user_id = uuid4()
    monkeypatch.setattr(dependencies, "decode_session_token", lambda token: {
        "sub": str(user_id), "client_id": 12, "role": "administrador",
    })
    row = dict(id=user_id, nome="Leitor", email="viewer@example.com", cliente_id=12,
               cliente_nome="Test", papel="visualizador")
    result = MagicMock()
    result.mappings.return_value.one_or_none.return_value = row
    session = AsyncMock()
    session.execute.return_value = result
    request = Request({"type": "http", "method": method, "headers": [
        (b"cookie", f"{dependencies.settings.session_cookie_name}=synthetic-session".encode()),
    ]})
    if method in {"GET", "HEAD", "OPTIONS"}:
        current = await dependencies.get_current_user(request, session)
        assert current.role == "visualizador"
    else:
        with pytest.raises(HTTPException) as exc:
            await dependencies.get_current_user(request, session)
        assert exc.value.status_code == 403
        assert "somente leitura" in exc.value.detail
    session.commit.assert_not_called()

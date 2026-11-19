import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.api.routes import passwords
from app.core.config import settings
from app.core.database import session_factory
from app.core.security import hash_password
from app.main import app

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DATABASE_TESTS") != "1", reason="Isolated DB required"
)


def test_first_password_recovery_expiry_single_use_and_session_revocation(monkeypatch):
    initial, changed, recovered = (
        "initial-test-password-123",
        "changed-test-password-456",
        "recovered-test-password-789",
    )
    email = f"password-{uuid4().hex}@example.com"

    async def seed():
        async with session_factory() as session:
            cid = (
                await session.execute(
                    text(
                        "INSERT INTO vm.cliente(nome,slug) "
                        "VALUES ('Password test',:slug) RETURNING id"
                    ),
                    {"slug": uuid4().hex},
                )
            ).scalar_one()
            uid = (
                await session.execute(
                    text("""INSERT INTO app.usuario(nome,email,senha_hash,trocar_senha)
                VALUES ('Password test',:email,:hash,true) RETURNING id"""),
                    {"email": email, "hash": hash_password(initial)},
                )
            ).scalar_one()
            await session.execute(
                text(
                    "INSERT INTO app.usuario_cliente(usuario_id,cliente_id,papel) "
                    "VALUES (:uid,:cid,'visualizador')"
                ),
                {"uid": uid, "cid": cid},
            )
            await session.commit()
            return uid

    sent = []

    def fake_send(address, token=None):
        sent.append((address, token))
        return True

    monkeypatch.setattr(passwords, "send_password_mail", fake_send)
    monkeypatch.setattr(passwords, "mail_ready", lambda: False)
    with TestClient(app) as client:
        uid = client.portal.call(seed)
        assert client.post("/api/v1/auth/forgot-password", json={"email": email}).status_code == 503
        login = client.post("/api/v1/auth/login", json={"email": email, "password": initial})
        assert login.status_code == 200 and login.json()["user"]["must_change_password"]
        old_cookie = client.cookies.get(settings.session_cookie_name)
        assert client.get("/api/v1/dashboard/summary").status_code == 428
        assert client.get("/api/v1/auth/me").json()["must_change_password"]
        assert (
            client.post(
                "/api/v1/auth/change-password",
                json={"current_password": "wrong", "new_password": changed},
            ).status_code
            == 400
        )
        assert (
            client.post(
                "/api/v1/auth/change-password",
                json={"current_password": initial, "new_password": initial},
            ).status_code
            == 400
        )
        invalid = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": initial, "new_password": "secret"},
        )
        assert invalid.status_code == 422 and "secret" not in invalid.text
        assert (
            client.post(
                "/api/v1/auth/change-password",
                json={"current_password": initial, "new_password": changed},
            ).status_code
            == 200
        )
        client.cookies.set(settings.session_cookie_name, old_cookie)
        assert client.get("/api/v1/auth/me").status_code == 401
        client.cookies.clear()
        assert (
            client.post(
                "/api/v1/auth/login", json={"email": email, "password": initial}
            ).status_code
            == 401
        )
        assert not client.post(
            "/api/v1/auth/login", json={"email": email, "password": changed}
        ).json()["user"]["must_change_password"]
        assert client.get("/api/v1/dashboard/summary").status_code == 200
        assert client.post("/api/v1/scans/import").status_code == 403
        session_before_reset = client.cookies.get(settings.session_cookie_name)
        monkeypatch.setattr(passwords, "mail_ready", lambda: True)
        known = client.post("/api/v1/auth/forgot-password", json={"email": email})
        token = sent[-1][1]
        unknown = client.post("/api/v1/auth/forgot-password", json={"email": "missing@example.com"})
        assert known.json() == unknown.json() and token not in known.text

        async def saved_tokens():
            async with session_factory() as session:
                return (
                    (
                        await session.execute(
                            text(
                                "SELECT token_hash FROM app.recuperacao_senha WHERE usuario_id=:uid"
                            ),
                            {"uid": uid},
                        )
                    )
                    .scalars()
                    .all()
                )

        assert token not in client.portal.call(saved_tokens)
        assert passwords.digest(token) in client.portal.call(saved_tokens)
        response = client.post(
            "/api/v1/auth/reset-password", json={"token": token, "new_password": recovered}
        )
        assert response.status_code == 200, response.text
        assert not client.portal.call(saved_tokens)
        assert (
            client.post(
                "/api/v1/auth/reset-password", json={"token": token, "new_password": changed}
            ).status_code
            == 400
        )
        client.cookies.set(settings.session_cookie_name, session_before_reset)
        assert client.get("/api/v1/auth/me").status_code == 401
        client.cookies.clear()
        assert (
            client.post(
                "/api/v1/auth/login", json={"email": email, "password": recovered}
            ).status_code
            == 200
        )
        client.post("/api/v1/auth/forgot-password", json={"email": email})
        expired_token = sent[-1][1]

        async def expire():
            async with session_factory() as session:
                await session.execute(
                    text(
                        "UPDATE app.recuperacao_senha SET expira_em=now()-interval '1 second' "
                        "WHERE usuario_id=:uid"
                    ),
                    {"uid": uid},
                )
                await session.commit()

        client.portal.call(expire)
        assert (
            client.post(
                "/api/v1/auth/reset-password",
                json={"token": expired_token, "new_password": changed},
            ).status_code
            == 400
        )
        client.post("/api/v1/auth/forgot-password", json={"email": email})
        count = len(sent)
        for _ in range(4):
            assert (
                client.post("/api/v1/auth/forgot-password", json={"email": email}).json()
                == known.json()
            )
        assert len(sent) == count

from unittest.mock import AsyncMock

import pytest
from asyncpg import InvalidPasswordError
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.core.database import get_session
from app.main import app


def test_healthcheck() -> None:
    client = TestClient(app)
    response = client.get("/api/v1/health")
    client.close()

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "neoguardian-insight-api",
    }


@pytest.mark.parametrize("failure_at", [None, 1, 2])
@pytest.mark.parametrize(
    "error_type", [SQLAlchemyError, InvalidPasswordError, OSError, TimeoutError],
)
def test_readiness_checks_database_and_schema_without_disclosing_errors(
    failure_at, error_type, monkeypatch,
) -> None:
    # This unit test replaces the DB session; startup must not bootstrap a real
    # database merely because the developer configured an account in their .env.
    monkeypatch.setattr("app.main.ensure_development_bootstrap", AsyncMock())
    class FakeSession:
        calls = 0

        async def execute(self, statement):
            self.calls += 1
            if self.calls == failure_at:
                raise error_type("postgresql://secret-user:secret-password@private-host")

    async def fake_session():
        yield FakeSession()

    app.dependency_overrides[get_session] = fake_session
    try:
        with TestClient(app, raise_server_exceptions=True) as client:
            response = client.get("/api/v1/health/ready")
    finally:
        app.dependency_overrides.pop(get_session, None)

    assert response.status_code == (200 if failure_at is None else 503)
    assert response.headers["cache-control"] == "no-store"
    assert "secret" not in response.text
    assert "private-host" not in response.text
    assert response.json()["checks"] == {
        "database": "unavailable" if failure_at == 1 else "ok",
        "schema": "unknown" if failure_at == 1 else "unavailable" if failure_at == 2 else "ok",
    }

"""Real PostgreSQL + simulated Jira. Never requires a real external account."""

import os
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import text
from test_integration_flow import SAMPLE_NESSUS

from app.api.routes import jira_admin, tickets
from app.core.config import settings
from app.core.database import session_factory
from app.core.security import create_session_token
from app.main import app
from app.services.ticketing import CreatedTicket, TicketProviderError

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DATABASE_TESTS") != "1", reason="Isolated PostgreSQL required"
)


async def seed_tenants():
    result = []
    async with session_factory() as session:
        for _ in range(2):
            suffix = uuid4().hex
            cid = (
                await session.execute(
                    text("""INSERT INTO vm.cliente(nome,slug)
                VALUES ('Jira synthetic',:slug) RETURNING id"""),
                    {"slug": suffix},
                )
            ).scalar_one()
            users = {}
            for role in ("administrador", "analista", "visualizador"):
                uid = (
                    await session.execute(
                        text("""INSERT INTO app.usuario(nome,email,senha_hash)
                    VALUES (:role,:email,'unused-test-hash') RETURNING id"""),
                        {"role": role, "email": f"{role}-{suffix}@example.com"},
                    )
                ).scalar_one()
                await session.execute(
                    text("""INSERT INTO app.usuario_cliente(usuario_id,cliente_id,papel)
                    VALUES (:uid,:cid,:role)"""),
                    {"uid": uid, "cid": cid, "role": role},
                )
                users[role] = uid
            result.append((cid, users))
        await session.commit()
    return result


def login_as(client, tenant, role="administrador"):
    cid, users = tenant
    token = create_session_token(user_id=users[role], client_id=cid, role=role)
    client.cookies.clear()
    client.cookies.set(settings.session_cookie_name, token)


async def read_config(cid):
    async with session_factory() as session:
        return (
            (
                await session.execute(
                    text("SELECT * FROM app.jira_integracao WHERE cliente_id=:cid"), {"cid": cid}
                )
            )
            .mappings()
            .one()
        )


def test_tenant_jira_configuration_preview_creation_and_uncertain_reconciliation(monkeypatch):
    monkeypatch.setattr(
        settings, "integration_encryption_keys", SecretStr(Fernet.generate_key().decode())
    )
    monkeypatch.setattr(settings, "jira_connections_enabled", True)
    checks, creates, searches = [], [], []
    mode = {"create": "success", "search": "success"}

    class FakeJira:
        def __init__(self, config):
            self.config = config

        def check_connection(self):
            checks.append(self.config)
            return {"issue_type_id": "10001"}

        def create_issue(self, draft):
            creates.append((self.config, draft))
            if mode["create"] == "uncertain":
                raise TicketProviderError("connection", uncertain=True)
            return CreatedTicket("SEC-42", f"{self.config.base_url}/browse/SEC-42")

        def find_issue(self, label):
            searches.append((self.config, label))
            if mode["search"] == "empty":
                raise TicketProviderError("unconfirmed", uncertain=True)
            return CreatedTicket("SEC-42", f"{self.config.base_url}/browse/SEC-42")

    monkeypatch.setattr(jira_admin, "JiraClient", FakeJira)
    monkeypatch.setattr(tickets, "JiraClient", FakeJira)
    with TestClient(app) as client:
        tenants = client.portal.call(seed_tenants)
        findings = []
        for index, tenant in enumerate(tenants):
            login_as(client, tenant)
            assert client.get("/api/v1/admin/jira").json()["configured"] is False
            response = client.post(
                "/api/v1/scans/import",
                files={"file": ("test.nessus", SAMPLE_NESSUS, "application/xml")},
            )
            assert response.status_code == 202
            findings.append(client.get("/api/v1/vulnerabilities").json()["items"][0]["id"])
            body = {
                "version": 0,
                "site_url": f"https://company{index}.atlassian.net",
                "email": f"jira{index}@example.com",
                "api_token": f"synthetic-private-{index}",
                "project_key": "SEC",
                "issue_type": "Task",
                "include_asset_details": False,
            }
            invalid = client.patch(
                "/api/v1/admin/jira", json={**body, "cloud_id": "invalid-secret-value"}
            )
            assert invalid.status_code == 422
            assert (
                "synthetic-private" not in invalid.text
                and "invalid-secret-value" not in invalid.text
            )
            saved = client.patch("/api/v1/admin/jira", json=body)
            assert saved.status_code == 200, saved.text
            assert saved.json()["version"] == 1 and not saved.json()["active"]
            assert "api_token" not in saved.text and "synthetic-private" not in saved.text
            db_config = client.portal.call(read_config, tenant[0])
            assert "synthetic-private" not in db_config["token_cifrado"]
            assert client.patch("/api/v1/admin/jira", json=body).status_code == 409
            assert (
                client.post("/api/v1/admin/jira/activate", json={"version": 1}).status_code == 409
            )
            tested = client.post("/api/v1/admin/jira/test", json={"version": 1})
            assert tested.status_code == 200 and tested.json()["test_ok"]
            assert client.post("/api/v1/admin/jira/test", json={"version": 1}).status_code == 429
            activated = client.post("/api/v1/admin/jira/activate", json={"version": 1})
            assert activated.status_code == 200 and activated.json()["active"]
            assert checks[index].api_token == f"synthetic-private-{index}"

        assert creates == [] and searches == []
        assert checks[0].base_url != checks[1].base_url
        login_as(client, tenants[0], "analista")
        assert client.get("/api/v1/admin/jira").status_code == 403
        assert client.post("/api/v1/admin/jira/test", json={"version": 2}).status_code == 403
        assert client.get(f"/api/v1/vulnerabilities/{findings[1]}/ticket").status_code == 404
        endpoint = f"/api/v1/vulnerabilities/{findings[0]}/ticket"
        preview = client.get(endpoint + "/preview")
        assert preview.status_code == 200
        assert "198.51.100.10" not in preview.text
        assert "ci-host.example.com" not in preview.text
        assert "synthetic-private" not in preview.text
        assert creates == []
        assert client.post(endpoint, json={"preview_fingerprint": "0" * 64}).status_code == 409
        fingerprint = {"preview_fingerprint": preview.json()["fingerprint"]}
        created = client.post(endpoint, json=fingerprint)
        assert created.status_code == 200, created.text
        assert created.json()["ticket"]["status"] == "created"
        assert client.post(endpoint, json=fingerprint).status_code == 200
        assert len(creates) == 1

        login_as(client, tenants[0], "visualizador")
        state = client.get(endpoint).json()
        assert not state["can_create"] and not state["can_reconcile"]
        assert state["ticket"]["external_key"] == "SEC-42"
        assert client.get(endpoint + "/preview").status_code == 403
        assert client.post(endpoint, json=fingerprint).status_code == 403
        assert client.post(endpoint + "/reconcile").status_code == 403
        assert client.get("/api/v1/admin/jira").status_code == 403

        login_as(client, tenants[1])
        second = f"/api/v1/vulnerabilities/{findings[1]}/ticket"
        assert client.get(second).json()["ticket"] is None
        preview = client.get(second + "/preview").json()
        fingerprint = {"preview_fingerprint": preview["fingerprint"]}
        mode["create"] = "uncertain"
        assert client.post(second, json=fingerprint).status_code == 502
        state = client.get(second).json()
        assert state["ticket"]["status"] == "uncertain"
        assert not state["can_create"] and state["can_reconcile"]
        assert client.post(second, json=fingerprint).status_code == 409
        assert len(creates) == 2
        mode["search"] = "empty"
        assert client.post(second + "/reconcile").status_code == 502
        assert client.get(second).json()["ticket"]["status"] == "uncertain"
        mode["search"] = "success"
        reconciled = client.post(second + "/reconcile")
        assert reconciled.status_code == 200, reconciled.text
        assert reconciled.json()["ticket"]["external_key"] == "SEC-42"
        assert len(creates) == 2 and len(searches) == 2
        assert searches[0][0].api_token == "synthetic-private-1"
        # Same key in independent customer sites must not conflict in PostgreSQL.
        assert "company1.atlassian.net" in reconciled.json()["ticket"]["external_url"]
        config = client.get("/api/v1/admin/jira").json()
        change = {
            "version": config["version"],
            "site_url": "https://new.atlassian.net",
            "email": config["email"],
            "project_key": "SEC",
            "issue_type": "Task",
            "api_token": "synthetic-new-token",
        }
        assert client.patch("/api/v1/admin/jira", json=change).status_code == 409
        disabled = client.post("/api/v1/admin/jira/disable", json={"version": config["version"]})
        assert disabled.status_code == 200 and not disabled.json()["active"]
        assert client.get(second).json()["ticket"]["external_key"] == "SEC-42"
        assert not client.get(second).json()["enabled"]

        # Replaying 006 after a multi-tenant installation must not restore the global index.
        async def check_replay():
            from pathlib import Path

            from app.core.database import engine

            migration = Path(__file__).parents[3] / "database/migrations/006_ticket_integration.sql"
            async with engine.connect() as conn:
                raw = await conn.get_raw_connection()
                await raw.driver_connection.execute(migration.read_text())

        client.portal.call(check_replay)

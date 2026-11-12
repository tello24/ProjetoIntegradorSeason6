"""Real PostgreSQL aggregations with synthetic data only; no provider calls."""

import os
from decimal import Decimal
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.database import session_factory
from app.core.security import create_session_token
from app.main import app

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DATABASE_TESTS") != "1", reason="Requer PostgreSQL isolado com migrations.",
)


async def seed_usage():
    users = {key: uuid4() for key in ("admin", "ana", "bia", "foreign", "failures")}
    async with session_factory() as session:
        clients = []
        for label in ("usage", "foreign"):
            clients.append((await session.execute(text("""
                INSERT INTO vm.cliente (nome, slug) VALUES (:name, :slug) RETURNING id
            """), {"name": label, "slug": f"{label}-{uuid4()}"})).scalar_one())
        for key, user_id in users.items():
            await session.execute(text("""
                INSERT INTO app.usuario (id, nome, email, senha_hash)
                VALUES (:id, :name, :email, 'synthetic-not-a-password-hash')
            """), {"id": user_id, "name": f"Pessoa {key}", "email": f"{user_id}@example.com"})
            await session.execute(text("""
                INSERT INTO app.usuario_cliente (usuario_id, cliente_id, papel, ativo)
                VALUES (:id, :client, :role, :active)
            """), {"id": user_id, "client": clients[1] if key == "foreign" else clients[0],
                   "role": "administrador" if key in {"admin", "foreign"} else "analista",
                   "active": key != "bia"})
        await session.execute(text("""
            INSERT INTO vm.plugin (plugin_id, nome) VALUES (990081, 'Achado de consumo sintético')
            ON CONFLICT (plugin_id) DO NOTHING
        """))
        workflows = []
        scans = []
        newest_finding = None
        for client_index, client_id in enumerate(clients):
            host = (await session.execute(text("""
                INSERT INTO vm.host (cliente_id, endereco) VALUES (:client, '192.0.2.200')
                RETURNING id
            """), {"client": client_id})).scalar_one()
            for port in range(21 if client_index == 0 else 1):
                workflow = (await session.execute(text("""
                    INSERT INTO app.vulnerabilidade_tratamento
                        (cliente_id, host_id, plugin_id, porta, responsavel_id)
                    VALUES (:client, :host, 990081, :port, :assignee) RETURNING id
                """), {"client": client_id, "host": host, "port": port,
                       "assignee": users["admin"] if client_index == 0 else users["foreign"]}
                )).scalar_one()
                if client_index == 0:
                    workflows.append(workflow)
                await add_analysis(session, client_id, workflow, 1,
                                   users["ana"] if client_index == 0 else users["foreign"],
                                   "0.001" if client_index == 0 else "99")
            if client_index == 0:
                # Multiple observations must not multiply the cost of a single generation.
                for index in range(2):
                    scan = (await session.execute(text("""
                        INSERT INTO vm.scan
                            (cliente_id, nome, escopo_chave, chave_origem, status, concluido_em)
                        VALUES (:client, 'Usage fixture', 'usage', :origin, 'concluido',
                                now() - make_interval(days => :age)) RETURNING id
                    """), {"client": client_id, "origin": str(uuid4()), "age": 2-index}
                    )).scalar_one()
                    scans.append(scan)
                    newest_finding = (await session.execute(text("""
                        INSERT INTO vm.achado (scan_id, host_id, plugin_id, porta, severidade)
                        VALUES (:scan, :host, 990081, 0, 3) RETURNING id
                    """), {"scan": scan, "host": host})).scalar_one()
        for version, author, cost, age in [
            (2, users["bia"], "0.005", 1), (3, users["ana"], "0.002", 1),
            (4, None, "0.003", 1), (5, users["foreign"], "0.004", 1),
            (6, users["ana"], "0.008", 40),
        ]:
            await add_analysis(session, clients[0], workflows[0], version, author, cost, age)
        for status in ("unknown", "not_requested"):
            await session.execute(text("""
                INSERT INTO app.evento_auditoria
                    (cliente_id, usuario_id, acao, recurso, detalhes)
                VALUES (:client, :user, 'ai_analysis.failed', 'vulnerability',
                    jsonb_build_object('cost_status', CAST(:status AS text)))
            """), {"client": clients[0], "user": users["failures"], "status": status})
        await session.commit()
    return users, clients, workflows, scans, newest_finding


async def add_analysis(session, client, workflow, version, author, cost, age=1):
    await session.execute(text("""
        INSERT INTO app.vulnerabilidade_analise_ia
            (cliente_id, tratamento_id, geracao, ativa, provedor, modelo, versao_prompt,
             assinatura_entrada, conteudo, tokens_entrada, tokens_saida, tokens_total,
             custo_estimado_usd, criado_por, criado_em)
        VALUES (:client, :workflow, :version, false, 'anthropic', 'synthetic-model', 'test-v1',
                repeat('a',64), '{}'::jsonb, 100, 50, 150, :cost, :author,
                now() - make_interval(days => :age))
    """), {"client": client, "workflow": workflow, "version": version, "author": author,
           "cost": Decimal(cost), "age": age})


def test_usage_ranking_attribution_pagination_and_tenant_isolation():
    with TestClient(app) as client:
        users, clients, workflows, scans, newest = client.portal.call(seed_usage)

        def headers(user="admin", tenant=0):
            token = create_session_token(user_id=users[user], client_id=clients[tenant],
                                         role="administrador")
            return {"Cookie": f"ng_session={token}"}

        def get(path, **kwargs):
            return client.get(f"/api/v1/admin/ai/{path}", headers=headers(), **kwargs)

        summary = get("summary").json()
        people = summary["users"]
        assert [p["estimated_cost_usd"] for p in people] == [0.023, 0.005, 0.004, 0.003, 0]
        assert sum(Decimal(str(p["estimated_cost_usd"])) for p in people) == Decimal("0.035")
        assert sum(p["analyses"] for p in people) == summary["usage"]["analyses"] == 25
        assert sum(p["input_tokens"] for p in people) == summary["usage"]["input_tokens"]
        assert sum(p["output_tokens"] for p in people) == summary["usage"]["output_tokens"]
        assert people[0]["user_id"] == str(users["ana"])
        assert people[0]["vulnerabilities"] == 21 and people[0]["analyses"] == 22
        assert people[1]["active"] is False  # Deactivation does not erase costs.
        assert people[2]["name"] == "Usuário sem vínculo atual"
        assert people[3]["user_id"] is None
        assert people[4]["failures_unknown_cost"] == 1
        assert people[4]["configuration_blocks"] == 1
        assert "Pessoa foreign" not in str(summary)
        assert str(users["admin"]) not in str(people)  # Assignee is not the requester.

        url = f"users/{users['ana']}/vulnerabilities"
        params = {"days": 30, "as_of": summary["as_of"]}
        response = get(url, params=params)
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "private, no-store"
        detail = response.json()
        assert detail["total"] == 21 and len(detail["items"]) == 20
        assert detail["items"][0]["workflow_id"] == str(workflows[0])
        assert detail["items"][0]["finding_id"] == newest
        assert detail["items"][0]["analyses"] == 2
        second = get(url, params={**params, "page": 2}).json()
        assert len(second["items"]) == 1
        combined = detail["items"] + second["items"]
        assert len({item["workflow_id"] for item in combined}) == 21
        assert sum(Decimal(str(i["estimated_cost_usd"])) for i in combined) == Decimal("0.023")
        assert get(url, params={**params, "page": 3}).json()["items"] == []
        assert get(url, params={"page": 0}).status_code == 422
        assert get(url, params={"days": 8}).status_code == 422
        assert get(url, params={"as_of": "2026-01-01T00:00:00"}).status_code == 422
        assert get("users/not-a-uuid/vulnerabilities").status_code == 422
        unattributed = get("users/unattributed/vulnerabilities").json()
        assert unattributed["items"][0]["estimated_cost_usd"] == 0.003
        assert get(f"users/{users['failures']}/vulnerabilities").json()["items"] == []
        assert get("summary", params={"days": 7}).json()["usage"] == summary["usage"]
        older = get("summary", params={"days": 90}).json()
        assert older["usage"]["estimated_cost_usd"] == 0.043
        foreign = client.get("/api/v1/admin/ai/summary", headers=headers("foreign", 1)).json()
        assert foreign["usage"]["estimated_cost_usd"] == 99
        foreign_details = client.get(f"/api/v1/admin/ai/{url}", headers=headers("foreign", 1))
        assert foreign_details.json()["items"] == []

        async def delete_fixture_scans():
            async with session_factory() as session:
                for scan in scans:
                    await session.execute(text("DELETE FROM vm.scan WHERE id = :id"), {"id": scan})
                await session.commit()

        client.portal.call(delete_fixture_scans)
        after = get(url, params=params).json()
        assert after["items"][0]["finding_id"] is None
        assert after["items"][0]["estimated_cost_usd"] == 0.003
        assert get("summary").json()["usage"] == summary["usage"]

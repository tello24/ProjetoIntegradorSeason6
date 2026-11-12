import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException, Response

from app.api.dependencies import CurrentUser
from app.api.routes.ai_admin import (
    configuration_snapshot,
    get_ai_summary,
    get_user_ai_vulnerabilities,
)
from app.core.config import Settings
from app.services.ai_monitoring import record_ai_failure


@pytest.mark.parametrize("provider,key,state", [
    ("disabled", None, "disabled"),
    ("anthropic", None, "missing_key"),
    ("anthropic", "synthetic-private-key", "configured"),
    ("openai", None, "missing_key"),
    ("openai", "synthetic-private-key", "configured"),
])
def test_configuration_uses_allowlist_and_never_exposes_secrets(provider, key, state):
    config = Settings(_env_file=None, ai_provider=provider, anthropic_api_key=key,
                      openai_api_key=key, anthropic_workspace_id="private-workspace-id",
                      app_secret_key="synthetic-private-session-secret")
    snapshot = configuration_snapshot(config)
    assert snapshot.state == state
    assert snapshot.key_configured is (key is not None and provider != "disabled")
    serialized = snapshot.model_dump_json()
    assert "private" not in serialized
    assert "api_key" not in serialized
    assert "workspace_id" not in serialized
    assert "database_url" not in serialized


@pytest.mark.parametrize("role", ["analista", "gestor", "visualizador"])
async def test_admin_panel_checks_role_before_reading_data(role):
    session = AsyncMock()
    user = CurrentUser(uuid4(), "Test", "test@example.com", 12, "Test", role)
    with pytest.raises(HTTPException) as exc:
        await get_ai_summary(user, session, Response())
    assert exc.value.status_code == 403
    session.execute.assert_not_called()
    with pytest.raises(HTTPException) as exc:
        await get_user_ai_vulnerabilities(uuid4(), user, session, Response(), page=1)
    assert exc.value.status_code == 403
    session.execute.assert_not_called()


def result(row=None, rows=None):
    value = MagicMock()
    value.mappings.return_value.one.return_value = row
    value.mappings.return_value.all.return_value = rows or []
    return value


@pytest.mark.parametrize("days", ["7", "30", "90"])
async def test_summary_scopes_every_query_to_tenant_and_bounds_dates(days):
    now = datetime.now(UTC)
    usage = dict(analyses=2, input_tokens=1000, output_tokens=200,
                 estimated_cost_usd=Decimal("0.002"), last_success_at=now)
    session = AsyncMock()
    session.execute.side_effect = [
        result(row=usage),
        result(row=dict(failures=2, configuration_blocks=1, failures_unknown_cost=1)),
        result(rows=[{**usage, "provider": "anthropic", "model": "test-model"}]),
        result(rows=[dict(id=11, criado_em=now, provider="raw-private-text",
                         error_code="raw-private-text", cost_status=None)]),
        result(rows=[dict(**usage, user_id=None, name="Autoria não registrada", active=False,
                         vulnerabilities=1, failures_unknown_cost=1, configuration_blocks=1)]),
    ]
    user = CurrentUser(uuid4(), "Test", "test@example.com", 12, "Test", "administrador")
    response = Response()
    summary = await get_ai_summary(user, session, response, days=days)
    assert summary.usage.estimated_cost_usd == 0.002
    assert summary.usage.analyses == 2
    assert summary.failures_unknown_cost == 1
    assert summary.configuration_blocks == 1
    assert summary.users[0].analyses == 2
    assert summary.users[0].vulnerabilities == 1
    assert summary.users[0].user_id is None
    assert (summary.as_of - summary.period_start).days == int(days)
    assert response.headers["Cache-Control"] == "private, no-store"
    assert summary.recent_failures[0].error_code == "invalid_response"
    assert summary.recent_failures[0].cost_status == "unknown"
    assert "raw-private-text" not in summary.model_dump_json()
    for call in session.execute.call_args_list:
        query, params = call.args
        assert "cliente_id = :client_id" in str(query)
        assert params["client_id"] == 12
        assert params["since"] == summary.period_start
        assert params["as_of"] == summary.as_of
        assert "ativa = true" not in str(query)  # Count superseded paid versions too.
    session.commit.assert_not_called()


@pytest.mark.parametrize("unattributed", [False, True])
async def test_user_details_scope_author_tenant_period_and_page(unattributed):
    author = "unattributed" if unattributed else uuid4()
    user = CurrentUser(uuid4(), "Admin", "admin@example.com", 12, "Test", "administrador")
    session = AsyncMock()
    session.execute.side_effect = [result(row={"total": 21}), result(rows=[])]
    response = Response()
    end = datetime.now(UTC) - timedelta(seconds=1)
    detail = await get_user_ai_vulnerabilities(
        author, user, session, response, days="7", page=2, as_of=end,
    )
    assert detail.total == 21 and detail.page_size == 20
    assert detail.user_id == (None if unattributed else author)
    assert response.headers["Cache-Control"] == "private, no-store"
    for call in session.execute.call_args_list:
        query, params = call.args
        assert "cliente_id = :client_id" in str(query)
        assert "criado_por IS NOT DISTINCT FROM CAST(:user_id AS uuid)" in str(query)
        assert "ativa = true" not in str(query)
        assert params == {"client_id": 12, "user_id": detail.user_id,
                          "since": end - timedelta(days=7), "as_of": end,
                          "limit": 20, "offset": 20}
    session.commit.assert_not_called()


async def test_future_usage_snapshot_is_rejected_before_query():
    user = CurrentUser(uuid4(), "Admin", "admin@example.com", 12, "Test", "administrador")
    session = AsyncMock()
    with pytest.raises(HTTPException) as exc:
        await get_user_ai_vulnerabilities(
            user.id, user, session, Response(), page=1,
            as_of=datetime.now(UTC) + timedelta(days=1),
        )
    assert exc.value.status_code == 422
    session.execute.assert_not_called()


@pytest.mark.parametrize("code,expected", [
    ("disabled", "not_requested"), ("missing_key", "not_requested"),
    ("timeout", "unknown"), ("billing", "unknown"),
    ("private provider text must not be persisted", "unknown"),
])
async def test_failures_persist_only_safe_metadata_and_do_not_claim_zero_cost(code, expected):
    session = AsyncMock()
    await record_ai_failure(session=session, client_id=17, user_id=uuid4(),
                            workflow_id=uuid4(), provider="anthropic",
                            error_code=code, regenerate=True)
    params = session.execute.call_args.args[1]
    details = json.loads(params["details"])
    assert params["client_id"] == 17
    assert details["cost_status"] == expected
    assert set(details) == {"provider", "error_code", "regenerate", "cost_status"}
    assert "private" not in params["details"]
    assert "tokens" not in details and "estimated_cost_usd" not in details
    session.commit.assert_not_called()  # The caller owns the transaction.

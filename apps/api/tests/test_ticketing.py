import json
from dataclasses import replace
from urllib.error import HTTPError, URLError
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from app.api.routes.tickets import _ticket_draft
from app.core.config import JiraConfig, settings
from app.services.ticketing import JiraClient, TicketDraft, TicketProviderError
from app.services.ticketing import jira as jira_module
from app.services.ticketing.configuration import decrypt_token, encrypt_token

CONFIG = JiraConfig(
    base_url="https://example.atlassian.net",
    email="security@example.com",
    api_token="synthetic-secret",
    project_key="SEC",
    issue_type="Task",
    timeout_seconds=20,
    include_asset_details=False,
    app_public_url="https://wvm.example.com",
)


def connection_responses():
    return [
        {"accountId": "synthetic", "active": True},
        {
            "permissions": {
                key: {"havePermission": True} for key in ("BROWSE_PROJECTS", "CREATE_ISSUES")
            }
        },
        {"issueTypes": [{"id": "10001", "name": "Task", "subtask": False}], "isLast": True},
        {
            "fields": [
                {"fieldId": key}
                for key in ("project", "issuetype", "summary", "description", "labels")
            ],
            "isLast": True,
        },
    ]


def transport(monkeypatch, responses):
    calls = []

    def fake(request, *, timeout):
        calls.append(request)
        assert 0 < timeout <= 20
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return FakeResponse(item)

    monkeypatch.setattr(jira_module, "urlopen", fake)
    return calls


class FakeResponse:
    def __init__(self, body=None):
        self.body = body if body is not None else {"key": "SEC-42"}

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, size=-1) -> bytes:
        return json.dumps(self.body).encode()[:size] if size > 0 else json.dumps(self.body).encode()


def test_jira_client_builds_adf_issue_without_leaking_token(monkeypatch) -> None:
    captured = {}
    responses = connection_responses() + [{"key": "SEC-42"}]

    def fake_urlopen(request, *, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(responses.pop(0))

    monkeypatch.setattr(jira_module, "urlopen", fake_urlopen)
    config = JiraConfig(
        base_url="https://example.atlassian.net",
        email="security@example.com",
        api_token="secret-token",
        project_key="SEC",
        issue_type="Task",
        timeout_seconds=20,
        include_asset_details=False,
        app_public_url="https://wvm.example.com",
    )

    created = JiraClient(config).create_issue(
        TicketDraft(
            summary="[WVM][ALTA] Atualizar pacote",
            description_lines=("WVM Score: 72/100", "Ativo: omitido"),
            stable_label="wvm-123",
        )
    )

    assert created.external_key == "SEC-42"
    assert created.external_url == "https://example.atlassian.net/browse/SEC-42"
    assert 0 < captured["timeout"] <= 20
    request = captured["request"]
    payload = json.loads(request.data.decode())
    assert payload["fields"]["project"] == {"key": "SEC"}
    assert payload["fields"]["labels"] == ["wvm", "wvm-123"]
    assert payload["fields"]["description"]["type"] == "doc"
    assert "secret-token" not in request.data.decode()


@pytest.mark.parametrize(
    "url",
    [
        "http://example.atlassian.net",
        "https://localhost",
        "https://127.0.0.1",
        "https://example.atlassian.net.evil.com",
        "https://user:token@example.atlassian.net",
        "https://example.atlassian.net:443",
        "https://example.atlassian.net/path",
        "https://example.atlassian.net?token=x",
    ],
)
def test_only_jira_cloud_sites_are_allowed(url):
    with pytest.raises(TicketProviderError, match="HTTPS"):
        JiraClient(replace(CONFIG, base_url=url))


def test_connection_check_does_not_create_issue(monkeypatch):
    calls = transport(monkeypatch, connection_responses())
    assert JiraClient(CONFIG).check_connection()["issue_type_id"] == "10001"
    assert all(call.method == "GET" for call in calls)


def test_custom_required_fields_block_creation_before_post(monkeypatch):
    responses = connection_responses()
    responses[-1]["fields"].append({"fieldId": "customfield_1000", "required": True})
    calls = transport(monkeypatch, responses)
    with pytest.raises(TicketProviderError) as error:
        JiraClient(CONFIG).create_issue(TicketDraft("test", ("test",), "wvm-test"))
    assert error.value.code == "required_fields"
    assert not error.value.uncertain
    assert all(call.method == "GET" for call in calls)


@pytest.mark.parametrize(
    "failure,uncertain",
    [
        (TimeoutError(), True),
        (URLError("sensitive diagnostic"), True),
        (HTTPError("url", 503, "secret", {}, None), True),
        (HTTPError("url", 401, "secret", {}, None), False),
        (HTTPError("url", 429, "secret", {}, None), False),
        (HTTPError("url", 302, "secret", {"Location": "https://evil.test"}, None), False),
        ({"key": "javascript:bad"}, True),
    ],
)
def test_remote_result_is_classified_without_secret_or_retry(monkeypatch, failure, uncertain):
    calls = transport(monkeypatch, connection_responses() + [failure])
    with pytest.raises(TicketProviderError) as error:
        JiraClient(CONFIG).create_issue(TicketDraft("test", ("test",), "wvm-test"))
    assert error.value.uncertain is uncertain
    assert "secret" not in str(error.value)
    assert len(calls) == 5


def test_scoped_token_cannot_target_another_site(monkeypatch):
    calls = transport(monkeypatch, [{"baseUrl": "https://different.atlassian.net"}])
    with pytest.raises(TicketProviderError) as error:
        JiraClient(replace(CONFIG, cloud_id=str(uuid4()))).check_connection()
    assert error.value.code == "site_mismatch"
    assert calls[0].full_url.startswith("https://api.atlassian.com/ex/jira/")


def test_reconcile_only_reads_and_validates_project_and_label(monkeypatch):
    label = f"wvm-{uuid4()}"
    calls = transport(
        monkeypatch,
        [
            {
                "issues": [
                    {"key": "SEC-42", "fields": {"labels": [label], "project": {"key": "SEC"}}}
                ],
                "isLast": True,
            }
        ],
    )
    assert JiraClient(CONFIG).find_issue(label).external_key == "SEC-42"
    assert len(calls) == 1 and calls[0].method == "GET"
    transport(monkeypatch, [{"issues": [], "isLast": True}])
    with pytest.raises(TicketProviderError) as error:
        JiraClient(CONFIG).find_issue(label)
    assert error.value.uncertain
    assert error.value.code == "unconfirmed"


def test_tokens_are_encrypted_bound_to_tenant_and_support_rotation(monkeypatch):
    old_key, new_key = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "integration_encryption_keys", SecretStr(old_key))
    encrypted = encrypt_token(123, "synthetic-secret")
    assert "synthetic-secret" not in encrypted
    assert decrypt_token(123, encrypted) == "synthetic-secret"
    with pytest.raises(TicketProviderError):
        decrypt_token(456, encrypted)
    monkeypatch.setattr(settings, "integration_encryption_keys", SecretStr(f"{new_key},{old_key}"))
    assert decrypt_token(123, encrypted) == "synthetic-secret"
    renewed = encrypt_token(123, "synthetic-secret")
    monkeypatch.setattr(settings, "integration_encryption_keys", SecretStr(new_key))
    assert decrypt_token(123, renewed) == "synthetic-secret"
    with pytest.raises(TicketProviderError):
        decrypt_token(123, encrypted)


def test_ticket_draft_omits_asset_details_by_default() -> None:
    draft = _ticket_draft(
        {
            "titulo": "Pacote desatualizado",
            "severidade": 3,
            "endereco": "192.0.2.10",
            "fqdn": "host.example.com",
            "cves": ["CVE-2099-0001"],
            "protocolo": "tcp",
            "porta": 443,
            "servico": "https",
            "cvss2": None,
            "cvss3": 8.1,
            "cvss4": None,
            "solucao": "Atualizar o pacote.",
            "workflow_id": uuid4(),
            "neo_score": 72,
            "ai_content": None,
        },
        finding_id=42,
        include_asset_details=False,
        app_public_url="https://wvm.example.com",
    )

    rendered = "\n".join(draft.description_lines)
    assert "192.0.2.10" not in rendered
    assert "host.example.com" not in rendered
    assert "Omitido pela política" in rendered
    assert "https://wvm.example.com/vulnerabilities/42" in rendered

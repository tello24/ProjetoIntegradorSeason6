import json
from uuid import uuid4

from app.api.routes.tickets import _ticket_draft
from app.core.config import JiraConfig
from app.services.ticketing import JiraClient, TicketDraft
from app.services.ticketing import jira as jira_module


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self) -> bytes:
        return b'{"key":"SEC-42"}'


def test_jira_client_builds_adf_issue_without_leaking_token(monkeypatch) -> None:
    captured = {}

    def fake_urlopen(request, *, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

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
    assert captured["timeout"] == 20
    request = captured["request"]
    payload = json.loads(request.data.decode())
    assert payload["fields"]["project"] == {"key": "SEC"}
    assert payload["fields"]["labels"] == ["wvm", "wvm-123"]
    assert payload["fields"]["description"]["type"] == "doc"
    assert "secret-token" not in request.data.decode()


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

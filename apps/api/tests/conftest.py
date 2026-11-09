"""Provider access is always mocked, even when the developer has a live key in .env."""

from urllib import request

import pytest

from app.services.ticketing import jira


@pytest.fixture(autouse=True)
def block_live_provider_requests(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail("Chamada externa bloqueada no teste; use uma resposta simulada.")

    # AI uses request.urlopen; Jira imports its own alias. Individual tests may
    # replace either with a fake response, but never need a real key or balance.
    monkeypatch.setattr(request, "urlopen", blocked)
    monkeypatch.setattr(jira, "urlopen", blocked)

from urllib import request

import pytest

from app.services.ticketing import jira


@pytest.mark.parametrize("connector", [request, jira])
def test_real_provider_requests_are_blocked_in_tests(connector):
    with pytest.raises(pytest.fail.Exception, match="Chamada externa bloqueada"):
        connector.urlopen("https://example.com/must-never-be-contacted")

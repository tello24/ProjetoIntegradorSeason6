import base64
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from app.core.config import JiraConfig
from app.services.ticketing.models import CreatedTicket, TicketDraft


class TicketProviderError(RuntimeError):
    """Safe, user-facing error returned by an external ticket provider."""


class JiraClient:
    def __init__(self, config: JiraConfig) -> None:
        self.config = config
        _validate_base_url(config.base_url)

    def create_issue(self, draft: TicketDraft) -> CreatedTicket:
        endpoint = f"{self.config.base_url}/rest/api/3/issue"
        token = base64.b64encode(
            f"{self.config.email}:{self.config.api_token}".encode()
        ).decode()
        payload = {
            "fields": {
                "project": {"key": self.config.project_key},
                "summary": draft.summary[:255],
                "issuetype": {"name": self.config.issue_type},
                "labels": ["wvm", draft.stable_label],
                "description": _adf_document(draft.description_lines),
            }
        }
        request = Request(
            endpoint,
            data=json.dumps(payload, ensure_ascii=False).encode(),
            headers={
                "Accept": "application/json",
                "Authorization": f"Basic {token}",
                "Content-Type": "application/json",
                "User-Agent": "WVM/0.1",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:  # noqa: S310
                body = json.loads(response.read().decode())
        except HTTPError as exc:
            detail = _jira_error_detail(exc)
            raise TicketProviderError(
                f"O Jira recusou a criação do ticket ({exc.code}). {detail}"
            ) from exc
        except URLError as exc:
            raise TicketProviderError(
                "Não foi possível conectar ao Jira. Confira a URL e a rede do servidor."
            ) from exc
        except (TimeoutError, json.JSONDecodeError) as exc:
            raise TicketProviderError(
                "O Jira não respondeu corretamente dentro do tempo esperado."
            ) from exc

        key = str(body.get("key") or "").strip()
        if not key:
            raise TicketProviderError("O Jira criou a solicitação sem retornar a chave do ticket.")
        return CreatedTicket(
            external_key=key,
            external_url=f"{self.config.base_url}/browse/{key}",
        )


def _adf_document(lines: tuple[str, ...]) -> dict[str, object]:
    content = [
        {
            "type": "paragraph",
            "content": [{"type": "text", "text": line[:3000]}],
        }
        for line in lines
        if line.strip()
    ]
    return {"version": 1, "type": "doc", "content": content}


def _jira_error_detail(exc: HTTPError) -> str:
    try:
        payload = json.loads(exc.read().decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "Confira projeto, tipo de item e credenciais."

    messages = [str(message) for message in payload.get("errorMessages", [])]
    messages.extend(str(message) for message in payload.get("errors", {}).values())
    return " ".join(messages)[:300] or "Confira projeto, tipo de item e credenciais."


def _validate_base_url(base_url: str) -> None:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise TicketProviderError("A URL configurada para o Jira é inválida.")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
        raise TicketProviderError("A integração com Jira exige HTTPS fora do ambiente local.")

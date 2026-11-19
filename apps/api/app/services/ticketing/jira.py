"""Bounded Jira Cloud transport. No redirects, retries, or raw provider errors."""

import base64
import json
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

from app.core.config import JiraConfig
from app.services.ticketing.models import CreatedTicket, TicketDraft

ERRORS = {
    "configuration": "Confira o endereço HTTPS do Jira Cloud e a chave do projeto.",
    "authentication": "O Jira recusou as credenciais. Confira o e-mail e o token.",
    "permission": "A conta precisa consultar o projeto e criar itens nele.",
    "not_found": "Projeto ou recurso não encontrado no Jira.",
    "required_fields": "Este tipo exige campos adicionais ou não permite descrição e etiquetas. "
    "Ajuste a configuração do Jira antes de ativar.",
    "issue_type": "Tipo de item não encontrado ou é uma subtarefa. "
    "Informe o nome exato ou ID de um tipo comum.",
    "rate_limit": "O Jira limitou as solicitações. Aguarde antes de tentar novamente.",
    "rejected": "O Jira recusou os campos enviados. Revise a configuração do projeto.",
    "connection": "Não foi possível concluir a comunicação com o Jira.",
    "response": "O Jira retornou uma resposta que não pôde ser validada.",
    "redirect": "O Jira redirecionou a solicitação. Confira o endereço; "
    "credenciais não foram encaminhadas.",
    "site_mismatch": "O Cloud ID não corresponde ao endereço Jira cadastrado.",
    "ambiguous": "Mais de um ticket corresponde ao vínculo. Confira os itens diretamente no Jira.",
    "unconfirmed": "Ainda não encontramos um ticket confirmado. A busca do Jira pode levar "
    "tempo para atualizar; nenhuma nova criação será feita.",
    "legacy_uncertain": "Tentativa antiga sem destino confirmado. "
    "Confira o Jira antes de qualquer nova criação.",
    "credentials": "As credenciais não podem ser lidas. "
    "Confira a chave de criptografia do servidor.",
    "disabled": "Peça ao administrador para configurar, testar e ativar o Jira desta empresa.",
}


class TicketProviderError(RuntimeError):
    def __init__(self, code: str, *, uncertain: bool = False):
        self.code = code if code in ERRORS else "response"
        self.uncertain = uncertain
        super().__init__(ERRORS[self.code])


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Named seam also blocked by the test suite's network guard.
urlopen = build_opener(ProxyHandler({}), _NoRedirect()).open


def validate_cloud_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    if not re.fullmatch(
        r"https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.atlassian\.net", normalized
    ):
        raise TicketProviderError("configuration")
    return normalized


class JiraClient:
    def __init__(self, config: JiraConfig):
        self.config = config
        self.site = validate_cloud_url(config.base_url)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,29}", config.project_key):
            raise TicketProviderError("configuration")
        self.base = self.site
        if config.cloud_id:
            try:
                cloud_id = str(UUID(config.cloud_id))
            except ValueError:
                raise TicketProviderError("configuration") from None
            self.base = f"https://api.atlassian.com/ex/jira/{cloud_id}"
        self.deadline = time.monotonic() + config.timeout_seconds

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TicketProviderError("connection")
        creating = method == "POST"
        auth = base64.b64encode(f"{self.config.email}:{self.config.api_token}".encode()).decode()
        request = Request(
            self.base + path,
            method=method,
            data=json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None,
            headers={
                "Authorization": f"Basic {auth}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "WVM/0.1",
            },
        )
        try:
            with urlopen(request, timeout=remaining) as response:  # noqa: S310
                raw = response.read(1_048_577)
            if len(raw) > 1_048_576:
                raise TicketProviderError("response", uncertain=creating)
            body = json.loads(raw.decode())
            if not isinstance(body, dict):
                raise TicketProviderError("response", uncertain=creating)
            return body
        except HTTPError as exc:
            code = {
                400: "rejected",
                401: "authentication",
                403: "permission",
                404: "not_found",
                422: "rejected",
                429: "rate_limit",
            }.get(exc.code)
            if 300 <= exc.code < 400:
                code = "redirect"
            exc.close()
            raise TicketProviderError(
                code or "connection", uncertain=creating and code is None
            ) from None
        except (URLError, OSError, TimeoutError):
            raise TicketProviderError("connection", uncertain=creating) from None
        except (ValueError, UnicodeError):
            raise TicketProviderError("response", uncertain=creating) from None

    def _pages(self, path: str, collection: str) -> list[dict]:
        items: list[dict] = []
        for _ in range(10):
            body = self._request("GET", f"{path}?startAt={len(items)}&maxResults=100")
            batch = body.get(collection, body.get("values"))
            if not isinstance(batch, list) or not all(isinstance(item, dict) for item in batch):
                raise TicketProviderError("response")
            items.extend(batch)
            total = body.get("total")
            if body.get("isLast") is True or isinstance(total, int) and len(items) >= total:
                return items
            if not batch:
                break
        raise TicketProviderError("response")

    def check_connection(self) -> dict:
        if self.config.cloud_id:
            info = self._request("GET", "/rest/api/3/serverInfo")
            if str(info.get("baseUrl", "")).rstrip("/") != self.site:
                raise TicketProviderError("site_mismatch")
        me = self._request("GET", "/rest/api/3/myself")
        if not me.get("accountId") or me.get("active") is False:
            raise TicketProviderError("authentication")
        query = urlencode(
            {"projectKey": self.config.project_key, "permissions": "BROWSE_PROJECTS,CREATE_ISSUES"}
        )
        permissions = self._request("GET", f"/rest/api/3/mypermissions?{query}").get("permissions")
        if not isinstance(permissions, dict) or any(
            not isinstance(permissions.get(key), dict)
            or permissions[key].get("havePermission") is not True
            for key in ("BROWSE_PROJECTS", "CREATE_ISSUES")
        ):
            raise TicketProviderError("permission")
        path = f"/rest/api/3/issue/createmeta/{self.config.project_key}/issuetypes"
        types = self._pages(path, "issueTypes")
        matching = [
            item
            for item in types
            if not item.get("subtask")
            and self.config.issue_type in (str(item.get("id")), item.get("name"))
        ]
        if len(matching) != 1 or not re.fullmatch(r"\d+", str(matching[0].get("id", ""))):
            raise TicketProviderError("issue_type")
        item_type = matching[0]
        fields = self._pages(f"{path}/{item_type['id']}", "fields")
        supported = {"project", "issuetype", "summary", "description", "labels"}
        keys = {field.get("fieldId", field.get("key")) for field in fields}
        if not {"summary", "description", "labels"}.issubset(keys) or any(
            field.get("required")
            and not field.get("hasDefaultValue")
            and field.get("fieldId", field.get("key")) not in supported
            for field in fields
        ):
            raise TicketProviderError("required_fields")
        return {
            "project_key": self.config.project_key,
            "issue_type_id": str(item_type["id"]),
            "issue_type_name": str(item_type.get("name", ""))[:80],
        }

    def create_issue(self, draft: TicketDraft) -> CreatedTicket:
        metadata = self.check_connection()
        result = self._request(
            "POST",
            "/rest/api/3/issue",
            {
                "fields": {
                    "project": {"key": self.config.project_key},
                    "summary": draft.summary[:255],
                    "issuetype": {"id": metadata["issue_type_id"]},
                    "labels": ["wvm", draft.stable_label],
                    "description": _adf_document(draft.description_lines),
                }
            },
        )
        return self._created(result)

    def _created(self, body: dict) -> CreatedTicket:
        key = str(body.get("key", ""))
        if not re.fullmatch(re.escape(self.config.project_key) + r"-[1-9]\d*", key):
            raise TicketProviderError("response", uncertain=True)
        return CreatedTicket(external_key=key, external_url=f"{self.site}/browse/{key}")

    def find_issue(self, label: str) -> CreatedTicket:
        if not re.fullmatch(r"wvm-[a-f0-9-]{36}", label):
            raise TicketProviderError("configuration")
        query = urlencode(
            {
                "jql": f'project = "{self.config.project_key}" AND labels = "{label}"',
                "maxResults": 2,
                "fields": "labels,project",
            }
        )
        body = self._request("GET", f"/rest/api/3/search/jql?{query}")
        issues = body.get("issues")
        if not isinstance(issues, list):
            raise TicketProviderError("response", uncertain=True)
        if not issues:
            raise TicketProviderError("unconfirmed", uncertain=True)
        if len(issues) != 1 or body.get("isLast") is False or body.get("nextPageToken"):
            raise TicketProviderError("ambiguous", uncertain=True)
        issue = issues[0]
        fields = issue.get("fields") if isinstance(issue, dict) else None
        project = fields.get("project") if isinstance(fields, dict) else None
        if (
            not isinstance(project, dict)
            or project.get("key") != self.config.project_key
            or not isinstance(fields.get("labels"), list)
            or label not in fields["labels"]
        ):
            raise TicketProviderError("response", uncertain=True)
        return self._created(issue)


def _adf_document(lines: tuple[str, ...]) -> dict:
    return {
        "version": 1,
        "type": "doc",
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": line[:3000]}]}
            for line in lines[:60]
            if line.strip()
        ],
    }

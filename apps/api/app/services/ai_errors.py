"""Safe, actionable AI diagnostics without returning provider bodies or credentials."""

import json
from urllib import error

ERROR_MESSAGES = {
    "disabled": "A IA está desativada. Configure AI_PROVIDER no .env e recrie o serviço da API.",
    "missing_key": "O provedor foi selecionado, mas sua chave não está configurada na API. "
    "Preencha a chave no .env local e recrie o serviço da API.",
    "authentication": "O provedor recusou a chave de API. Confira se ela está válida e ativa.",
    "billing": "O provedor informou um bloqueio de cobrança, saldo ou limite de gastos. "
    "Confira o faturamento e os limites da organização/workspace.",
    "permission": "A chave não tem permissão para este recurso. Confira o workspace e o modelo.",
    "model_not_found": "O recurso solicitado não foi encontrado. Confira o modelo configurado.",
    "rate_limit": "O provedor atingiu um limite de uso. "
    "Confira os limites antes de tentar novamente.",
    "provider_unavailable": "O provedor está temporariamente indisponível. Tente novamente depois.",
    "timeout": "A IA não concluiu a resposta dentro do prazo. Confira a conexão e "
    "AI_TIMEOUT_SECONDS antes de tentar novamente.",
    "connection": "A API não conseguiu se conectar ao provedor. Confira internet, proxy e TLS.",
    "request_rejected": "O provedor rejeitou a solicitação. Confira a compatibilidade do modelo "
    "com respostas estruturadas e os parâmetros configurados.",
    "output_limit": "A resposta foi interrompida pelo limite de tokens de saída. "
    "Revise AI_MAX_OUTPUT_TOKENS com o administrador antes de uma nova tentativa.",
    "refusal": "O provedor recusou gerar esta resposta. "
    "Revise o contexto com o responsável técnico.",
    "unsafe_response": "A resposta foi rejeitada por contradizer a evidência ou sugerir uma ação "
    "insegura. Revise os dados técnicos; o plano-base permanece disponível.",
    "invalid_response": "A resposta recebida não passou pela validação de formato da aplicação.",
}


class AIResponseError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def classify_ai_error(exc: Exception) -> str:
    if isinstance(exc, AIResponseError):
        return exc.code
    if isinstance(exc, error.HTTPError):
        # Inspect a bounded error body only for classification. Never log/return its contents.
        message = ""
        try:
            payload = json.loads(exc.read(16_384))
            detail = payload.get("error", {}) if isinstance(payload, dict) else {}
            if isinstance(detail, dict):
                message = str(detail.get("message", "")).lower()
        except (OSError, TypeError, ValueError):
            pass
        if exc.code == 402 or (
            exc.code in {400, 429}
            and any(
                fragment in message
                for fragment in (
                    "credit balance",
                    "spend limit",
                    "spending limit",
                    "insufficient_quota",
                )
            )
        ):
            return "billing"
        if exc.code in {408, 504}:
            return "timeout"
        if exc.code >= 500:
            return "provider_unavailable"
        return {
            401: "authentication",
            403: "permission",
            404: "model_not_found",
            429: "rate_limit",
        }.get(exc.code, "request_rejected")
    if isinstance(exc, TimeoutError) or (
        isinstance(exc, error.URLError) and isinstance(exc.reason, TimeoutError)
    ):
        return "timeout"
    if isinstance(exc, (error.URLError, OSError)):
        return "connection"
    return "invalid_response"


def ai_failure_warning(code: str) -> str:
    reason = ERROR_MESSAGES.get(code, ERROR_MESSAGES["invalid_response"])
    if code in {"disabled", "missing_key"}:
        return reason + " Nenhuma chamada de IA foi feita nesta tentativa."
    return reason + (
        " Nenhuma nova análise foi salva. O custo da tentativa não foi confirmado pela "
        "aplicação; o provedor pode contabilizar os tokens processados. "
        "Não haverá nova tentativa automática."
    )

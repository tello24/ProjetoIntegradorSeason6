import json
from io import BytesIO
from urllib import error

import pytest

from app.services.ai_errors import AIResponseError, ai_failure_warning, classify_ai_error


@pytest.mark.parametrize(
    ("status", "message", "code"),
    [
        (400, "Your credit balance is too low", "billing"),
        (400, "Workspace spend limit reached", "billing"),
        (400, "Invalid schema", "request_rejected"),
        (401, "Invalid key", "authentication"),
        (402, "Payment required", "billing"),
        (403, "Permission denied", "permission"),
        (404, "Model not found", "model_not_found"),
        (429, "Too many requests", "rate_limit"),
        (429, "Monthly spend limit reached", "billing"),
        (500, "Internal error", "provider_unavailable"),
        (504, "Timeout", "timeout"),
        (529, "Overloaded", "provider_unavailable"),
    ],
)
def test_http_error_is_classified_without_exposing_body(status, message, code):
    secret = "sensitive-test-key-must-not-appear"
    body = json.dumps({"error": {"message": message + " " + secret}}).encode()
    exc = error.HTTPError("https://example.com", status, "Failed", {}, BytesIO(body))
    assert classify_ai_error(exc) == code
    assert secret not in ai_failure_warning(code)


def test_malformed_error_body_does_not_hide_http_status():
    exc = error.HTTPError("https://example.com", 401, "Failed", {}, BytesIO(b"<html>bad</html>"))
    assert classify_ai_error(exc) == "authentication"


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (TimeoutError(), "timeout"),
        (error.URLError(TimeoutError()), "timeout"),
        (error.URLError("DNS unavailable"), "connection"),
        (ValueError("private response"), "invalid_response"),
        (AIResponseError("output_limit"), "output_limit"),
        (AIResponseError("unsafe_response"), "unsafe_response"),
    ],
)
def test_non_http_errors(exc, code):
    assert classify_ai_error(exc) == code


def test_configuration_failures_do_not_claim_a_provider_call():
    for code in ("disabled", "missing_key"):
        assert "Nenhuma chamada de IA" in ai_failure_warning(code)
    assert "custo da tentativa não foi confirmado" in ai_failure_warning("timeout")

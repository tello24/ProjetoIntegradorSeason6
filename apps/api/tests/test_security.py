from uuid import uuid4

import jwt
import pytest
from pydantic import ValidationError

from app.core.config import DEVELOPMENT_SECRET, Settings, settings
from app.core.security import (
    SessionTokenError,
    create_session_token,
    decode_session_token,
    hash_password,
    verify_password,
)


def test_password_hash_is_not_plaintext_and_can_be_verified() -> None:
    encoded = hash_password("A-strong-local-password-2026!")

    assert encoded != "A-strong-local-password-2026!"
    assert verify_password("A-strong-local-password-2026!", encoded) is True
    assert verify_password("wrong-password", encoded) is False


def test_session_token_contains_tenant_context() -> None:
    user_id = uuid4()
    token = create_session_token(user_id=user_id, client_id=42, role="analista")

    payload = decode_session_token(token)

    assert payload["sub"] == str(user_id)
    assert payload["client_id"] == 42
    assert payload["role"] == "analista"


def test_tampered_session_token_is_rejected() -> None:
    token = create_session_token(user_id=uuid4(), client_id=7, role="administrador")
    tampered = f"{token[:-2]}xx"

    with pytest.raises(SessionTokenError):
        decode_session_token(tampered)


@pytest.mark.parametrize("case", ["expired", "wrong-issuer", "missing-expiration"])
def test_session_claims_remain_required_after_jwt_upgrade(case: str) -> None:
    token = create_session_token(user_id=uuid4(), client_id=7, role="analista")
    payload = decode_session_token(token)
    if case == "expired":
        payload["exp"] = 1
    elif case == "wrong-issuer":
        payload["iss"] = "untrusted-issuer"
    else:
        del payload["exp"]
    altered = jwt.encode(payload, settings.app_secret_key, algorithm="HS256")

    with pytest.raises(SessionTokenError):
        decode_session_token(altered)


@pytest.mark.parametrize("algorithm", ["none", "HS384"])
def test_only_the_configured_session_algorithm_is_accepted(algorithm: str, monkeypatch) -> None:
    monkeypatch.setattr(settings, "app_secret_key", "test-session-signing-key-" * 4)
    token = create_session_token(user_id=uuid4(), client_id=7, role="analista")
    payload = decode_session_token(token)
    key = None if algorithm == "none" else settings.app_secret_key
    altered = jwt.encode(payload, key, algorithm=algorithm)

    with pytest.raises(SessionTokenError):
        decode_session_token(altered)


def test_production_rejects_the_known_development_secret() -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            app_env="production",
            app_secret_key=DEVELOPMENT_SECRET,
        )


def test_cors_origins_accept_comma_separated_environment_format() -> None:
    configured = Settings(
        _env_file=None,
        api_cors_origins="http://localhost:3000, https://insight.example.com",
    )

    assert configured.cors_origins == [
        "http://localhost:3000",
        "https://insight.example.com",
    ]


def test_cors_origins_accept_json_array_environment_format() -> None:
    configured = Settings(
        _env_file=None,
        api_cors_origins='["http://localhost:3000", "https://insight.example.com"]',
    )

    assert configured.cors_origins == [
        "http://localhost:3000",
        "https://insight.example.com",
    ]


def test_active_ai_selects_anthropic_without_exposing_other_provider() -> None:
    configured = Settings(
        _env_file=None,
        ai_provider="anthropic",
        anthropic_api_key="anthropic-test-key",
        anthropic_workspace_id="wrkspc_test",
        anthropic_model="claude-haiku-4-5",
        openai_api_key="openai-test-key",
    )

    assert configured.active_ai is not None
    assert configured.active_ai.provider == "anthropic"
    assert configured.active_ai.api_key == "anthropic-test-key"
    assert configured.active_ai.model == "claude-haiku-4-5"
    assert configured.active_ai.workspace_id == "wrkspc_test"


def test_active_ai_is_disabled_when_selected_key_is_missing() -> None:
    configured = Settings(
        _env_file=None,
        ai_provider="anthropic",
        anthropic_api_key="",
    )

    assert configured.active_ai is None

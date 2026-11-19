import pytest
from pydantic import SecretStr

from app.core.config import settings
from app.services import password_mail


@pytest.mark.parametrize("security", ["ssl", "starttls"])
def test_mail_requires_tls_and_never_includes_password(monkeypatch, security):
    for key, value in {
        "password_email_enabled": True,
        "smtp_host": "smtp.example.com",
        "smtp_from": "wvm@example.com",
        "smtp_username": "wvm",
        "smtp_password": SecretStr("synthetic-smtp-secret"),
        "smtp_security": security,
        "app_public_url": "https://wvm.example.com",
    }.items():
        monkeypatch.setattr(settings, key, value)
    events = []
    messages = []

    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            events.append("ssl" if "context" in kwargs else "connect")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def starttls(self, *, context):
            assert context.check_hostname
            events.append("tls")

        def login(self, username, password):
            assert events[-1] in {"ssl", "tls"}
            events.append("login")

        def send_message(self, message):
            messages.append(message)

    monkeypatch.setattr(password_mail.smtplib, "SMTP_SSL", FakeSMTP)
    monkeypatch.setattr(password_mail.smtplib, "SMTP", FakeSMTP)
    assert password_mail.send_password_mail("test@example.com", "a" * 43)
    assert "#token=" in messages[0].get_content()
    assert "synthetic-smtp-secret" not in messages[0].as_string()
    assert password_mail.send_password_mail("test@example.com")
    assert "#token=" not in messages[1].get_content()


def test_disabled_or_unsafe_public_url_does_not_send(monkeypatch):
    monkeypatch.setattr(settings, "password_email_enabled", False)
    assert not password_mail.send_password_mail("test@example.com", "a" * 43)
    monkeypatch.setattr(settings, "password_email_enabled", True)
    monkeypatch.setattr(settings, "app_public_url", "http://untrusted.example.com")
    assert not password_mail.mail_ready()

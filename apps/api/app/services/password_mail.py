"""SMTP with mandatory transport encryption; never log message contents or exceptions."""

import logging
import smtplib
import ssl
from email.message import EmailMessage
from urllib.parse import urlsplit

from app.core.config import settings

logger = logging.getLogger(__name__)


def mail_ready() -> bool:
    url = urlsplit(settings.app_public_url)
    safe_url = (
        url.scheme == "https"
        or settings.is_development
        and url.scheme == "http"
        and url.hostname in {"localhost", "127.0.0.1"}
    )
    return bool(
        settings.password_email_enabled
        and settings.smtp_host
        and settings.smtp_from
        and safe_url
        and url.netloc
        and not url.username
        and not url.query
        and not url.fragment
    )


def send_password_mail(email: str, token: str | None = None) -> bool:
    if not mail_ready():
        return False
    message = EmailMessage()
    message["From"] = str(settings.smtp_from)
    message["To"] = email
    message["Subject"] = "WVM — recuperação de senha" if token else "WVM — senha alterada"
    if token:
        # Fragment is not sent in HTTP requests or Referer; browser removes it on load.
        link = settings.app_public_url.rstrip("/") + "/reset-password#token=" + token
        message.set_content(
            f"Para escolher uma nova senha, abra:\n{link}\n\n"
            "Este link vale por 20 minutos e só pode ser usado uma vez. "
            "Se não solicitou, ignore esta mensagem. Não compartilhe o link."
        )
    else:
        message.set_content(
            "Sua senha do WVM foi alterada e as sessões anteriores foram encerradas. "
            "Se não reconhece esta alteração, contate o administrador imediatamente."
        )
    try:
        context = ssl.create_default_context()
        if settings.smtp_security == "ssl":
            connection = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, timeout=10, context=context
            )
        else:
            connection = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10)
        with connection as smtp:
            if settings.smtp_security == "starttls":
                smtp.starttls(context=context)
            if settings.smtp_username:
                smtp.login(
                    settings.smtp_username,
                    settings.smtp_password.get_secret_value() if settings.smtp_password else "",
                )
            smtp.send_message(message)
        return True
    except Exception:
        logger.warning("password_email_delivery_failed")
        return False

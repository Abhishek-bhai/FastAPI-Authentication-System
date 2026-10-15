import logging
import smtplib
import ssl
from email.message import EmailMessage

from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailDeliveryError(RuntimeError):
    """Raised when the configured SMTP server cannot deliver an email."""


def send_email(subject: str, recipient: str, body: str) -> None:
    if (
        not settings.smtp_host
        or settings.smtp_host == "smtp.example.com"
        or not settings.smtp_from
        or settings.smtp_from == "noreply@example.com"
    ):
        raise EmailDeliveryError("SMTP is not configured")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = recipient
    message.set_content(body)
    context = ssl.create_default_context()

    try:
        if settings.smtp_port == 465:
            with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=15, context=context) as server:
                if settings.smtp_username and settings.smtp_password:
                    server.login(settings.smtp_username, settings.smtp_password)
                server.send_message(message)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                if settings.smtp_username and settings.smtp_password:
                    server.login(settings.smtp_username, settings.smtp_password)
                server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        logger.warning("SMTP delivery failed for recipient domain %s", recipient.rpartition("@")[2])
        raise EmailDeliveryError("Email delivery failed") from exc

    logger.info("Email delivered to recipient domain %s", recipient.rpartition("@")[2])

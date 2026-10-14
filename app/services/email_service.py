import logging

logger = logging.getLogger(__name__)


def send_email(subject: str, recipient: str, body: str) -> None:
    logger.info("Email sent: %s -> %s", subject, recipient)
    logger.debug("Email body omitted for security reasons.")

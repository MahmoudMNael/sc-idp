import smtplib
from email.message import EmailMessage

from src.core.settings import Settings


def send_mail(settings: Settings, to: str, subject: str, body: str) -> None:
    sender = settings.smtp_from or "noreply@localhost"
    if settings.mail_backend != "smtp":
        print(f"[mail] to={to} subject={subject}\n{body}\n")
        return
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        smtp.starttls()
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(msg)

import smtplib
from email.message import EmailMessage
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.core.settings import Settings

_TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def render_mail_template(template_name: str, **context) -> str:
    template = _env.get_template(template_name)
    return template.render(**context)


def send_mail(
    settings: Settings,
    to: str,
    subject: str,
    body: str,
    html: str | None = None,
    *args,
    **kwargs,
) -> None:
    sender = settings.smtp_from or "noreply@localhost"
    if settings.mail_backend != "smtp":
        print(f"[mail] to={to} subject={subject}\n{body}\n")
        return
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        smtp.starttls()
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(msg)


def send_otp_register_mail(settings: Settings, to: str, code: str) -> None:
    base_url = settings.idp_issuer.rstrip("/")
    subject = "Verify your email"
    body = f"Your verification code is: {code}\nThis code expires in 10 minutes."
    html = render_mail_template(
        "mail/otp_register.html",
        base_url=base_url,
        to=to,
        code=code,
    )
    send_mail(settings, to, subject, body, html=html)


def send_otp_forgot_password_mail(settings: Settings, to: str, code: str) -> None:
    base_url = settings.idp_issuer.rstrip("/")
    subject = "Reset your password"
    body = f"Your password reset code is: {code}\nThis code expires in 10 minutes."
    html = render_mail_template(
        "mail/otp_forgot_password.html",
        base_url=base_url,
        to=to,
        code=code,
    )
    send_mail(settings, to, subject, body, html=html)


def send_account_created_mail(settings: Settings, to: str) -> None:
    base_url = settings.idp_issuer.rstrip("/")
    subject = "Welcome to Short Circuit — Account Created"
    body = (
        f"Welcome to Short Circuit!\n\n"
        f"Your account ({to}) has been verified and created.\n"
        f"Manage your account at: {base_url}/account\n"
    )
    html = render_mail_template(
        "mail/account_created.html",
        base_url=base_url,
        to=to,
    )
    send_mail(settings, to, subject, body, html=html)


def send_account_linked_mail(settings: Settings, to: str, client_name: str, scopes: str) -> None:
    base_url = settings.idp_issuer.rstrip("/")
    subject = f"Application Connected: {client_name}"
    body = (
        f"Your Short Circuit account ({to}) was connected to {client_name}.\n"
        f"Authorized scopes: {scopes}\n"
        f"Review your account settings at: {base_url}/account\n"
    )
    html = render_mail_template(
        "mail/account_linked.html",
        base_url=base_url,
        to=to,
        client_name=client_name,
        scopes=scopes,
    )
    send_mail(settings, to, subject, body, html=html)

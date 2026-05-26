"""
Email sending service.
If SMTP_HOST is empty, the email body is printed to the log instead (dev mode).
"""
import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


def _is_configured() -> bool:
    return bool(settings.SMTP_HOST)


def send_email(
    to: list[str],
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
    attachment_filename: Optional[str] = None,
    attachment_data: Optional[bytes] = None,
    attachment_mime: str = "text/csv",
) -> bool:
    """
    Send an email synchronously. Returns True on success.
    Falls back to logging when SMTP is not configured.
    """
    if not _is_configured():
        logger.info(
            "SMTP not configured — email not sent. Subject: %s | To: %s | Body preview: %.300s",
            subject, to, text_body or html_body,
        )
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = ", ".join(to)

    if text_body:
        msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    if attachment_data and attachment_filename:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment_data)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{attachment_filename}"')
        part.add_header("Content-Type", attachment_mime)
        msg.attach(part)

    try:
        context = ssl.create_default_context()
        if settings.SMTP_TLS:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
                server.starttls(context=context)
                if settings.SMTP_USER:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(settings.SMTP_FROM, to, msg.as_string())
        else:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
                if settings.SMTP_USER:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(settings.SMTP_FROM, to, msg.as_string())
        logger.info("Email sent: subject=%s to=%s", subject, to)
        return True
    except Exception as e:
        logger.error("Failed to send email: %s", e, exc_info=True)
        return False


def send_invitation_email(to_email: str, role: str, token: str, invited_by: str) -> bool:
    accept_url = f"{settings.APP_URL}/accept-invite?token={token}"
    role_label = role.capitalize()
    html = f"""
<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:24px;">
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
    <div style="background:#0f172a;padding:24px 32px;">
      <h1 style="color:#fff;margin:0;font-size:20px;">SEC360 – You're invited</h1>
    </div>
    <div style="padding:32px;">
      <p style="color:#374151;margin:0 0 16px;">
        <strong>{invited_by}</strong> has invited you to join <strong>SEC360</strong> as a
        <strong>{role_label}</strong>.
      </p>
      <p style="color:#374151;margin:0 0 24px;">
        Click the button below to set your password and activate your account.
        This link expires in <strong>7 days</strong>.
      </p>
      <a href="{accept_url}"
         style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;
                padding:12px 28px;border-radius:6px;font-weight:600;font-size:14px;">
        Accept invitation
      </a>
      <p style="color:#9ca3af;font-size:12px;margin-top:24px;">
        Or copy this link: <a href="{accept_url}" style="color:#2563eb;">{accept_url}</a>
      </p>
    </div>
  </div>
</body>
</html>
"""
    text = (
        f"You've been invited to SEC360 as {role_label} by {invited_by}.\n\n"
        f"Accept your invitation here (expires in 7 days):\n{accept_url}\n"
    )
    logger.info("Invitation link for %s: %s", to_email, accept_url)
    return send_email([to_email], "You've been invited to SEC360", html, text)


def send_report_email(
    recipients: list[str],
    report_name: str,
    report_type: str,
    csv_data: bytes,
    summary_html: str,
) -> bool:
    filename = f"{report_type}_{report_name.replace(' ', '_')}.csv"
    html = f"""
<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:24px;">
  <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
    <div style="background:#0f172a;padding:24px 32px;">
      <h1 style="color:#fff;margin:0;font-size:20px;">SEC360 – Scheduled Report</h1>
    </div>
    <div style="padding:32px;">
      <h2 style="color:#111827;font-size:16px;margin:0 0 8px;">{report_name}</h2>
      <p style="color:#6b7280;font-size:13px;margin:0 0 24px;">Report type: {report_type.replace('_', ' ').title()}</p>
      {summary_html}
      <p style="color:#9ca3af;font-size:12px;margin-top:24px;">
        Full data is attached as a CSV file ({filename}).
      </p>
    </div>
  </div>
</body>
</html>
"""
    return send_email(
        recipients,
        f"SEC360 Report – {report_name}",
        html,
        attachment_filename=filename,
        attachment_data=csv_data,
    )

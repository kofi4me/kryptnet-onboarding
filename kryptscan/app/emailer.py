from __future__ import annotations

import smtplib
from email.message import EmailMessage

from kryptscan.app.config import Settings


class BaseEmailSender:
    def send_verification_code(self, email: str, code: str, domain: str) -> None:
        raise NotImplementedError

    def send_assessment_report(
        self,
        email: str,
        target: str,
        pdf_filename: str,
        pdf_bytes: bytes,
        summary: str,
    ) -> None:
        raise NotImplementedError


class ConsoleEmailSender(BaseEmailSender):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def send_verification_code(self, email: str, code: str, domain: str) -> None:
        print(
            f"[{self.settings.app_name}] Verification code for {email} "
            f"(verified email domain {domain}): {code}"
        )

    def send_assessment_report(
        self,
        email: str,
        target: str,
        pdf_filename: str,
        pdf_bytes: bytes,
        summary: str,
    ) -> None:
        print(
            f"[{self.settings.app_name}] Assessment report for {target} prepared for {email}: "
            f"{pdf_filename} ({len(pdf_bytes)} bytes)"
        )
        print(summary)


class SmtpEmailSender(BaseEmailSender):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _from_header(self) -> str:
        return f"{self.settings.email_from_name} <{self.settings.email_from}>"

    def _send_message(self, message: EmailMessage) -> None:
        smtp_client = smtplib.SMTP_SSL if self.settings.smtp_use_ssl else smtplib.SMTP
        with smtp_client(self.settings.smtp_host, self.settings.smtp_port, timeout=20) as smtp:
            if not self.settings.smtp_use_ssl:
                smtp.ehlo()
                if self.settings.smtp_use_tls:
                    smtp.starttls()
                    smtp.ehlo()
            if self.settings.smtp_username:
                smtp.login(self.settings.smtp_username, self.settings.smtp_password)
            smtp.send_message(message)

    def send_verification_code(self, email: str, code: str, domain: str) -> None:
        message = EmailMessage()
        message["Subject"] = "Your KryptScan verification code"
        message["From"] = self._from_header()
        message["To"] = email
        message.set_content(
            "Use this code to verify your KryptScan account for ethical vulnerability assessment access.\n\n"
            f"Verification code: {code}\n"
            f"Verified email domain: {domain}\n\n"
            "If you did not request this code, ignore this message."
        )

        self._send_message(message)

    def send_assessment_report(
        self,
        email: str,
        target: str,
        pdf_filename: str,
        pdf_bytes: bytes,
        summary: str,
    ) -> None:
        message = EmailMessage()
        message["Subject"] = f"{self.settings.app_name} assessment report for {target}"
        message["From"] = self._from_header()
        message["To"] = email
        message.set_content(
            "Your vulnerability assessment has completed.\n\n"
            f"Target: {target}\n\n"
            f"{summary}\n\n"
            "The PDF assessment report is attached."
        )
        message.add_attachment(
            pdf_bytes,
            maintype="application",
            subtype="pdf",
            filename=pdf_filename,
        )

        self._send_message(message)


def get_email_sender(settings: Settings) -> BaseEmailSender:
    if settings.email_delivery == "smtp":
        return SmtpEmailSender(settings)
    return ConsoleEmailSender(settings)

from datetime import datetime, timedelta
from email.message import EmailMessage
from io import BytesIO
import os
import re
import secrets
import smtplib
import textwrap
from urllib.parse import quote

from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from a2wsgi import ASGIMiddleware
from werkzeug.datastructures import MultiDict
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.middleware.proxy_fix import ProxyFix


def normalize_database_url(database_url):
    if not database_url:
        return "sqlite:///kryptnet_onboarding.db"
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql://", 1)
    return database_url


DATABASE_URL_RAW = os.getenv("DATABASE_URL", "").strip()

app = Flask(__name__, static_folder="static")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["SQLALCHEMY_DATABASE_URI"] = normalize_database_url(DATABASE_URL_RAW)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_ENV") == "production"

db = SQLAlchemy(app)
migrate = Migrate(app, db)

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin").strip()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me-now").strip()
ADMIN_SESSION_KEY = "admin_authenticated"
ADMIN_LOGIN_ATTEMPTS = {}
ADMIN_MAX_LOGIN_ATTEMPTS = 5
ADMIN_LOCKOUT_SECONDS = 15 * 60
SUBMISSION_ATTEMPTS = {}
SUBMISSION_RATE_LIMIT = 5
SUBMISSION_RATE_WINDOW_SECONDS = 60 * 60
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "").strip()
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "KryptNet")
ADMIN_NOTIFICATION_EMAIL = os.getenv(
    "ADMIN_NOTIFICATION_EMAIL", "support@kryptnet.org"
).strip()
KRYPTSCAN_DOMAIN = os.getenv("KRYPTSCAN_DOMAIN", "kryptscan.kryptnet.org").strip().lower()

LOGO_CANDIDATES = (
    "kryptnet-logo.png",
    "kryptnet_logo.png",
    "kryptnet_logo.png.png",
)


@app.before_request
def route_kryptscan_subdomain():
    host = request.host.split(":", 1)[0].lower()
    if host == KRYPTSCAN_DOMAIN and request.path == "/":
        return redirect("/kryptscan/")
    return None


@app.route("/kryptscan/")
def kryptscan_home():
    from kryptscan.app.config import get_settings as get_kryptscan_settings
    from kryptscan.app.security import create_csrf_token

    settings = get_kryptscan_settings()
    response = send_from_directory(
        os.path.join(app.root_path, "kryptscan", "app", "templates"),
        "index.html",
    )
    if not request.cookies.get(settings.csrf_cookie_name):
        response.set_cookie(
            settings.csrf_cookie_name,
            create_csrf_token(settings),
            httponly=False,
            secure=settings.session_cookie_secure,
            samesite="Lax",
            path="/",
            max_age=int(timedelta(hours=settings.session_ttl_hours).total_seconds()),
        )
    return response


@app.route("/kryptscan/static/<path:filename>")
def kryptscan_static(filename):
    return send_from_directory(
        os.path.join(app.root_path, "kryptscan", "app", "static"),
        filename,
    )


@app.route("/kryptscan/request-code", methods=["GET", "POST"])
def kryptscan_request_code_fallback():
    try:
        if request.method != "POST":
            return redirect("/kryptscan/")
        email = request.form.get("email", "").strip()
        if not email:
            return redirect("/kryptscan/?verification_error=Email%20address%20is%20required")

        from kryptscan.app.config import get_settings as get_kryptscan_settings
        from kryptscan.app.emailer import get_email_sender
        from kryptscan.app.services.auth import AuthService

        settings = get_kryptscan_settings()
        AuthService(settings, get_email_sender(settings)).request_code(email)
        session["kryptscan_pending_email"] = email
    except Exception as exc:
        app.logger.exception("KryptScan verification code request failed")
        message = str(exc) or "Verification email could not be sent. Check SMTP settings in Render."
        return redirect(f"/kryptscan/?verification_error={quote(message)}")
    return redirect(f"/kryptscan/?verification_sent=1&email={quote(email)}#verify-code")


@app.route("/kryptscan/verify-code", methods=["POST"])
def kryptscan_verify_code_fallback():
    code = request.form.get("code", "").strip()
    email = session.get("kryptscan_pending_email", "").strip()
    if not email:
        return redirect("/kryptscan/?verification_error=Start%20again%20by%20requesting%20a%20new%20verification%20code")
    if not code:
        return redirect(f"/kryptscan/?verification_error=Verification%20code%20is%20required&email={quote(email)}#verify-code")
    try:
        from kryptscan.app.config import get_settings as get_kryptscan_settings
        from kryptscan.app.emailer import get_email_sender
        from kryptscan.app.security import create_session_token
        from kryptscan.app.services.auth import AuthService

        settings = get_kryptscan_settings()
        user = AuthService(settings, get_email_sender(settings)).verify_code(email, code)
        token = create_session_token(settings, int(user["id"]), user["email"])
        profile_complete = bool(user["profile_completed_at"]) and bool(user["safe_use_accepted"])
        next_step = "choose-tool" if profile_complete else "register"
        response = redirect(f"/kryptscan/?verified=1&next={next_step}#{next_step}")
        response.set_cookie(
            settings.session_cookie_name,
            token,
            httponly=True,
            secure=settings.session_cookie_secure,
            samesite="Lax",
            path="/",
            max_age=int(timedelta(hours=settings.session_ttl_hours).total_seconds()),
        )
        session.pop("kryptscan_pending_email", None)
        return response
    except Exception as exc:
        app.logger.exception("KryptScan verification code validation failed")
        message = str(exc) or "Verification failed. Request a new code and try again."
        return redirect(f"/kryptscan/?verification_error={quote(message)}&email={quote(email)}#verify-code")

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
VERIFICATION_STATUS_PENDING = "Pending Verification"
VERIFICATION_STATUS_VERIFIED = "Verified"
VERIFICATION_STATUS_SUSPICIOUS = "Suspicious"


def split_csv(value):
    return [item.strip() for item in value.split(",") if item.strip()] if value else []


def format_score(score):
    if score is None:
        score = 0
    return f"{score}%"


def safe_pdf_text(text):
    return str(text).encode("cp1252", "replace").decode("cp1252")


def build_control_assessment(record):
    selected_controls = split_csv(record.risk_controls)
    missing_controls = [
        control for control in RISK_CONTROL_OPTIONS if control not in selected_controls
    ]
    exposure_lines = [
        f"{control}: {RISK_CONTROL_EXPOSURES[control]}"
        for control in missing_controls
    ]
    selected_controls_text = (
        ", ".join(selected_controls) if selected_controls else "No implemented controls selected"
    )
    missing_controls_text = (
        ", ".join(missing_controls) if missing_controls else "No major control gaps selected"
    )

    return {
        "selected_controls": selected_controls,
        "missing_controls": missing_controls,
        "exposure_lines": exposure_lines,
        "selected_controls_text": selected_controls_text,
        "missing_controls_text": missing_controls_text,
    }


def build_service_risk_statement(record):
    services = split_csv(record.selected_services)
    services_text = ", ".join(services) if services else "the requested services"
    assessment = build_control_assessment(record)
    if not assessment["missing_controls"]:
        return (
            f"Based on the services requested ({services_text}), KryptNet should still "
            "validate the selected controls, confirm they are configured correctly, "
            "and identify any hidden gaps that may not be visible from the intake form."
        )

    return (
        f"Based on the services requested ({services_text}), KryptNet recommends "
        "addressing the missing security controls before they become business-impacting "
        "risks. Unresolved gaps can lead to account compromise, ransomware exposure, "
        "data loss, downtime, compliance concerns, and higher recovery costs."
    )


class ClientOnboarding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(200), nullable=False)
    industry = db.Column(db.String(120), nullable=True)
    contact_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    address = db.Column(db.Text, nullable=True)
    employees = db.Column(db.Integer, nullable=True)
    computers = db.Column(db.Integer, nullable=True)
    servers = db.Column(db.Integer, nullable=True)
    wifi_aps = db.Column(db.Integer, nullable=True)
    email_platform = db.Column(db.String(120), nullable=True)
    internet_provider = db.Column(db.String(120), nullable=True)
    antivirus = db.Column(db.Boolean, default=False)
    backups = db.Column(db.Boolean, default=False)
    mfa = db.Column(db.Boolean, default=False)
    risk_controls = db.Column(db.Text, nullable=True)
    selected_services = db.Column(db.Text, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    authorized = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(50), default="Unknown")
    verification_status = db.Column(
        db.String(50), default=VERIFICATION_STATUS_PENDING, nullable=False
    )
    verification_token = db.Column(db.String(128), nullable=True, unique=True)
    verification_sent_at = db.Column(db.DateTime, nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)
    suspicious_reason = db.Column(db.String(250), nullable=True)
    submitter_ip = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "business_name": self.business_name,
            "industry": self.industry,
            "contact_name": self.contact_name,
            "email": self.email,
            "phone": self.phone,
            "address": self.address,
            "employees": self.employees,
            "computers": self.computers,
            "servers": self.servers,
            "wifi_aps": self.wifi_aps,
            "email_platform": self.email_platform,
            "internet_provider": self.internet_provider,
            "antivirus": self.antivirus,
            "backups": self.backups,
            "mfa": self.mfa,
            "risk_controls": split_csv(self.risk_controls),
            "selected_services": (
                self.selected_services.split(",") if self.selected_services else []
            ),
            "notes": self.notes,
            "authorized": self.authorized,
            "risk_score": self.risk_score,
            "risk_score_percent": format_score(self.risk_score or 0),
            "risk_level": self.risk_level,
            "verification_status": self.verification_status,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "suspicious_reason": self.suspicious_reason,
            "submitter_ip": self.submitter_ip,
            "security_readiness_score": self.risk_score,
            "readiness_summary": build_readiness_summary(
                self.risk_score or 0, self.risk_level
            ),
            "created_at": self.created_at.isoformat(),
        }


SERVICE_OPTIONS = [
    "Basic IT Support",
    "Managed IT Services",
    "Cybersecurity Protection",
    "Backup & Disaster Recovery",
    "Email Security",
    "Vulnerability Assessment",
]

RISK_CONTROL_OPTIONS = [
    "Multi-Factor Authentication (MFA)",
    "Backup & Disaster Recovery",
    "Endpoint Protection (Antivirus/EDR)",
    "Email Security & Phishing Protection",
    "Employee Security Awareness Training",
    "Patch Management & Updates",
    "Firewall & Network Security",
    "Access Control (Least Privilege)",
    "Vulnerability Scanning",
    "Data Encryption",
    "Incident Response Plan",
    "Logging & Monitoring",
]

RISK_CONTROL_WEIGHTS = {
    "Multi-Factor Authentication (MFA)": 12,
    "Backup & Disaster Recovery": 12,
    "Endpoint Protection (Antivirus/EDR)": 12,
    "Email Security & Phishing Protection": 10,
    "Firewall & Network Security": 10,
    "Employee Security Awareness Training": 8,
    "Patch Management & Updates": 8,
    "Access Control (Least Privilege)": 8,
    "Incident Response Plan": 8,
    "Logging & Monitoring": 8,
    "Vulnerability Scanning": 7,
    "Data Encryption": 7,
}

RISK_CONTROL_EXPOSURES = {
    "Multi-Factor Authentication (MFA)": "Without MFA, stolen or guessed passwords can give attackers direct access to email, cloud apps, and business systems.",
    "Backup & Disaster Recovery": "Without reliable backup and recovery, ransomware, accidental deletion, or hardware failure can cause extended downtime and permanent data loss.",
    "Endpoint Protection (Antivirus/EDR)": "Without endpoint protection, workstations and servers are more exposed to malware, ransomware, and unauthorized activity.",
    "Email Security & Phishing Protection": "Without email security, phishing messages, malicious attachments, and credential theft attempts are more likely to reach users.",
    "Employee Security Awareness Training": "Without user awareness training, employees may be more likely to click phishing links, share credentials, or miss warning signs.",
    "Patch Management & Updates": "Without timely patching, known software weaknesses can remain open for attackers to exploit.",
    "Firewall & Network Security": "Without strong network protection, unauthorized traffic and exposed services can increase the chance of intrusion.",
    "Access Control (Least Privilege)": "Without least-privilege access, one compromised account can create broader damage across files, systems, and applications.",
    "Vulnerability Scanning": "Without routine vulnerability scanning, weaknesses may remain hidden until they are discovered by attackers.",
    "Data Encryption": "Without encryption, sensitive business or client data may be exposed if devices, files, or accounts are compromised.",
    "Incident Response Plan": "Without an incident response plan, security events can take longer to contain, increasing cost, disruption, and reputational impact.",
    "Logging & Monitoring": "Without monitoring, suspicious activity may go unnoticed until business operations or client data are already affected.",
}


def ensure_database_tables():
    # Keep migrations as the primary schema workflow, but bootstrap the core
    # table defensively in environments where the start command skips them.
    with app.app_context():
        db.create_all()


def smtp_is_configured():
    return all([SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM_EMAIL])


def smtp_config_status():
    checks = {
        "SMTP_HOST": bool(SMTP_HOST),
        "SMTP_PORT": bool(SMTP_PORT),
        "SMTP_USERNAME": bool(SMTP_USERNAME),
        "SMTP_PASSWORD": bool(SMTP_PASSWORD),
        "SMTP_FROM_EMAIL": bool(SMTP_FROM_EMAIL),
    }
    return {
        "configured": all(checks.values()),
        "checks": checks,
        "host": SMTP_HOST or "Not set",
        "port": SMTP_PORT,
        "username": SMTP_USERNAME or "Not set",
        "from_email": SMTP_FROM_EMAIL or "Not set",
        "use_ssl": SMTP_USE_SSL,
        "use_tls": SMTP_USE_TLS,
    }


def database_config_status():
    database_uri = app.config["SQLALCHEMY_DATABASE_URI"]
    is_sqlite = database_uri.startswith("sqlite:")
    return {
        "backend": "SQLite" if is_sqlite else "External database",
        "persistent": not is_sqlite,
        "database_url_configured": bool(DATABASE_URL_RAW),
        "message": (
            "Persistent database configured."
            if not is_sqlite
            else (
                "Using fallback SQLite. On Render this can reset or appear to replace "
                "entries after deploys/restarts. Add DATABASE_URL for persistent storage."
            )
        ),
    }


def build_report_context(record):
    return {
        "record": record,
        "assessment": build_control_assessment(record),
        "readiness_summary": build_readiness_summary(
            record.risk_score, record.risk_level
        ),
        "risk_score_percent": format_score(record.risk_score),
        "service_risk_statement": build_service_risk_statement(record),
    }


def build_client_confirmation_email(record):
    message = EmailMessage()
    message["Subject"] = "KryptNet onboarding submission received"
    message["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    message["To"] = record.email

    services = split_csv(record.selected_services)
    services_text = ", ".join(services) if services else "Not specified"
    assessment = build_control_assessment(record)
    readiness_summary = build_readiness_summary(record.risk_score, record.risk_level)
    service_risk_statement = build_service_risk_statement(record)
    exposure_text = "\n".join(f"- {line}" for line in assessment["exposure_lines"])
    if not exposure_text:
        exposure_text = "- No major missing control exposures were identified from the selected answers."

    body = f"""Hello {record.contact_name},

Thank you for submitting your onboarding information to KryptNet.

We have received your request for:
- Business: {record.business_name}
- Contact email: {record.email}
- Phone: {record.phone}
- Services requested: {services_text}
- Security readiness score: {format_score(record.risk_score)}
- Risk level: {record.risk_level}
- Readiness summary: {readiness_summary}
- Controls selected as currently implemented: {assessment["selected_controls_text"]}
- Controls not selected and requiring review: {assessment["missing_controls_text"]}

Potential vulnerability areas:
{exposure_text}

Risk evaluation note:
{service_risk_statement}

Our team will review your submission and follow up with next steps.

Thank you,
KryptNet
"""
    message.set_content(body)
    pdf_bytes = generate_onboarding_report_pdf(record)
    filename = f"kryptnet-onboarding-report-{record.id}.pdf"
    message.add_attachment(
        pdf_bytes,
        maintype="application",
        subtype="pdf",
        filename=filename,
    )
    return message


def build_email_verification_message(record):
    message = EmailMessage()
    message["Subject"] = "Verify your KryptNet onboarding request"
    message["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    message["To"] = record.email

    verification_url = url_for(
        "verify_submission",
        token=record.verification_token,
        _external=True,
        _scheme="https" if request.is_secure else request.scheme,
    )
    body = f"""Hello {record.contact_name},

KryptNet received an onboarding request for {record.business_name}.

Please verify this email address before KryptNet finalizes the onboarding report:
{verification_url}

If you did not submit this request, you can ignore this email.

Thank you,
KryptNet
"""
    message.set_content(body)
    return message


def build_admin_notification_email(record):
    message = EmailMessage()
    message["Subject"] = f"New KryptNet onboarding submission: {record.business_name}"
    message["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    message["To"] = ADMIN_NOTIFICATION_EMAIL

    services = split_csv(record.selected_services)
    services_text = ", ".join(services) if services else "Not specified"
    assessment = build_control_assessment(record)
    readiness_summary = build_readiness_summary(record.risk_score, record.risk_level)
    service_risk_statement = build_service_risk_statement(record)
    exposure_text = "\n".join(f"- {line}" for line in assessment["exposure_lines"])
    if not exposure_text:
        exposure_text = "- No major missing control exposures were identified from the selected answers."

    body = f"""A new onboarding submission has been received.

Business: {record.business_name}
Industry: {record.industry or 'Not provided'}
Contact name: {record.contact_name}
Contact email: {record.email}
Phone: {record.phone}
Address: {record.address or 'Not provided'}
Employees: {record.employees if record.employees is not None else 'Not provided'}
Computers: {record.computers if record.computers is not None else 'Not provided'}
Servers: {record.servers if record.servers is not None else 'Not provided'}
Email platform: {record.email_platform or 'Not provided'}
Internet provider: {record.internet_provider or 'Not provided'}
Number of WiFi AP: {record.wifi_aps if record.wifi_aps is not None else 'Not provided'}
Risk evaluation controls selected: {assessment["selected_controls_text"]}
Missing controls requiring review: {assessment["missing_controls_text"]}
Services requested: {services_text}
Security readiness score: {format_score(record.risk_score)}
Risk level: {record.risk_level}
Readiness summary: {readiness_summary}

Potential vulnerability areas:
{exposure_text}

Risk evaluation note:
{service_risk_statement}

Notes: {record.notes or 'None'}
Submitted at: {record.created_at.isoformat()}
"""
    message.set_content(body)
    return message


def generate_onboarding_report_pdf(record):
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 50

    def write_line(text, gap=18):
        nonlocal y
        text = safe_pdf_text(text)
        if not text:
            y -= gap
            return
        for wrapped_line in textwrap.wrap(text, width=92, subsequent_indent="  "):
            if y < 60:
                pdf.showPage()
                y = height - 50
            pdf.drawString(50, y, wrapped_line)
            y -= gap

    services = split_csv(record.selected_services)
    services_text = ", ".join(services) if services else "Not specified"
    assessment = build_control_assessment(record)
    readiness_summary = build_readiness_summary(record.risk_score, record.risk_level)
    service_risk_statement = build_service_risk_statement(record)

    pdf.setTitle(f"KryptNet Client Onboarding Report {record.id}")
    pdf.setFont("Helvetica-Bold", 18)
    write_line("Onboarding Submitted Successfully", gap=28)

    pdf.setFont("Helvetica", 11)
    write_line("KryptNet has captured the client onboarding record.", gap=24)
    write_line(
        "Risk Evaluation: KryptNet reviewed the security controls selected, "
        "measured the environment against essential cybersecurity readiness "
        "areas, and generated the readiness score below to help identify the "
        "current risk status and next protection priorities.",
        gap=18,
    )
    write_line("", gap=12)

    pdf.setFont("Helvetica-Bold", 13)
    write_line("Client Summary", gap=22)
    pdf.setFont("Helvetica", 11)
    for line in [
        f"Business: {record.business_name}",
        f"Contact: {record.contact_name}",
        f"Email: {record.email}",
        f"Phone: {record.phone}",
        f"Services: {services_text}",
    ]:
        write_line(line)

    write_line("", gap=12)
    pdf.setFont("Helvetica-Bold", 13)
    write_line("Security Readiness Snapshot", gap=22)
    pdf.setFont("Helvetica", 11)
    for line in [
        f"Readiness Score: {format_score(record.risk_score)}",
        f"Risk Level: {record.risk_level}",
        f"Summary: {readiness_summary}",
        f"Controls selected: {assessment['selected_controls_text']}",
    ]:
        write_line(line)

    write_line("", gap=12)
    pdf.setFont("Helvetica-Bold", 13)
    write_line("Potential Vulnerability Areas", gap=22)
    pdf.setFont("Helvetica", 11)
    write_line(
        "These are the security controls not selected in the risk evaluation. "
        "They may represent business risks that should be reviewed during onboarding."
    )

    if assessment["exposure_lines"]:
        for exposure_line in assessment["exposure_lines"]:
            write_line(exposure_line)
    else:
        write_line(
            "No major missing control exposures were identified from the selected answers."
        )

    write_line("", gap=12)
    pdf.setFont("Helvetica-Bold", 13)
    write_line("Recommended Next Step", gap=22)
    pdf.setFont("Helvetica", 11)
    write_line(service_risk_statement)

    pdf.save()
    buffer.seek(0)
    return buffer.read()


def send_client_confirmation_email(record):
    if not smtp_is_configured():
        app.logger.warning(
            "SMTP is not configured; skipping confirmation email for submission %s",
            record.id,
        )
        return "skipped"

    try:
        message = build_client_confirmation_email(record)
        smtp_client = smtplib.SMTP_SSL if SMTP_USE_SSL else smtplib.SMTP
        with smtp_client(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
            if not SMTP_USE_SSL:
                smtp.ehlo()
                if SMTP_USE_TLS:
                    smtp.starttls()
                    smtp.ehlo()
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(message)
        return "sent"
    except Exception:
        app.logger.exception(
            "Failed to send confirmation email for submission %s", record.id
        )
        return "failed"


def send_verification_email(record):
    if not smtp_is_configured():
        app.logger.warning(
            "SMTP is not configured; skipping verification email for submission %s",
            record.id,
        )
        return "skipped"

    try:
        message = build_email_verification_message(record)
        smtp_client = smtplib.SMTP_SSL if SMTP_USE_SSL else smtplib.SMTP
        with smtp_client(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
            if not SMTP_USE_SSL:
                smtp.ehlo()
                if SMTP_USE_TLS:
                    smtp.starttls()
                    smtp.ehlo()
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(message)
        return "sent"
    except Exception:
        app.logger.exception(
            "Failed to send verification email for submission %s", record.id
        )
        return "failed"


def send_admin_notification_email(record):
    if not smtp_is_configured():
        app.logger.warning(
            "SMTP is not configured; skipping admin notification email for submission %s",
            record.id,
        )
        return "skipped"

    try:
        message = build_admin_notification_email(record)
        smtp_client = smtplib.SMTP_SSL if SMTP_USE_SSL else smtplib.SMTP
        with smtp_client(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
            if not SMTP_USE_SSL:
                smtp.ehlo()
                if SMTP_USE_TLS:
                    smtp.starttls()
                    smtp.ehlo()
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(message)
        return "sent"
    except Exception:
        app.logger.exception(
            "Failed to send admin notification email for submission %s", record.id
        )
        return "failed"


def calculate_risk_score(selected_controls):
    total_weight = sum(RISK_CONTROL_WEIGHTS.values())
    selected_weight = sum(RISK_CONTROL_WEIGHTS.get(control, 0) for control in selected_controls)
    score = round((selected_weight / total_weight) * 100)

    if score >= 85:
        level = "Low"
    elif score >= 70:
        level = "Moderate"
    elif score >= 50:
        level = "High"
    else:
        level = "Critical"

    return score, level


def build_readiness_summary(score, risk_level):
    if score >= 85:
        return "Strong security readiness. Core controls appear well represented, with only minor gaps to review."
    if score >= 70:
        return "Good security readiness. The environment has several important controls, but selected gaps should be prioritized."
    if score >= 50:
        return "Developing security readiness. Key protections are present, but important safeguards need attention."
    return "Limited security readiness. Critical controls appear missing and should be reviewed as onboarding priorities."


def get_logo_filename():
    static_folder = app.static_folder or "static"
    for filename in LOGO_CANDIDATES:
        if os.path.exists(os.path.join(static_folder, filename)):
            return filename
    return None


def is_admin_authenticated():
    return session.get(ADMIN_SESSION_KEY) is True


def get_admin_client_key():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def submission_rate_limited(client_ip):
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=SUBMISSION_RATE_WINDOW_SECONDS)
    attempts = [
        attempt
        for attempt in SUBMISSION_ATTEMPTS.get(client_ip, [])
        if attempt >= window_start
    ]
    if len(attempts) >= SUBMISSION_RATE_LIMIT:
        SUBMISSION_ATTEMPTS[client_ip] = attempts
        return True

    attempts.append(now)
    SUBMISSION_ATTEMPTS[client_ip] = attempts
    return False


def get_admin_lockout_seconds(client_key):
    attempt = ADMIN_LOGIN_ATTEMPTS.get(client_key)
    if not attempt:
        return 0

    locked_until = attempt.get("locked_until")
    if not locked_until:
        return 0

    now = datetime.utcnow()
    if locked_until <= now:
        ADMIN_LOGIN_ATTEMPTS.pop(client_key, None)
        return 0

    return int((locked_until - now).total_seconds())


def record_failed_admin_login(client_key):
    attempt = ADMIN_LOGIN_ATTEMPTS.setdefault(
        client_key, {"count": 0, "locked_until": None}
    )
    attempt["count"] += 1
    if attempt["count"] >= ADMIN_MAX_LOGIN_ATTEMPTS:
        attempt["locked_until"] = datetime.utcnow() + timedelta(
            seconds=ADMIN_LOCKOUT_SECONDS
        )


def clear_admin_login_attempts(client_key):
    ADMIN_LOGIN_ATTEMPTS.pop(client_key, None)


def require_admin():
    if not is_admin_authenticated():
        if request.path.endswith("/api/submissions"):
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("admin_login", next=request.path))
    return None


def sanitize_next_url(next_url):
    if (
        next_url
        and next_url.startswith("/kryptnet-secure-review")
        and not next_url.startswith("//")
    ):
        return next_url
    return url_for("admin_submissions")


def validate_required_text(errors, field, value, label, max_length):
    if not value:
        errors[field] = f"{label} is required."
    elif len(value) > max_length:
        errors[field] = f"{label} must be {max_length} characters or fewer."


def validate_optional_text(errors, field, value, label, max_length):
    if value and len(value) > max_length:
        errors[field] = f"{label} must be {max_length} characters or fewer."


def validate_non_negative_integer(errors, field, value, label, required=False):
    if not value:
        if required:
            errors[field] = f"{label} is required."
        return None

    try:
        parsed = int(value)
    except ValueError:
        errors[field] = f"{label} must be a whole number."
        return None

    if parsed < 0:
        errors[field] = f"{label} cannot be negative."
        return None

    return parsed


@app.route("/")
def index():
    logo_filename = get_logo_filename()
    logo_src = url_for("static", filename=logo_filename) if logo_filename else None
    return render_template("home.html", logo_src=logo_src)


@app.route("/onboarding", methods=["GET", "POST"])
def onboarding():
    errors = {}
    form_data = request.form if request.method == "POST" else MultiDict()

    if request.method == "POST":
        client_ip = get_client_ip()
        honeypot = request.form.get("company_website_confirm", "").strip()
        if honeypot:
            app.logger.warning(
                "Honeypot trapped suspicious onboarding submission from %s",
                client_ip,
            )
            return redirect(url_for("submission_pending"))

        if submission_rate_limited(client_ip):
            errors["rate_limit"] = (
                "Too many onboarding attempts were submitted from this connection. "
                "Please wait and try again later."
            )
            return render_template(
                "onboarding.html",
                errors=errors,
                form=form_data,
                service_options=SERVICE_OPTIONS,
                risk_control_options=RISK_CONTROL_OPTIONS,
            )

        business_name = request.form.get("business_name", "").strip()
        industry = request.form.get("industry", "").strip()
        contact_name = request.form.get("contact_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        employees = request.form.get("employees", "").strip()
        computers = request.form.get("computers", "").strip()
        servers = request.form.get("servers", "").strip()
        wifi_aps = request.form.get("wifi_aps", "").strip()
        email_platform = request.form.get("email_platform", "").strip()
        internet_provider = request.form.get("internet_provider", "").strip()
        selected_risk_controls = request.form.getlist("risk_controls")
        selected_services = request.form.getlist("selected_services")
        notes = request.form.get("notes", "").strip()
        authorized = request.form.get("authorized") == "on"

        validate_required_text(errors, "business_name", business_name, "Business name", 200)
        validate_required_text(errors, "industry", industry, "Industry", 120)
        validate_required_text(errors, "contact_name", contact_name, "Contact name", 150)
        validate_required_text(errors, "email", email, "Email", 150)
        validate_required_text(errors, "phone", phone, "Phone", 50)
        validate_required_text(errors, "address", address, "Business address", 2000)
        validate_required_text(errors, "email_platform", email_platform, "Email platform", 120)
        validate_required_text(errors, "internet_provider", internet_provider, "Internet provider", 120)
        validate_required_text(errors, "notes", notes, "Additional notes", 4000)

        if email and not EMAIL_REGEX.match(email):
            errors["email"] = "Enter a valid email address."

        phone_digits = re.sub(r"\D", "", phone)
        if phone and len(phone_digits) < 10:
            errors["phone"] = "Enter a valid phone number with at least 10 digits."

        employees_val = validate_non_negative_integer(
            errors, "employees", employees, "Number of employees", required=True
        )
        computers_val = validate_non_negative_integer(
            errors, "computers", computers, "Number of computers", required=True
        )
        servers_val = validate_non_negative_integer(
            errors, "servers", servers, "Number of servers", required=True
        )
        wifi_aps_val = validate_non_negative_integer(
            errors, "wifi_aps", wifi_aps, "Number of WiFi AP", required=True
        )

        if not selected_risk_controls:
            errors["risk_controls"] = "Select at least one implemented security control."
        if not selected_services:
            errors["selected_services"] = "Select at least one service."
        if not authorized:
            errors["authorized"] = (
                "You must authorize KryptNet to review the submission."
            )

        if errors:
            return render_template(
                "onboarding.html",
                errors=errors,
                form=form_data,
                service_options=SERVICE_OPTIONS,
                risk_control_options=RISK_CONTROL_OPTIONS,
            )

        risk_score, risk_level = calculate_risk_score(selected_risk_controls)

        record = ClientOnboarding(
            business_name=business_name,
            industry=industry,
            contact_name=contact_name,
            email=email,
            phone=phone,
            address=address,
            employees=employees_val,
            computers=computers_val,
            servers=servers_val,
            wifi_aps=wifi_aps_val,
            email_platform=email_platform,
            internet_provider=internet_provider,
            antivirus="Endpoint Protection (Antivirus/EDR)" in selected_risk_controls,
            backups="Backup & Disaster Recovery" in selected_risk_controls,
            mfa="Multi-Factor Authentication (MFA)" in selected_risk_controls,
            risk_controls=",".join(selected_risk_controls),
            selected_services=",".join(selected_services),
            notes=notes,
            authorized=authorized,
            risk_score=risk_score,
            risk_level=risk_level,
            verification_status=VERIFICATION_STATUS_PENDING,
            verification_token=secrets.token_urlsafe(32),
            verification_sent_at=datetime.utcnow(),
            submitter_ip=client_ip,
        )

        db.session.add(record)
        db.session.commit()
        verification_email_status = send_verification_email(record)
        return redirect(
            url_for(
                "submission_pending",
                verification_email_status=verification_email_status,
            )
        )

    return render_template(
        "onboarding.html",
        errors=errors,
        form=form_data,
        service_options=SERVICE_OPTIONS,
        risk_control_options=RISK_CONTROL_OPTIONS,
    )


@app.route("/pending-verification")
def submission_pending():
    return render_template(
        "pending_verification.html",
        verification_email_status=request.args.get(
            "verification_email_status", "unknown"
        ),
    )


@app.route("/verify/<token>")
def verify_submission(token):
    record = ClientOnboarding.query.filter_by(verification_token=token).first_or_404()
    already_verified = record.verification_status == VERIFICATION_STATUS_VERIFIED
    if record.verification_status != VERIFICATION_STATUS_VERIFIED:
        record.verification_status = VERIFICATION_STATUS_VERIFIED
        record.verified_at = datetime.utcnow()
        db.session.commit()

    if already_verified:
        email_status = "already_sent"
        admin_email_status = "already_sent"
    else:
        email_status = send_client_confirmation_email(record)
        admin_email_status = send_admin_notification_email(record)

    return redirect(
        url_for(
            "submission_success",
            submission_id=record.id,
            email_status=email_status,
            admin_email_status=admin_email_status,
        )
    )


@app.route("/success/<int:submission_id>")
def submission_success(submission_id):
    record = ClientOnboarding.query.get_or_404(submission_id)
    if record.verification_status != VERIFICATION_STATUS_VERIFIED:
        return redirect(url_for("submission_pending"))

    email_status = request.args.get("email_status", "unknown")
    admin_email_status = request.args.get("admin_email_status", "unknown")
    report_context = build_report_context(record)
    return render_template(
        "success.html",
        record=report_context["record"],
        email_status=email_status,
        admin_email_status=admin_email_status,
        admin_notification_email=ADMIN_NOTIFICATION_EMAIL,
        readiness_summary=report_context["readiness_summary"],
        assessment=report_context["assessment"],
        service_risk_statement=report_context["service_risk_statement"],
        risk_score_percent=report_context["risk_score_percent"],
    )


@app.route("/kryptnet-secure-review/submissions")
def admin_submissions():
    auth_redirect = require_admin()
    if auth_redirect:
        return auth_redirect

    records = ClientOnboarding.query.order_by(ClientOnboarding.created_at.desc()).all()
    report_rows = [build_report_context(record) for record in records]
    return render_template(
        "admin.html",
        report_rows=report_rows,
        smtp_status=smtp_config_status(),
        database_status=database_config_status(),
        notice=request.args.get("notice", ""),
        notice_type=request.args.get("notice_type", "hint"),
    )


@app.route("/kryptnet-secure-review/submissions/<int:submission_id>/delete", methods=["POST"])
def delete_submission(submission_id):
    auth_redirect = require_admin()
    if auth_redirect:
        return auth_redirect

    record = ClientOnboarding.query.get_or_404(submission_id)
    db.session.delete(record)
    db.session.commit()
    return redirect(url_for("admin_submissions"))


@app.route("/kryptnet-secure-review/submissions/<int:submission_id>/resend-client-report", methods=["POST"])
def resend_client_report(submission_id):
    auth_redirect = require_admin()
    if auth_redirect:
        return auth_redirect

    record = ClientOnboarding.query.get_or_404(submission_id)
    if record.verification_status != VERIFICATION_STATUS_VERIFIED:
        notice = (
            "The client report was not sent because this submission is still "
            "pending email verification."
        )
        return redirect(
            url_for(
                "admin_submissions",
                notice=notice,
                notice_type="warning",
            )
        )

    status = send_client_confirmation_email(record)
    if status == "sent":
        notice = f"Client PDF report was resent to {record.email}."
        notice_type = "hint"
    elif status == "skipped":
        notice = "Client PDF report could not be sent because SMTP is not configured."
        notice_type = "warning"
    else:
        notice = (
            "Client PDF report could not be sent. Check Render logs and SMTP "
            "credentials, then try again."
        )
        notice_type = "warning"

    return redirect(
        url_for("admin_submissions", notice=notice, notice_type=notice_type)
    )


@app.route("/kryptnet-secure-review/submissions/<int:submission_id>/resend-verification", methods=["POST"])
def resend_verification_email(submission_id):
    auth_redirect = require_admin()
    if auth_redirect:
        return auth_redirect

    record = ClientOnboarding.query.get_or_404(submission_id)
    if record.verification_status == VERIFICATION_STATUS_VERIFIED:
        notice = "This submission is already verified."
        notice_type = "hint"
    else:
        if not record.verification_token:
            record.verification_token = secrets.token_urlsafe(32)
        record.verification_sent_at = datetime.utcnow()
        db.session.commit()
        status = send_verification_email(record)
        if status == "sent":
            notice = f"Verification email was resent to {record.email}."
            notice_type = "hint"
        elif status == "skipped":
            notice = "Verification email could not be sent because SMTP is not configured."
            notice_type = "warning"
        else:
            notice = "Verification email could not be sent. Check SMTP settings and Render logs."
            notice_type = "warning"

    return redirect(
        url_for("admin_submissions", notice=notice, notice_type=notice_type)
    )


@app.route("/kryptnet-secure-review", methods=["GET", "POST"])
def admin_login():
    if is_admin_authenticated():
        return redirect(url_for("admin_submissions"))

    error = ""
    next_url = sanitize_next_url(
        request.args.get("next") or request.form.get("next")
    )

    if request.method == "POST":
        client_key = get_admin_client_key()
        lockout_seconds = get_admin_lockout_seconds(client_key)
        if lockout_seconds:
            minutes = max(1, (lockout_seconds + 59) // 60)
            error = (
                "Too many unsuccessful login attempts. "
                f"Please try again in about {minutes} minute(s)."
            )
            return render_template(
                "admin_login.html",
                error=error,
                next_url=next_url,
                using_default_credentials=False,
            )

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            clear_admin_login_attempts(client_key)
            session.clear()
            session[ADMIN_SESSION_KEY] = True
            return redirect(next_url)

        record_failed_admin_login(client_key)
        error = "Invalid admin username or password."

    using_default_credentials = (
        ADMIN_USERNAME == "admin" and ADMIN_PASSWORD == "change-me-now"
    )
    return render_template(
        "admin_login.html",
        error=error,
        next_url=next_url,
        using_default_credentials=using_default_credentials,
    )


@app.route("/kryptnet-secure-review/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/kryptnet-secure-review/api/submissions")
def api_submissions():
    auth_redirect = require_admin()
    if auth_redirect:
        return auth_redirect

    records = ClientOnboarding.query.order_by(ClientOnboarding.created_at.desc()).all()
    return jsonify([record.to_dict() for record in records])


@app.route("/healthz")
def healthcheck():
    try:
        db.session.execute(db.text("SELECT 1"))
        database_status = "ok"
    except Exception:
        database_status = "error"

    status_code = 200 if database_status == "ok" else 503
    return (
        jsonify(
            {
                "status": "ok" if database_status == "ok" else "degraded",
                "database": database_status,
            }
        ),
        status_code,
    )


def mount_kryptscan_app():
    os.environ.setdefault("APP_NAME", "Kryptnet Security Assessment")
    os.environ["APP_ENV"] = os.getenv("KRYPTSCAN_APP_ENV", "staging")
    os.environ.setdefault("APP_SECRET", app.config["SECRET_KEY"])
    os.environ.setdefault("DATABASE_PATH", "../instance/kryptscan.db")
    os.environ.setdefault("REPORTS_DIR", "../instance/kryptscan_reports")
    os.environ.setdefault("SESSION_COOKIE_NAME", "kryptscan_session")
    os.environ.setdefault("SESSION_COOKIE_SECURE", "true" if app.config["SESSION_COOKIE_SECURE"] else "false")
    trusted_hosts = os.getenv("KRYPTSCAN_TRUSTED_HOSTS") or os.getenv("TRUSTED_HOSTS", "")
    required_hosts = "kryptscan.kryptnet.org,*.kryptnet.org,*.onrender.com,localhost,127.0.0.1"
    os.environ["TRUSTED_HOSTS"] = ",".join(
        item
        for item in [trusted_hosts, required_hosts]
        if item
    )
    smtp_ready = all(
        [
            os.getenv("SMTP_HOST", "").strip(),
            os.getenv("SMTP_USERNAME", "").strip(),
            os.getenv("SMTP_PASSWORD", "").strip(),
            os.getenv("SMTP_FROM_EMAIL", "").strip(),
        ]
    )
    requested_email_delivery = os.getenv("KRYPTSCAN_EMAIL_DELIVERY") or os.getenv("EMAIL_DELIVERY", "")
    if smtp_ready and requested_email_delivery.strip().lower() in {"", "console"}:
        os.environ["EMAIL_DELIVERY"] = "smtp"
    else:
        os.environ.setdefault("EMAIL_DELIVERY", requested_email_delivery or "console")
    os.environ.setdefault("EMAIL_FROM", os.getenv("SMTP_FROM_EMAIL", "security@kryptnet.org"))
    os.environ.setdefault("KRYPTNET_PAYMENT_API_URL", "https://payments.kryptnet.com/api")
    os.environ.setdefault("PAYMENT_DEMO_MODE", "false")
    os.environ.setdefault("SCANNER_BACKEND", "mock")
    os.environ.setdefault("ALLOW_PRIVATE_NETWORK_TARGETS", "false")

    from kryptscan.app.db import init_db as init_kryptscan_db
    from kryptscan.app.main import app as kryptscan_asgi_app

    init_kryptscan_db()
    app.wsgi_app = DispatcherMiddleware(
        app.wsgi_app,
        {"/kryptscan-app": ASGIMiddleware(kryptscan_asgi_app)},
    )


ensure_database_tables()
mount_kryptscan_app()


if __name__ == "__main__":
    app.run(debug=True)

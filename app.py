from datetime import datetime, timedelta
from email.message import EmailMessage
from io import BytesIO
import os
import re
import secrets
import smtplib
import textwrap

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from werkzeug.datastructures import MultiDict
from werkzeug.middleware.proxy_fix import ProxyFix


def normalize_database_url(database_url):
    if not database_url:
        return "sqlite:///kryptnet_onboarding.db"
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql://", 1)
    return database_url


app = Flask(__name__, static_folder="static")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["SQLALCHEMY_DATABASE_URI"] = normalize_database_url(
    os.getenv("DATABASE_URL")
)
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
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "").strip()
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "KryptNet")
ADMIN_NOTIFICATION_EMAIL = os.getenv(
    "ADMIN_NOTIFICATION_EMAIL", "support@kryptnet.org"
).strip()

LOGO_CANDIDATES = (
    "kryptnet-logo.png",
    "kryptnet_logo.png",
    "kryptnet_logo.png.png",
)

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def split_csv(value):
    return [item.strip() for item in value.split(",") if item.strip()] if value else []


def format_score(score):
    if score is None:
        score = 0
    return f"{score}%"


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
        text = str(text)
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

    pdf.setTitle(f"KryptNet Onboarding Report {record.id}")
    pdf.setFont("Helvetica-Bold", 18)
    write_line("KryptNet Onboarding Report", gap=28)

    pdf.setFont("Helvetica", 11)
    report_lines = [
        f"Submission ID: {record.id}",
        f"Submitted At: {record.created_at.isoformat()}",
        "",
        f"Business: {record.business_name}",
        f"Industry: {record.industry or 'Not provided'}",
        f"Contact Name: {record.contact_name}",
        f"Email: {record.email}",
        f"Phone: {record.phone}",
        f"Address: {record.address or 'Not provided'}",
        "",
        f"Employees: {record.employees if record.employees is not None else 'Not provided'}",
        f"Computers: {record.computers if record.computers is not None else 'Not provided'}",
        f"Servers: {record.servers if record.servers is not None else 'Not provided'}",
        f"Number of WiFi AP: {record.wifi_aps if record.wifi_aps is not None else 'Not provided'}",
        f"Email Platform: {record.email_platform or 'Not provided'}",
        f"Internet Provider: {record.internet_provider or 'Not provided'}",
        "",
        f"Risk Evaluation Controls Selected: {assessment['selected_controls_text']}",
        f"Controls Not Selected For Review: {assessment['missing_controls_text']}",
        f"Services Requested: {services_text}",
        f"Security Readiness Score: {format_score(record.risk_score)}",
        f"Risk Level: {record.risk_level}",
        f"Readiness Summary: {readiness_summary}",
        "",
        "Potential Vulnerability Areas:",
    ]

    for exposure_line in assessment["exposure_lines"]:
        report_lines.append(f"- {exposure_line}")

    if not assessment["exposure_lines"]:
        report_lines.append(
            "- No major missing control exposures were identified from the selected answers."
        )

    report_lines.extend(
        [
            "",
            "Risk Evaluation Note:",
            service_risk_statement,
            "",
            f"Notes: {record.notes or 'None'}",
        ]
    )

    for line in report_lines:
        write_line(line)

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

    message = build_client_confirmation_email(record)

    try:
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


def send_admin_notification_email(record):
    if not smtp_is_configured():
        app.logger.warning(
            "SMTP is not configured; skipping admin notification email for submission %s",
            record.id,
        )
        return "skipped"

    message = build_admin_notification_email(record)

    try:
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
        )

        db.session.add(record)
        db.session.commit()
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

    return render_template(
        "onboarding.html",
        errors=errors,
        form=form_data,
        service_options=SERVICE_OPTIONS,
        risk_control_options=RISK_CONTROL_OPTIONS,
    )


@app.route("/success/<int:submission_id>")
def submission_success(submission_id):
    record = ClientOnboarding.query.get_or_404(submission_id)
    email_status = request.args.get("email_status", "unknown")
    admin_email_status = request.args.get("admin_email_status", "unknown")
    readiness_summary = build_readiness_summary(record.risk_score, record.risk_level)
    assessment = build_control_assessment(record)
    return render_template(
        "success.html",
        record=record,
        email_status=email_status,
        admin_email_status=admin_email_status,
        admin_notification_email=ADMIN_NOTIFICATION_EMAIL,
        readiness_summary=readiness_summary,
        assessment=assessment,
        service_risk_statement=build_service_risk_statement(record),
        risk_score_percent=format_score(record.risk_score),
    )


@app.route("/kryptnet-secure-review/submissions")
def admin_submissions():
    auth_redirect = require_admin()
    if auth_redirect:
        return auth_redirect

    records = ClientOnboarding.query.order_by(ClientOnboarding.created_at.desc()).all()
    return render_template("admin.html", records=records)


@app.route("/kryptnet-secure-review/submissions/<int:submission_id>/delete", methods=["POST"])
def delete_submission(submission_id):
    auth_redirect = require_admin()
    if auth_redirect:
        return auth_redirect

    record = ClientOnboarding.query.get_or_404(submission_id)
    db.session.delete(record)
    db.session.commit()
    return redirect(url_for("admin_submissions"))


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


ensure_database_tables()


if __name__ == "__main__":
    app.run(debug=True)

from datetime import datetime
import os
import re
import secrets

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
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

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me-now")
ADMIN_SESSION_KEY = "admin_authenticated"

LOGO_CANDIDATES = (
    "kryptnet-logo.png",
    "kryptnet_logo.png",
    "kryptnet_logo.png.png",
)

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


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
    email_platform = db.Column(db.String(120), nullable=True)
    internet_provider = db.Column(db.String(120), nullable=True)
    antivirus = db.Column(db.Boolean, default=False)
    backups = db.Column(db.Boolean, default=False)
    mfa = db.Column(db.Boolean, default=False)
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
            "email_platform": self.email_platform,
            "internet_provider": self.internet_provider,
            "antivirus": self.antivirus,
            "backups": self.backups,
            "mfa": self.mfa,
            "selected_services": (
                self.selected_services.split(",") if self.selected_services else []
            ),
            "notes": self.notes,
            "authorized": self.authorized,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
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


def ensure_database_tables():
    # Keep migrations as the primary schema workflow, but bootstrap the core
    # table defensively in environments where the start command skips them.
    with app.app_context():
        db.create_all()


def calculate_risk_score(antivirus, backups, mfa):
    score = 0
    if not antivirus:
        score += 30
    if not backups:
        score += 35
    if not mfa:
        score += 35

    if score <= 20:
        level = "Low"
    elif score <= 40:
        level = "Moderate"
    elif score <= 70:
        level = "High"
    else:
        level = "Critical"

    return score, level


def get_logo_filename():
    static_folder = app.static_folder or "static"
    for filename in LOGO_CANDIDATES:
        if os.path.exists(os.path.join(static_folder, filename)):
            return filename
    return None


def is_admin_authenticated():
    return session.get(ADMIN_SESSION_KEY) is True


def require_admin():
    if not is_admin_authenticated():
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("admin_login", next=request.path))
    return None


def sanitize_next_url(next_url):
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
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
    return render_template("home.html", logo_src=logo_src, admin_logged_in=is_admin_authenticated())


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
        email_platform = request.form.get("email_platform", "").strip()
        internet_provider = request.form.get("internet_provider", "").strip()
        antivirus = request.form.get("antivirus") == "on"
        backups = request.form.get("backups") == "on"
        mfa = request.form.get("mfa") == "on"
        selected_services = request.form.getlist("selected_services")
        notes = request.form.get("notes", "").strip()
        authorized = request.form.get("authorized") == "on"

        validate_required_text(errors, "business_name", business_name, "Business name", 200)
        validate_optional_text(errors, "industry", industry, "Industry", 120)
        validate_required_text(errors, "contact_name", contact_name, "Contact name", 150)
        validate_required_text(errors, "email", email, "Email", 150)
        validate_required_text(errors, "phone", phone, "Phone", 50)
        validate_optional_text(errors, "address", address, "Business address", 2000)
        validate_required_text(errors, "email_platform", email_platform, "Email platform", 120)
        validate_optional_text(errors, "internet_provider", internet_provider, "Internet provider", 120)
        validate_optional_text(errors, "notes", notes, "Additional notes", 4000)

        if email and not EMAIL_REGEX.match(email):
            errors["email"] = "Enter a valid email address."

        phone_digits = re.sub(r"\D", "", phone)
        if phone and len(phone_digits) < 10:
            errors["phone"] = "Enter a valid phone number with at least 10 digits."

        employees_val = validate_non_negative_integer(
            errors, "employees", employees, "Number of employees"
        )
        computers_val = validate_non_negative_integer(
            errors, "computers", computers, "Number of computers", required=True
        )
        servers_val = validate_non_negative_integer(
            errors, "servers", servers, "Number of servers"
        )

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
            )

        risk_score, risk_level = calculate_risk_score(antivirus, backups, mfa)

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
            email_platform=email_platform,
            internet_provider=internet_provider,
            antivirus=antivirus,
            backups=backups,
            mfa=mfa,
            selected_services=",".join(selected_services),
            notes=notes,
            authorized=authorized,
            risk_score=risk_score,
            risk_level=risk_level,
        )

        db.session.add(record)
        db.session.commit()
        return redirect(url_for("submission_success", submission_id=record.id))

    return render_template(
        "onboarding.html",
        errors=errors,
        form=form_data,
        service_options=SERVICE_OPTIONS,
    )


@app.route("/success/<int:submission_id>")
def submission_success(submission_id):
    record = ClientOnboarding.query.get_or_404(submission_id)
    return render_template("success.html", record=record)


@app.route("/admin/submissions")
def admin_submissions():
    auth_redirect = require_admin()
    if auth_redirect:
        return auth_redirect

    records = ClientOnboarding.query.order_by(ClientOnboarding.created_at.desc()).all()
    return render_template("admin.html", records=records)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if is_admin_authenticated():
        return redirect(url_for("admin_submissions"))

    error = ""
    next_url = sanitize_next_url(
        request.args.get("next") or request.form.get("next")
    )

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session.clear()
            session[ADMIN_SESSION_KEY] = True
            return redirect(next_url)

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


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/api/submissions")
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

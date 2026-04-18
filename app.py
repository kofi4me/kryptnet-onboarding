from flask import Flask, request, redirect, url_for, render_template_string, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.datastructures import MultiDict
import os

app = Flask(__name__, static_folder="static")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///kryptnet_onboarding.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-secret-key")

db = SQLAlchemy(app)


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
            "selected_services": self.selected_services.split(",") if self.selected_services else [],
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


@app.route("/")
def index():
    return render_template_string(HOME_TEMPLATE)


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

        if not business_name:
            errors["business_name"] = "Business name is required."
        if not contact_name:
            errors["contact_name"] = "Contact name is required."
        if not email:
            errors["email"] = "Email is required."
        if not phone:
            errors["phone"] = "Phone is required."
        if not computers:
            errors["computers"] = "Number of computers is required."
        if not email_platform:
            errors["email_platform"] = "Email platform is required."
        if not selected_services:
            errors["selected_services"] = "Select at least one service."
        if not authorized:
            errors["authorized"] = "You must authorize KryptNet to review the submission."

        if errors:
            return render_template_string(
                FORM_TEMPLATE,
                errors=errors,
                form=form_data,
                service_options=SERVICE_OPTIONS,
            )

        employees_val = int(employees) if employees.isdigit() else None
        computers_val = int(computers) if computers.isdigit() else None
        servers_val = int(servers) if servers.isdigit() else None

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

    return render_template_string(
        FORM_TEMPLATE,
        errors=errors,
        form=form_data,
        service_options=SERVICE_OPTIONS,
    )


@app.route("/success/<int:submission_id>")
def submission_success(submission_id):
    record = ClientOnboarding.query.get_or_404(submission_id)
    return render_template_string(SUCCESS_TEMPLATE, record=record)


@app.route("/admin/submissions")
def admin_submissions():
    records = ClientOnboarding.query.order_by(ClientOnboarding.created_at.desc()).all()
    return render_template_string(ADMIN_TEMPLATE, records=records)


@app.route("/api/submissions")
def api_submissions():
    records = ClientOnboarding.query.order_by(ClientOnboarding.created_at.desc()).all()
    return jsonify([r.to_dict() for r in records])


HOME_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>KryptNet Client Onboarding</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f8fafc; margin: 0; color: #0f172a; }
        .container { max-width: 1100px; margin: 0 auto; padding: 40px 20px; }
        .hero { background: white; border-radius: 18px; padding: 40px; box-shadow: 0 8px 24px rgba(0,0,0,0.06); }
        .logo-wrap { margin-bottom: 24px; }
        .logo { max-width: 220px; height: auto; display: block; }
        h1 { margin-top: 0; font-size: 2.2rem; }
        .btn { display: inline-block; padding: 14px 22px; border-radius: 12px; background: #0f172a; color: white; text-decoration: none; font-weight: bold; }
        .muted { color: #475569; line-height: 1.6; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 18px; margin-top: 24px; }
        .card { background: white; border-radius: 16px; padding: 20px; box-shadow: 0 8px 24px rgba(0,0,0,0.05); }
        .note { margin-top: 14px; font-size: 0.95rem; color: #64748b; }
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <div class="logo-wrap">
                <img src="/static/kryptnet-logo.png" alt="KryptNet Logo" class="logo" onerror="this.style.display='none'; document.getElementById('logo-fallback').style.display='block';">
                <div id="logo-fallback" style="display:none; font-size:1.6rem; font-weight:bold; color:#0f172a;">KryptNet</div>
            </div>
            <h1>KryptNet Client Onboarding Portal</h1>
            <p class="muted">Use this onboarding application to collect business profile details, technical environment information, requested services, and authorization for new managed service clients.</p>
            <p><a class="btn" href="/onboarding">Start Client Onboarding</a></p>
            <p class="note">To show your real logo here, create a folder named <strong>static</strong> in your project and save the file as <strong>kryptnet-logo.png</strong>.</p>
        </div>
        <div class="grid">
            <div class="card">
                <h3>Business Profile</h3>
                <p class="muted">Capture organization details, primary contact information, and business size.</p>
            </div>
            <div class="card">
                <h3>Technical Intake</h3>
                <p class="muted">Collect computer counts, server details, email platform information, and provider data.</p>
            </div>
            <div class="card">
                <h3>Risk Snapshot</h3>
                <p class="muted">Generate a simple risk score using antivirus, backups, and MFA answers.</p>
            </div>
        </div>
    </div>
</body>
</html>
"""


FORM_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>KryptNet Onboarding Form</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f8fafc; margin: 0; color: #0f172a; }
        .container { max-width: 980px; margin: 0 auto; padding: 32px 20px; }
        .panel { background: white; border-radius: 18px; padding: 28px; box-shadow: 0 8px 24px rgba(0,0,0,0.06); }
        h1, h2 { margin-top: 0; }
        .section { margin-top: 28px; padding-top: 20px; border-top: 1px solid #e2e8f0; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }
        label { display: block; font-weight: bold; margin-bottom: 6px; }
        input[type=text], input[type=email], input[type=number], textarea { width: 100%; box-sizing: border-box; padding: 12px; border: 1px solid #cbd5e1; border-radius: 10px; }
        textarea { min-height: 96px; }
        .error { color: #b91c1c; font-size: 0.92rem; margin-top: 6px; }
        .checkbox-group { display: grid; gap: 10px; }
        .service-box, .security-box { padding: 14px; border: 1px solid #cbd5e1; border-radius: 12px; background: #fff; }
        .btn { padding: 14px 22px; border: none; border-radius: 12px; background: #0f172a; color: white; font-weight: bold; cursor: pointer; }
        .muted { color: #475569; }
        .hint { background: #eff6ff; color: #1e3a8a; border-radius: 12px; padding: 14px; margin-bottom: 18px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="panel">
            <h1>KryptNet Client Onboarding Form</h1>
            <p class="muted">Complete this intake form to begin onboarding with KryptNet managed services.</p>
            <div class="hint">This version stores submissions in a database and calculates a lightweight risk score based on antivirus, backups, and MFA.</div>
            <form method="POST">
                <div class="section">
                    <h2>1. Business Profile</h2>
                    <div class="grid">
                        <div>
                            <label>Business Name *</label>
                            <input type="text" name="business_name" value="{{ form.get('business_name', '') }}">
                            {% if errors.get('business_name') %}<div class="error">{{ errors.get('business_name') }}</div>{% endif %}
                        </div>
                        <div>
                            <label>Industry</label>
                            <input type="text" name="industry" value="{{ form.get('industry', '') }}">
                        </div>
                        <div>
                            <label>Contact Name *</label>
                            <input type="text" name="contact_name" value="{{ form.get('contact_name', '') }}">
                            {% if errors.get('contact_name') %}<div class="error">{{ errors.get('contact_name') }}</div>{% endif %}
                        </div>
                        <div>
                            <label>Email *</label>
                            <input type="email" name="email" value="{{ form.get('email', '') }}">
                            {% if errors.get('email') %}<div class="error">{{ errors.get('email') }}</div>{% endif %}
                        </div>
                        <div>
                            <label>Phone *</label>
                            <input type="text" name="phone" value="{{ form.get('phone', '') }}">
                            {% if errors.get('phone') %}<div class="error">{{ errors.get('phone') }}</div>{% endif %}
                        </div>
                        <div>
                            <label>Number of Employees</label>
                            <input type="number" name="employees" value="{{ form.get('employees', '') }}">
                        </div>
                    </div>
                    <div style="margin-top: 16px;">
                        <label>Business Address</label>
                        <textarea name="address">{{ form.get('address', '') }}</textarea>
                    </div>
                </div>

                <div class="section">
                    <h2>2. Technical Environment</h2>
                    <div class="grid">
                        <div>
                            <label>Number of Computers *</label>
                            <input type="number" name="computers" value="{{ form.get('computers', '') }}">
                            {% if errors.get('computers') %}<div class="error">{{ errors.get('computers') }}</div>{% endif %}
                        </div>
                        <div>
                            <label>Number of Servers</label>
                            <input type="number" name="servers" value="{{ form.get('servers', '') }}">
                        </div>
                        <div>
                            <label>Email Platform *</label>
                            <input type="text" name="email_platform" value="{{ form.get('email_platform', '') }}" placeholder="Microsoft 365, Google Workspace">
                            {% if errors.get('email_platform') %}<div class="error">{{ errors.get('email_platform') }}</div>{% endif %}
                        </div>
                        <div>
                            <label>Internet Provider</label>
                            <input type="text" name="internet_provider" value="{{ form.get('internet_provider', '') }}">
                        </div>
                    </div>
                    <div class="grid" style="margin-top: 16px;">
                        <div class="security-box">
                            <label><input type="checkbox" name="antivirus" {% if form.get('antivirus') %}checked{% endif %}> Antivirus / EDR in place</label>
                        </div>
                        <div class="security-box">
                            <label><input type="checkbox" name="backups" {% if form.get('backups') %}checked{% endif %}> Backups enabled</label>
                        </div>
                        <div class="security-box">
                            <label><input type="checkbox" name="mfa" {% if form.get('mfa') %}checked{% endif %}> MFA enabled</label>
                        </div>
                    </div>
                </div>

                <div class="section">
                    <h2>3. Requested Services</h2>
                    <div class="checkbox-group">
                        {% for service in service_options %}
                        <div class="service-box">
                            <label>
                                <input type="checkbox" name="selected_services" value="{{ service }}" {% if service in form.getlist('selected_services') %}checked{% endif %}>
                                {{ service }}
                            </label>
                        </div>
                        {% endfor %}
                    </div>
                    {% if errors.get('selected_services') %}<div class="error">{{ errors.get('selected_services') }}</div>{% endif %}
                    <div style="margin-top: 16px;">
                        <label>Additional Notes</label>
                        <textarea name="notes">{{ form.get('notes', '') }}</textarea>
                    </div>
                </div>

                <div class="section">
                    <h2>4. Authorization</h2>
                    <div class="service-box">
                        <label>
                            <input type="checkbox" name="authorized" {% if form.get('authorized') %}checked{% endif %}>
                            I authorize KryptNet to review this information and begin onboarding preparation.
                        </label>
                    </div>
                    {% if errors.get('authorized') %}<div class="error">{{ errors.get('authorized') }}</div>{% endif %}
                </div>

                <div style="margin-top: 24px;">
                    <button class="btn" type="submit">Submit Onboarding</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
"""


SUCCESS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Submission Successful</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f8fafc; margin: 0; color: #0f172a; }
        .container { max-width: 980px; margin: 0 auto; padding: 40px 20px; }
        .panel { background: white; border-radius: 18px; padding: 32px; box-shadow: 0 8px 24px rgba(0,0,0,0.06); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 18px; margin-top: 18px; }
        .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 14px; padding: 18px; }
        .btn { display: inline-block; padding: 12px 18px; border-radius: 12px; background: #0f172a; color: white; text-decoration: none; font-weight: bold; margin-right: 10px; }
        .badge { display: inline-block; padding: 6px 10px; border-radius: 999px; background: #e2e8f0; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="panel">
            <h1>Onboarding Submitted Successfully</h1>
            <p>KryptNet has captured the client onboarding record.</p>
            <div class="grid">
                <div class="card">
                    <h3>Client Summary</h3>
                    <p><strong>Business:</strong> {{ record.business_name }}</p>
                    <p><strong>Contact:</strong> {{ record.contact_name }}</p>
                    <p><strong>Email:</strong> {{ record.email }}</p>
                    <p><strong>Phone:</strong> {{ record.phone }}</p>
                    <p><strong>Services:</strong> {{ record.selected_services }}</p>
                </div>
                <div class="card">
                    <h3>Risk Snapshot</h3>
                    <p><strong>Score:</strong> {{ record.risk_score }}/100</p>
                    <p><strong>Level:</strong> <span class="badge">{{ record.risk_level }}</span></p>
                    <p><strong>Antivirus:</strong> {{ 'Yes' if record.antivirus else 'No' }}</p>
                    <p><strong>Backups:</strong> {{ 'Yes' if record.backups else 'No' }}</p>
                    <p><strong>MFA:</strong> {{ 'Yes' if record.mfa else 'No' }}</p>
                </div>
            </div>
            <p style="margin-top: 24px;">
                <a class="btn" href="/onboarding">New Submission</a>
                <a class="btn" href="/admin/submissions">View Admin List</a>
            </p>
        </div>
    </div>
</body>
</html>
"""


ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>KryptNet Admin - Submissions</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f8fafc; margin: 0; color: #0f172a; }
        .container { max-width: 1180px; margin: 0 auto; padding: 32px 20px; }
        .panel { background: white; border-radius: 18px; padding: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.06); }
        table { width: 100%; border-collapse: collapse; margin-top: 18px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
        th { background: #f8fafc; }
        .badge { display: inline-block; padding: 6px 10px; border-radius: 999px; background: #e2e8f0; font-weight: bold; }
        .small { color: #475569; font-size: 0.9rem; }
        .btn { display: inline-block; padding: 12px 18px; border-radius: 12px; background: #0f172a; color: white; text-decoration: none; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="panel">
            <h1>KryptNet Client Onboarding Submissions</h1>
            <p class="small">This page lists all onboarding records stored in the database.</p>
            <p><a class="btn" href="/onboarding">Create New Submission</a></p>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Business</th>
                        <th>Contact</th>
                        <th>Email</th>
                        <th>Services</th>
                        <th>Risk</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
                    {% for record in records %}
                    <tr>
                        <td>{{ record.id }}</td>
                        <td>{{ record.business_name }}</td>
                        <td>{{ record.contact_name }}<br><span class="small">{{ record.phone }}</span></td>
                        <td>{{ record.email }}</td>
                        <td>{{ record.selected_services }}</td>
                        <td><span class="badge">{{ record.risk_level }} ({{ record.risk_score }})</span></td>
                        <td>{{ record.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="7">No submissions yet.</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

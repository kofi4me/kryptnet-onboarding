# KryptNet MSP Onboarding

Flask application for collecting MSP onboarding submissions, calculating a simple risk score, and reviewing submissions through an authenticated admin area.

## Features

- Public onboarding form for new client intake
- Database-backed submission storage with Flask-SQLAlchemy
- Risk scoring based on antivirus, backups, and MFA answers
- Authenticated admin submissions view
- Protected JSON API for submission data
- Health check endpoint at `/healthz`

## Local setup

1. Create and activate a virtual environment.
2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Copy `.env.example` values into your environment.
4. Initialize or upgrade the database schema:

```powershell
flask db upgrade
```

5. Run the app:

```powershell
python app.py
```

## Required environment variables

- `SECRET_KEY`: Required for stable, secure session signing.
- `ADMIN_USERNAME`: Admin login username.
- `ADMIN_PASSWORD`: Admin login password.

## Optional environment variables

- `DATABASE_URL`: Defaults to `sqlite:///kryptnet_onboarding.db`.
- `FLASK_ENV`: Set to `production` to enable secure session cookies behind HTTPS.
- `FLASK_APP`: Use `app.py` when running Flask CLI commands.

## Deployment

The project includes a `Procfile` configured for Gunicorn:

```text
web: gunicorn app:app
```

Notes:

- The app supports hosted Postgres connection strings that begin with `postgres://` and normalizes them to `postgresql://`.
- Reverse proxy headers are handled with `ProxyFix`, which helps when deploying behind platforms like Render, Railway, or Heroku.
- Use a real external database for production instead of SQLite.
- Set strong values for `SECRET_KEY`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD` before deployment.
- Run `flask db upgrade` during deploy so the target database is on the expected schema.

## Admin access

- Admin login: `/admin/login`
- Admin submissions view: `/admin/submissions`
- Protected API: `/api/submissions`

## Health checks

Use `/healthz` for uptime checks. It returns:

- `200` when the app and database query are healthy
- `503` when the app is up but the database is unavailable

## Database migrations

This project uses Flask-Migrate/Alembic for schema changes.

Common commands:

```powershell
flask db upgrade
flask db migrate -m "describe change"
flask db downgrade
```

For a brand-new environment, run `flask db upgrade` before starting the app.

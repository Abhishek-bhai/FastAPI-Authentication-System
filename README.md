# FastAPI Authentication System

A REST API built with FastAPI, SQLAlchemy and JWT authentication. It demonstrates account registration, login, protected endpoints, refresh-token rotation, logout/revocation, email verification, password reset, OTP login, and Google/GitHub OAuth.

## Features

- Password hashing and validated request schemas
- Short-lived access tokens and rotating refresh tokens
- Refresh-token reuse detection and logout revocation
- Protected profile and premium endpoints
- Email verification and password-reset token flows
- Email OTP with expiry and attempt limits
- Google ID-token signature/audience/expiry verification
- GitHub OAuth with verified primary-email lookup
- OAuth state bound to a signed, HttpOnly, short-lived browser cookie
- CORS configuration and request rate limits
- Pytest suite with isolated SQLite databases

## Requirements

- Python 3.11 or newer
- pip
- SMTP credentials for actual email delivery
- Google/GitHub OAuth app credentials for social login

## Local setup (Linux/Kali)

```bash
git clone https://github.com/Abhishek-bhai/FastAPI-Authentication-System.git
cd FastAPI-Authentication-System
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`. Generate a strong development secret with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set `SECRET_KEY` to that value. The default database is local SQLite. Never commit `.env` or real provider credentials.

## Configuration

The application reads these environment variables from `.env` (or the process environment):

| Variable | Purpose |
|---|---|
| `APP_ENV`, `DEBUG` | Environment and debug mode |
| `DATABASE_URL` | SQLAlchemy database URL; defaults to `sqlite:///./app.db` |
| `SECRET_KEY`, `ALGORITHM` | JWT signing configuration |
| `ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_EXPIRE_DAYS` | Token lifetimes |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` | Email delivery |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` | Google OAuth |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URI` | GitHub OAuth |
| `CORS_ORIGINS` | Comma-separated allowed origins |
| `RATE_LIMIT_PER_MINUTE`, `OTP_RATE_LIMIT_PER_MINUTE` | Request limits |

Values in `.env.example` are placeholders, not working credentials. Configure real credentials only in your local `.env` or deployment secret store.

## Database migrations

Apply migrations before starting the server:

```bash
python -m alembic upgrade head
python -m alembic current
python -m alembic check
```

The server does not create tables on startup; Alembic is the schema owner. For an existing database created outside Alembic, first back it up and verify that its tables, columns, indexes, constraints, and foreign keys match the migration. Only then record the matching revision with `python -m alembic stamp 20250217_initial_auth`; do not stamp an unverified database or run the initial upgrade against tables that already exist.

## Run

```bash
uvicorn app.main:app --reload
```

- API docs: http://127.0.0.1:8000/docs
- Health check: http://127.0.0.1:8000/health

## Email configuration

Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM` in `.env`. Port 465 uses SMTP over SSL; other configured ports use STARTTLS. Email-related endpoints return an error if SMTP delivery is not configured or fails. Tests mock SMTP and do not send real email.

## OAuth setup

Create OAuth applications in the Google Cloud Console and GitHub Developer settings. Configure each client ID, client secret and exact callback URL in `.env`:

- Google callback: `http://localhost:8000/auth/google/callback`
- GitHub callback: `http://localhost:8000/auth/github/callback`

The frontend/client must call `/auth/google/login` or `/auth/github/login` using a browser that retains cookies, then navigate to the returned `authorization_url`. The callback checks the returned state against a signed, short-lived HttpOnly cookie. OAuth is unavailable until real credentials are supplied.

For production, use HTTPS, set `APP_ENV=production`, `DEBUG=false`, a strong secret, real SMTP credentials and real OAuth credentials. Restrict CORS origins to trusted frontend origins.

## Main endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/auth/register` | Create account |
| POST | `/auth/login` | Obtain access and refresh tokens |
| POST | `/auth/refresh` | Rotate refresh token |
| POST | `/auth/logout` | Revoke tokens |
| GET | `/auth/me` | Current authenticated profile |
| GET | `/auth/premium` | Example protected resource |
| POST | `/auth/request-verification` | Send verification email |
| POST | `/auth/verify-email` | Verify email token |
| POST | `/auth/request-password-reset` | Request password reset |
| POST | `/auth/reset-password` | Set password using reset token |
| POST | `/auth/otp/request` | Send email OTP |
| POST | `/auth/otp/verify` | Verify OTP and log in |
| GET | `/auth/google/login` | Start Google OAuth |
| GET | `/auth/github/login` | Start GitHub OAuth |

## Tests

```bash
python -m pytest -q
pip check
```

The tests use temporary SQLite databases and mock email delivery; they do not need live SMTP or OAuth provider credentials.

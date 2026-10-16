# FastAPI Authentication System

A REST API built with FastAPI, SQLAlchemy and JWT authentication. It demonstrates account registration, login, protected endpoints, refresh-token rotation, logout/revocation, email verification, password reset, OTP login, and Google/GitHub OAuth.

## Features

- Password hashing and validated request schemas
- Short-lived access tokens and rotating refresh tokens
- Refresh-token reuse detection and logout revocation
- Password resets invalidate previously issued access and refresh tokens
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

Rate limits are enforced in process memory and are intended for a single application worker. Multi-worker or multi-instance deployments should use a shared rate-limit backend at the edge or in the application.

Values in `.env.example` are placeholders, not working credentials. Configure real credentials only in your local `.env` or deployment secret store.
`SECRET_KEY` is required; the application no longer falls back to a known development signing key.

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

In Swagger UI, use **Authorize** with the account email as the username and its password. This uses the OAuth2 password-flow endpoint `/auth/token`; JSON clients can continue using `/auth/login`.

## Docker

Docker Compose runs the API as a non-root user, binds port 8000 to localhost, and stores SQLite data in a named volume. The project `.env` file is supplied to the container at runtime and excluded from the image build context.

```bash
if [ ! -f .env ]; then cp .env.example .env; fi
# Edit .env and set SECRET_KEY to a strong, unique value.
docker compose build
docker compose run --rm api alembic upgrade head
docker compose up
```

Open `http://127.0.0.1:8000/docs` for interactive API testing. Stop the service with `docker compose down`; the `auth_data` volume is retained. To remove that volume and its database, use `docker compose down --volumes` only when you intend to delete the persisted data.

## Email configuration

Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM` in `.env`. Port 465 uses SMTP over SSL; other configured ports use STARTTLS. Registration reports a service error if the initial verification email cannot be delivered. Verification-email resend, password-reset, and OTP requests use generic responses to avoid revealing whether an email belongs to an account; delivery failures are logged without including tokens, codes, or recipient addresses. Tests mock SMTP and do not send real email.

## OAuth setup

OAuth login requires real provider credentials; the placeholder values in `.env.example` are deliberately rejected. Configure the provider callback URI exactly the same way in your provider dashboard and `.env`. The hostname used when starting OAuth, receiving the callback, and in the callback URI must be consistent (for example, use `localhost` throughout rather than mixing it with `127.0.0.1`).

### Google

1. In Google Cloud Console, create or select a project and configure the OAuth consent screen for your application.
2. Create an OAuth client ID of type **Web application**.
3. Add the exact callback URL `http://localhost:8000/auth/google/callback` as an authorized redirect URI for local development. For deployment, register the HTTPS callback URL instead.
4. Put the generated client ID and client secret in `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`; set `GOOGLE_REDIRECT_URI` to the same exact callback URI.
5. Start the API, request `http://localhost:8000/auth/google/login` from the browser/client, and navigate to the `authorization_url` in its JSON response. The browser must retain the API's OAuth state cookie and return to the same API hostname.
6. The callback exchanges the authorization code and verifies Google's ID token signature, audience, expiry, and verified email before creating or linking the account.

The Google flow requests `openid email profile`. Ensure your consent-screen configuration and any testing-user restrictions allow the account you use to sign in.

### GitHub

1. Create an OAuth App in GitHub Developer Settings.
2. Set its **Authorization callback URL** to `http://localhost:8000/auth/github/callback` for local development. For deployment, use the exact HTTPS callback URL.
3. Put the client ID and client secret in `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`; set `GITHUB_REDIRECT_URI` to the same exact callback URI.
4. Start the API, request `http://localhost:8000/auth/github/login`, and navigate to the returned `authorization_url` in a browser that retains the OAuth state cookie.
5. The callback exchanges the authorization code and requires a verified primary GitHub email.

Both callbacks validate the returned state against a signed, short-lived HttpOnly cookie before contacting the provider. A local test with placeholder credentials should return HTTP 400 with an OAuth-not-configured error; that is expected and does not indicate a callback defect. Automated tests cover placeholder rejection and state mismatch without calling external providers. Successful Google/GitHub login still requires manual testing with valid provider credentials, correct dashboard callback URLs, and browser cookie retention.

For production, use HTTPS, set `APP_ENV=production`, `DEBUG=false`, a strong secret, real SMTP credentials and real OAuth credentials. Restrict CORS origins to trusted frontend origins. Current production configuration requires both Google and GitHub credentials; change that policy before deploying if your service intentionally supports only one provider.

## Main endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/auth/register` | Create account |
| POST | `/auth/login` | Obtain access and refresh tokens |
| POST | `/auth/token` | Obtain tokens using OAuth2 password form (used by Swagger Authorize) |
| POST | `/auth/refresh` | Rotate refresh token |
| POST | `/auth/logout` | Revoke tokens |
| GET | `/auth/me` | Current authenticated profile |
| GET | `/auth/premium` | Example protected resource |
| POST | `/auth/request-verification` | Request a verification email using `{"email": "..."}` |
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

## API smoke test

Start the API, then run the smoke test with an existing account. It prompts for the password without echoing it, keeps tokens in memory, and checks login, protected endpoints, logout, and both token revocation paths:

```bash
python scripts/api_smoke_test.py --email user@example.com
```

To test against another local API URL:

```bash
python scripts/api_smoke_test.py --base-url http://127.0.0.1:8000 --email user@example.com
```

The smoke test logs out that account and revokes the session used for the test. Do not use an account whose session you need to keep active.

## Known limitations and manual verification

- Automated tests use temporary SQLite databases and mock email sending; they do not prove delivery through a real SMTP server.
- Google and GitHub authorization-code exchanges require provider credentials and matching callback configuration. They have not been tested end-to-end against live providers.
- The built-in rate limiter is in-memory and is not shared between multiple worker processes.
- Verify the email verification, password-reset, OTP, and social login flows manually in a configured local environment before relying on external delivery/provider behavior.

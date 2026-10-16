from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from fastapi.testclient import TestClient
from jose import jwt

from app.core.config import Settings, settings
from app.core.security import create_access_token, verify_password
from app.models.user import OAuthIdentity, OTPChallenge, PasswordResetToken, User
from app.services import auth_service
from app.services.email_service import EmailDeliveryError


def test_secret_key_must_be_configured(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_production_cors_rejects_wildcard_origins():
    production_settings = {
        "app_env": "production",
        "debug": False,
        "secret_key": "x" * 48,
        "smtp_host": "smtp.example.org",
        "smtp_username": "sender@example.org",
        "smtp_password": "test-placeholder",
        "smtp_from": "sender@example.org",
        "google_client_id": "configured-google-client",
        "google_client_secret": "configured-google-secret",
        "github_client_id": "configured-github-client",
        "github_client_secret": "configured-github-secret",
        "cors_origins": "https://app.example.org, *",
    }

    with pytest.raises(ValidationError, match="CORS_ORIGINS"):
        Settings(_env_file=None, **production_settings)


def test_production_cors_accepts_explicit_origins():
    production_settings = {
        "app_env": "production",
        "debug": False,
        "secret_key": "x" * 48,
        "smtp_host": "smtp.example.org",
        "smtp_username": "sender@example.org",
        "smtp_password": "test-placeholder",
        "smtp_from": "sender@example.org",
        "google_client_id": "configured-google-client",
        "google_client_secret": "configured-google-secret",
        "github_client_id": "configured-github-client",
        "github_client_secret": "configured-github-secret",
        "cors_origins": "https://app.example.org,https://admin.example.org",
    }

    config = Settings(_env_file=None, **production_settings)
    assert config.cors_origins == production_settings["cors_origins"]


def test_registration_and_login(client: TestClient):
    response = client.post(
        "/auth/register",
        json={"email": "alice@example.com", "username": "alice", "password": "strongpass123"},
    )
    assert response.status_code == 201, response.text

    verify_registered_user(client, "alice@example.com")
    login = client.post(
        "/auth/login",
        json={"email": "alice@example.com", "password": "strongpass123"},
    )
    assert login.status_code == 200, login.text
    data = login.json()
    assert "access_token" in data and "refresh_token" in data

    user = client.get("/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"})
    assert user.status_code == 200


def test_duplicate_registration(client: TestClient):
    payload = {"email": "bob@example.com", "username": "bob", "password": "strongpass123"}
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 201
    duplicate = client.post("/auth/register", json=payload)
    assert duplicate.status_code == 409


def test_password_login_requires_email_verification(client: TestClient):
    email = "unverified@example.com"
    client.post("/auth/register", json={"email": email, "username": "unverified", "password": "strongpass123"})

    unverified_login = client.post("/auth/login", json={"email": email, "password": "strongpass123"})
    assert unverified_login.status_code == 403
    assert unverified_login.json() == {"detail": "Please verify your email before logging in"}

    verify_registered_user(client, email)
    verified_login = client.post("/auth/login", json={"email": email, "password": "strongpass123"})
    assert verified_login.status_code == 200, verified_login.text


def test_password_reset_request_is_rate_limited_per_email(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "otp_rate_limit_per_minute", 1)
    email = "rate-limit@example.com"
    first = client.post("/auth/request-password-reset", json={"email": email})
    second = client.post("/auth/request-password-reset", json={"email": email})

    assert first.status_code == 200
    assert first.json() == {"message": "If that account exists, a password reset link has been sent."}
    assert second.status_code == 429


def test_protected_route_and_invalid_tokens(client: TestClient):
    openapi = client.get("/openapi.json").json()
    assert openapi["paths"]["/auth/me"]["get"]["security"] == [{"OAuth2PasswordBearer": []}]
    assert openapi["components"]["securitySchemes"]["OAuth2PasswordBearer"] == {
        "type": "oauth2",
        "flows": {
            "password": {
                "scopes": {},
                "tokenUrl": "/auth/token",
            },
        },
    }

    client.post("/auth/register", json={"email": "carol@example.com", "username": "carol", "password": "strongpass123"})
    verify_registered_user(client, "carol@example.com")
    login = client.post("/auth/login", json={"email": "carol@example.com", "password": "strongpass123"})
    access = login.json()["access_token"]

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert me.status_code == 200

    missing = client.get("/auth/me")
    assert missing.status_code == 401

    invalid = client.get("/auth/me", headers={"Authorization": "Bearer bad.token.here"})
    assert invalid.status_code == 401


def test_expired_access_token_is_rejected(client: TestClient):
    expired_token = jwt.encode(
        {
            "sub": "1",
            "type": "access",
            "jti": "expired-token",
            "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
        },
        settings.secret_key,
        algorithm=settings.algorithm,
    )
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401


def test_access_token_missing_jti_is_rejected(client: TestClient):
    token = jwt.encode(
        {
            "sub": "1",
            "type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=1),
            "iat": datetime.now(timezone.utc),
        },
        settings.secret_key,
        algorithm=settings.algorithm,
    )
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_access_token_without_expiry_is_rejected(client: TestClient):
    token_without_expiry = jwt.encode(
        {"sub": "1", "type": "access", "jti": "missing-expiry"},
        settings.secret_key,
        algorithm=settings.algorithm,
    )
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token_without_expiry}"})
    assert response.status_code == 401


def test_access_token_with_non_numeric_subject_returns_unauthorized(client: TestClient):
    token = create_access_token("not-a-user-id", "invalid-subject")
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_oauth2_form_login_and_protected_route(client: TestClient):
    client.post("/auth/register", json={"email": "oauth2@example.com", "username": "oauth2", "password": "strongpass123"})
    verify_registered_user(client, "oauth2@example.com")
    token_response = client.post(
        "/auth/token",
        data={"username": "oauth2@example.com", "password": "strongpass123"},
    )
    assert token_response.status_code == 200, token_response.text
    access_token = token_response.json()["access_token"]
    profile = client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert profile.status_code == 200


def test_refresh_rotation_and_reuse_detection(client: TestClient):
    client.post("/auth/register", json={"email": "dave@example.com", "username": "dave", "password": "strongpass123"})
    verify_registered_user(client, "dave@example.com")
    login = client.post("/auth/login", json={"email": "dave@example.com", "password": "strongpass123"})
    old_refresh = login.json()["refresh_token"]

    rotated = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert rotated.status_code == 200, rotated.text
    new_refresh = rotated.json()["refresh_token"]
    assert new_refresh != old_refresh

    replay = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert replay.status_code == 401
    revoked_after_replay = client.post("/auth/refresh", json={"refresh_token": new_refresh})
    assert revoked_after_replay.status_code == 401


def test_refresh_token_cannot_be_used_after_account_is_disabled(client: TestClient):
    client.post("/auth/register", json={"email": "disabled-refresh@example.com", "username": "disabled-refresh", "password": "strongpass123"})
    verify_registered_user(client, "disabled-refresh@example.com")
    login = client.post(
        "/auth/login",
        json={"email": "disabled-refresh@example.com", "password": "strongpass123"},
    )
    from app.database.session import SessionLocal

    db = SessionLocal()
    user = db.query(User).filter_by(email="disabled-refresh@example.com").first()
    user.is_active = False
    db.commit()
    db.close()

    disabled_refresh = client.post("/auth/refresh", json={"refresh_token": login.json()["refresh_token"]})
    assert disabled_refresh.status_code == 403

    revoked_refresh = client.post("/auth/refresh", json={"refresh_token": login.json()["refresh_token"]})
    assert revoked_refresh.status_code == 401


def test_logout_revokes_refresh_token(client: TestClient):
    client.post("/auth/register", json={"email": "erin@example.com", "username": "erin", "password": "strongpass123"})
    verify_registered_user(client, "erin@example.com")
    login = client.post("/auth/login", json={"email": "erin@example.com", "password": "strongpass123"})
    tokens = login.json()
    access = tokens["access_token"]
    refresh = tokens["refresh_token"]

    logout = client.post("/auth/logout", json={"refresh_token": refresh}, headers={"Authorization": f"Bearer {access}"})
    assert logout.status_code == 200, logout.text

    revoked_access = client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert revoked_access.status_code == 401

    reuse = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert reuse.status_code == 401


def test_logout_cannot_revoke_another_users_refresh_token(client: TestClient):
    client.post("/auth/register", json={"email": "owner@example.com", "username": "owner", "password": "strongpass123"})
    client.post("/auth/register", json={"email": "other@example.com", "username": "other", "password": "strongpass123"})
    verify_registered_user(client, "owner@example.com")
    verify_registered_user(client, "other@example.com")
    owner_login = client.post("/auth/login", json={"email": "owner@example.com", "password": "strongpass123"})
    other_login = client.post("/auth/login", json={"email": "other@example.com", "password": "strongpass123"})

    attempted_logout = client.post(
        "/auth/logout",
        json={"refresh_token": other_login.json()["refresh_token"]},
        headers={"Authorization": f"Bearer {owner_login.json()['access_token']}"},
    )
    assert attempted_logout.status_code == 403

    other_refresh = client.post(
        "/auth/refresh",
        json={"refresh_token": other_login.json()["refresh_token"]},
    )
    assert other_refresh.status_code == 200, other_refresh.text


def verify_registered_user(client: TestClient, email: str) -> None:
    from app.database.session import SessionLocal

    db = SessionLocal()
    try:
        user = db.query(User).filter_by(email=email).first()
        assert user is not None
        token = auth_service.request_verification_token(db, user)
    finally:
        db.close()
    response = client.post("/auth/verify-email", json={"token": token})
    assert response.status_code == 200, response.text


def test_email_verification_flow(client: TestClient):
    client.post("/auth/register", json={"email": "frank@example.com", "username": "frank", "password": "strongpass123"})
    from app.database.session import SessionLocal
    db = SessionLocal()
    user = db.query(User).filter_by(email="frank@example.com").first()
    token = auth_service.request_verification_token(db, user)
    db.close()

    verify = client.post("/auth/verify-email", json={"token": token})
    assert verify.status_code == 200, verify.text
    replay = client.post("/auth/verify-email", json={"token": token})
    assert replay.status_code == 400


def test_unverified_user_can_resend_verification_without_account_enumeration(
    client: TestClient, monkeypatch
):
    email = "resend-verification@example.com"
    registered = client.post(
        "/auth/register",
        json={"email": email, "username": "resend-verification", "password": "strongpass123"},
    )
    assert registered.status_code == 201

    delivered_bodies: list[str] = []
    monkeypatch.setattr(
        auth_service,
        "send_email",
        lambda subject, recipient, body: delivered_bodies.append(body),
    )
    response = client.post("/auth/request-verification", json={"email": email})
    unknown = client.post(
        "/auth/request-verification",
        json={"email": "unknown-verification@example.com"},
    )

    expected = {
        "message": "If that account exists and needs verification, a verification email has been sent."
    }
    assert response.status_code == unknown.status_code == 200
    assert response.json() == unknown.json() == expected
    assert len(delivered_bodies) == 1
    token = delivered_bodies[0].split("\n\n")[2]
    assert token not in response.text

    verified = client.post("/auth/verify-email", json={"token": token})
    assert verified.status_code == 200, verified.text
    client.post("/auth/request-verification", json={"email": email})
    assert len(delivered_bodies) == 1


def test_password_reset_flow(client: TestClient):
    client.post("/auth/register", json={"email": "gina@example.com", "username": "gina", "password": "strongpass123"})
    verify_registered_user(client, "gina@example.com")
    prior_login = client.post("/auth/login", json={"email": "gina@example.com", "password": "strongpass123"})
    prior_tokens = prior_login.json()
    from app.database.session import SessionLocal
    db = SessionLocal()
    user = db.query(User).filter_by(email="gina@example.com").first()
    token = auth_service.request_password_reset(db, user.email)
    db.close()

    reset = client.post("/auth/reset-password", json={"token": token, "new_password": "newStrongPass123"})
    assert reset.status_code == 200, reset.text
    old_access = client.get("/auth/me", headers={"Authorization": f"Bearer {prior_tokens['access_token']}"})
    assert old_access.status_code == 401
    old_refresh = client.post("/auth/refresh", json={"refresh_token": prior_tokens["refresh_token"]})
    assert old_refresh.status_code == 401

    login = client.post("/auth/login", json={"email": "gina@example.com", "password": "strongpass123"})
    assert login.status_code == 401

    success = client.post("/auth/login", json={"email": "gina@example.com", "password": "newStrongPass123"})
    assert success.status_code == 200, success.text

    replay = client.post("/auth/reset-password", json={"token": token, "new_password": "anotherPass123"})
    assert replay.status_code == 400


def test_password_reset_invalidates_other_outstanding_reset_tokens(client: TestClient):
    client.post(
        "/auth/register",
        json={"email": "reset-multiple@example.com", "username": "reset-multiple", "password": "strongpass123"},
    )
    verify_registered_user(client, "reset-multiple@example.com")

    from app.database.session import SessionLocal

    db = SessionLocal()
    try:
        first_token = auth_service.request_password_reset(db, "reset-multiple@example.com")
        second_token = auth_service.request_password_reset(db, "reset-multiple@example.com")
    finally:
        db.close()

    reset = client.post(
        "/auth/reset-password",
        json={"token": second_token, "new_password": "newStrongPass123"},
    )
    assert reset.status_code == 200, reset.text

    stale_reset = client.post(
        "/auth/reset-password",
        json={"token": first_token, "new_password": "anotherStrongPass123"},
    )
    assert stale_reset.status_code == 400


def test_expired_password_reset_token_is_rejected(client: TestClient):
    client.post("/auth/register", json={"email": "reset-expired@example.com", "username": "reset-expired", "password": "strongpass123"})
    from app.database.session import SessionLocal

    db = SessionLocal()
    user = db.query(User).filter_by(email="reset-expired@example.com").first()
    token = auth_service.request_password_reset(db, user.email)
    record = db.query(PasswordResetToken).filter_by(user_id=user.id).first()
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    db.close()

    response = client.post("/auth/reset-password", json={"token": token, "new_password": "newStrongPass123"})
    assert response.status_code == 400


def test_otp_flow(client: TestClient):
    client.post("/auth/register", json={"email": "henry@example.com", "username": "henry", "password": "strongpass123"})
    from app.database.session import SessionLocal
    db = SessionLocal()
    code = auth_service.request_otp(db, "henry@example.com")
    db.close()
    verify = client.post("/auth/otp/verify", json={"email": "henry@example.com", "code": code})
    assert verify.status_code == 200, verify.text
    tokens = verify.json()
    assert tokens["access_token"]
    assert tokens["refresh_token"]
    profile = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert profile.status_code == 200, profile.text
    replay = client.post("/auth/otp/verify", json={"email": "henry@example.com", "code": code})
    assert replay.status_code == 401


def test_otp_request_is_rate_limited(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "otp_rate_limit_per_minute", 1)
    client.post(
        "/auth/register",
        json={"email": "otp-rate-limit@example.com", "username": "otp-rate-limit", "password": "strongpass123"},
    )

    first = client.post("/auth/otp/request", json={"email": "otp-rate-limit@example.com"})
    second = client.post("/auth/otp/request", json={"email": "otp-rate-limit@example.com"})

    assert first.status_code == 200
    assert second.status_code == 429


def test_expired_otp_is_rejected(client: TestClient):
    client.post("/auth/register", json={"email": "otp-expired@example.com", "username": "otp-expired", "password": "strongpass123"})
    from app.database.session import SessionLocal

    db = SessionLocal()
    auth_service.request_otp(db, "otp-expired@example.com")
    challenge = db.query(OTPChallenge).filter_by(email="otp-expired@example.com").first()
    challenge.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    db.close()

    response = client.post(
        "/auth/otp/verify",
        json={"email": "otp-expired@example.com", "code": "000000"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired OTP"}


def test_otp_attempt_limit_blocks_later_correct_code(client: TestClient, monkeypatch):
    client.post("/auth/register", json={"email": "otp-lock@example.com", "username": "otp-lock", "password": "strongpass123"})
    monkeypatch.setattr(auth_service, "generate_otp_code", lambda: "123456")
    from app.database.session import SessionLocal

    db = SessionLocal()
    auth_service.request_otp(db, "otp-lock@example.com")
    for _ in range(5):
        with pytest.raises(HTTPException) as invalid_attempt:
            auth_service.verify_otp(db, "otp-lock@example.com", "000000")
        assert invalid_attempt.value.status_code == 401

    with pytest.raises(HTTPException) as locked_attempt:
        auth_service.verify_otp(db, "otp-lock@example.com", "123456")
    assert locked_attempt.value.status_code == 401
    assert locked_attempt.value.detail == "Invalid or expired OTP"
    challenge = db.query(OTPChallenge).filter_by(email="otp-lock@example.com").first()
    assert challenge.attempts == 5
    assert challenge.verified_at is None
    db.close()


def test_otp_login_rejects_inactive_user(client: TestClient, monkeypatch):
    client.post("/auth/register", json={"email": "disabled-otp@example.com", "username": "disabled-otp", "password": "strongpass123"})
    monkeypatch.setattr(auth_service, "generate_otp_code", lambda: "123456")
    from app.database.session import SessionLocal

    db = SessionLocal()
    user = db.query(User).filter_by(email="disabled-otp@example.com").first()
    auth_service.request_otp(db, user.email)
    user.is_active = False
    db.commit()

    with pytest.raises(HTTPException) as inactive:
        auth_service.verify_otp(db, user.email, "123456")
    assert inactive.value.status_code == 403
    db.close()


def test_oauth_login_rejects_inactive_linked_user(client: TestClient):
    client.post("/auth/register", json={"email": "disabled-oauth@example.com", "username": "disabled-oauth", "password": "strongpass123"})
    from app.database.session import SessionLocal

    db = SessionLocal()
    user = db.query(User).filter_by(email="disabled-oauth@example.com").first()
    user.is_active = False
    db.commit()

    with pytest.raises(HTTPException) as inactive:
        auth_service.handle_oauth_user(db, "google", "provider-user-123", user.email)
    assert inactive.value.status_code == 403
    assert db.query(OAuthIdentity).filter_by(user_id=user.id).count() == 0
    db.close()


def test_oauth_login_rejects_existing_link_for_inactive_user(client: TestClient):
    client.post("/auth/register", json={"email": "disabled-linked@example.com", "username": "disabled-linked", "password": "strongpass123"})
    from app.database.session import SessionLocal

    db = SessionLocal()
    user = db.query(User).filter_by(email="disabled-linked@example.com").first()
    db.add(OAuthIdentity(user_id=user.id, provider="google", provider_user_id="linked-disabled-user"))
    user.is_active = False
    db.commit()

    with pytest.raises(HTTPException) as inactive:
        auth_service.handle_oauth_user(db, "google", "linked-disabled-user", user.email)
    assert inactive.value.status_code == 403
    db.close()


def test_otp_request_does_not_disclose_unknown_email(client: TestClient):
    response = client.post("/auth/otp/request", json={"email": "unknown@example.com"})
    assert response.status_code == 200
    assert response.json() == {"message": "OTP sent."}


def test_otp_verification_does_not_disclose_account_existence(client: TestClient):
    unknown = client.post(
        "/auth/otp/verify",
        json={"email": "unknown@example.com", "code": "000000"},
    )
    client.post("/auth/register", json={"email": "otp@example.com", "username": "otp", "password": "strongpass123"})
    no_challenge = client.post(
        "/auth/otp/verify",
        json={"email": "otp@example.com", "code": "000000"},
    )
    assert unknown.status_code == no_challenge.status_code == 401
    assert unknown.json() == no_challenge.json() == {"detail": "Invalid or expired OTP"}


def test_reset_request_response_is_generic_when_smtp_fails(client: TestClient, monkeypatch):
    client.post("/auth/register", json={"email": "reset-mail@example.com", "username": "reset-mail", "password": "strongpass123"})
    monkeypatch.setattr(
        auth_service,
        "send_email",
        lambda *args, **kwargs: (_ for _ in ()).throw(EmailDeliveryError("SMTP unavailable")),
    )

    known = client.post("/auth/request-password-reset", json={"email": "reset-mail@example.com"})
    unknown = client.post("/auth/request-password-reset", json={"email": "unknown-reset@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json() == {
        "message": "If that account exists, a password reset link has been sent."
    }


def test_otp_request_response_is_generic_when_smtp_fails(client: TestClient, monkeypatch):
    client.post("/auth/register", json={"email": "otp-mail@example.com", "username": "otp-mail", "password": "strongpass123"})
    monkeypatch.setattr(
        auth_service,
        "send_email",
        lambda *args, **kwargs: (_ for _ in ()).throw(EmailDeliveryError("SMTP unavailable")),
    )

    known = client.post("/auth/otp/request", json={"email": "otp-mail@example.com"})
    unknown = client.post("/auth/otp/request", json={"email": "unknown-otp@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json() == {"message": "OTP sent."}


def test_oauth_state_validation(client: TestClient):
    bad = client.get("/auth/google/callback", params={"code": "abc"})
    assert bad.status_code == 400


def test_oauth_callback_rejects_state_mismatch_before_provider_request(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "google_client_id", "assessment-test-client")
    monkeypatch.setattr(settings, "google_client_secret", "assessment-test-secret")
    login = client.get("/auth/google/login")
    assert login.status_code == 200
    state = parse_qs(urlparse(login.json()["authorization_url"]).query)["state"][0]

    callback = client.get(
        "/auth/google/callback",
        params={"code": "not-a-real-code", "state": state + "-tampered"},
    )
    assert callback.status_code == 400
    assert callback.json() == {"detail": "OAuth state mismatch"}


@pytest.mark.parametrize(
    ("provider", "client_id", "client_secret"),
    [
        ("google", "your-google-client-id", "replace-with-your-google-client-secret"),
        ("google", "configured-client-id", "replace-with-your-google-client-secret"),
        ("github", "your-github-client-id", "replace-with-your-github-client-secret"),
    ],
)
def test_oauth_login_rejects_placeholder_credentials(client: TestClient, monkeypatch, provider, client_id, client_secret):
    monkeypatch.setattr(settings, f"{provider}_client_id", client_id)
    monkeypatch.setattr(settings, f"{provider}_client_secret", client_secret)

    response = client.get(f"/auth/{provider}/login")
    assert response.status_code == 400
    provider_name = {"google": "Google", "github": "GitHub"}[provider]
    assert response.json() == {"detail": f"{provider_name} OAuth is not configured"}


def test_unauthorized_access_to_another_user(client: TestClient):
    client.post("/auth/register", json={"email": "ivy@example.com", "username": "ivy", "password": "strongpass123"})
    client.post("/auth/register", json={"email": "jane@example.com", "username": "jane", "password": "strongpass123"})
    verify_registered_user(client, "ivy@example.com")
    verify_registered_user(client, "jane@example.com")
    login = client.post("/auth/login", json={"email": "ivy@example.com", "password": "strongpass123"})
    token = login.json()["access_token"]
    response = client.get("/auth/users/2", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_input_validation(client: TestClient):
    bad = client.post("/auth/register", json={"email": "bad-email", "username": "x", "password": "short"})
    assert bad.status_code == 422

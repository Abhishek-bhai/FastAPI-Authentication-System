from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from fastapi.testclient import TestClient
from jose import jwt

from app.core.config import Settings, settings
from app.core.security import verify_password
from app.models.user import OTPChallenge, PasswordResetToken, User
from app.services import auth_service


def test_secret_key_must_be_configured(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_registration_and_login(client: TestClient):
    response = client.post(
        "/auth/register",
        json={"email": "alice@example.com", "username": "alice", "password": "strongpass123"},
    )
    assert response.status_code == 201, response.text

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


def test_oauth2_form_login_and_protected_route(client: TestClient):
    client.post("/auth/register", json={"email": "oauth2@example.com", "username": "oauth2", "password": "strongpass123"})
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


def test_logout_revokes_refresh_token(client: TestClient):
    client.post("/auth/register", json={"email": "erin@example.com", "username": "erin", "password": "strongpass123"})
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


def test_email_verification_flow(client: TestClient):
    client.post("/auth/register", json={"email": "frank@example.com", "username": "frank", "password": "strongpass123"})
    from app.database.session import SessionLocal
    db = SessionLocal()
    user = db.query(User).filter_by(email="frank@example.com").first()
    token = auth_service.request_verification_token(db, user)
    db.close()

    verify = client.post("/auth/verify-email", json={"token": token})
    assert verify.status_code == 200, verify.text


def test_password_reset_flow(client: TestClient):
    client.post("/auth/register", json={"email": "gina@example.com", "username": "gina", "password": "strongpass123"})
    from app.database.session import SessionLocal
    db = SessionLocal()
    user = db.query(User).filter_by(email="gina@example.com").first()
    token = auth_service.request_password_reset(db, user.email)
    db.close()

    reset = client.post("/auth/reset-password", json={"token": token, "new_password": "newStrongPass123"})
    assert reset.status_code == 200, reset.text

    login = client.post("/auth/login", json={"email": "gina@example.com", "password": "strongpass123"})
    assert login.status_code == 401

    success = client.post("/auth/login", json={"email": "gina@example.com", "password": "newStrongPass123"})
    assert success.status_code == 200, success.text

    replay = client.post("/auth/reset-password", json={"token": token, "new_password": "anotherPass123"})
    assert replay.status_code == 400


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
    replay = client.post("/auth/otp/verify", json={"email": "henry@example.com", "code": code})
    assert replay.status_code == 401


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


def test_unauthorized_access_to_another_user(client: TestClient):
    client.post("/auth/register", json={"email": "ivy@example.com", "username": "ivy", "password": "strongpass123"})
    client.post("/auth/register", json={"email": "jane@example.com", "username": "jane", "password": "strongpass123"})
    login = client.post("/auth/login", json={"email": "ivy@example.com", "password": "strongpass123"})
    token = login.json()["access_token"]
    response = client.get("/auth/users/2", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_input_validation(client: TestClient):
    bad = client.post("/auth/register", json={"email": "bad-email", "username": "x", "password": "short"})
    assert bad.status_code == 422

from fastapi.testclient import TestClient

from app.core.security import verify_password
from app.models.user import User
from app.services import auth_service


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
    client.post("/auth/register", json={"email": "carol@example.com", "username": "carol", "password": "strongpass123"})
    login = client.post("/auth/login", json={"email": "carol@example.com", "password": "strongpass123"})
    access = login.json()["access_token"]

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert me.status_code == 200

    missing = client.get("/auth/me")
    assert missing.status_code == 401

    invalid = client.get("/auth/me", headers={"Authorization": "Bearer bad.token.here"})
    assert invalid.status_code == 401


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


def test_logout_revokes_refresh_token(client: TestClient):
    client.post("/auth/register", json={"email": "erin@example.com", "username": "erin", "password": "strongpass123"})
    login = client.post("/auth/login", json={"email": "erin@example.com", "password": "strongpass123"})
    tokens = login.json()
    access = tokens["access_token"]
    refresh = tokens["refresh_token"]

    logout = client.post("/auth/logout", json={"refresh_token": refresh}, headers={"Authorization": f"Bearer {access}"})
    assert logout.status_code == 200, logout.text

    reuse = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert reuse.status_code == 401


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


def test_otp_flow(client: TestClient):
    client.post("/auth/register", json={"email": "henry@example.com", "username": "henry", "password": "strongpass123"})
    from app.database.session import SessionLocal
    db = SessionLocal()
    code = auth_service.request_otp(db, "henry@example.com")
    db.close()
    verify = client.post("/auth/otp/verify", json={"email": "henry@example.com", "code": code})
    assert verify.status_code == 200, verify.text


def test_oauth_state_validation(client: TestClient):
    bad = client.get("/auth/google/callback", params={"code": "abc"})
    assert bad.status_code == 400


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

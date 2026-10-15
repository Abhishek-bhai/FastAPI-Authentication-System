import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, status
from jose import jwt as jose_jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import AuthError
from app.core.rate_limit import rate_limit
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_email_token,
    generate_otp_code,
    hash_password,
    hash_token_value,
    verify_password,
)
from app.models.user import OTPChallenge, OAuthIdentity, PasswordResetToken, RefreshToken, RevokedToken, User, UserVerificationToken
from app.services.email_service import send_email


def _ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email.lower()))


def _create_token_pair(db: Session, user: User) -> tuple[str, str]:
    access_jti = str(uuid.uuid4())
    refresh_jti = str(uuid.uuid4())
    access_token = create_access_token(str(user.id), access_jti)
    refresh_token = create_refresh_token(str(user.id), refresh_jti)
    family_id = str(uuid.uuid4())
    refresh_hash = hash_token_value(refresh_token)
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=refresh_hash,
            family_id=family_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days),
            revoked_at=None,
        )
    )
    db.commit()
    return access_token, refresh_token


def register_user(db: Session, payload: Any) -> User:
    email = payload.email.lower().strip()
    if _get_user_by_email(db, email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This email is already registered")
    user = User(
        email=email,
        username=payload.username,
        hashed_password=hash_password(payload.password),
        is_active=True,
        is_verified=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    request_verification_token(db, user)
    return user


def authenticate_user(db: Session, email: str, password: str) -> User:
    user = _get_user_by_email(db, email.lower())
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")
    return user


def login_user(db: Session, email: str, password: str) -> dict[str, str]:
    user = authenticate_user(db, email, password)
    access_token, refresh_token = _create_token_pair(db, user)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


def request_verification_token(db: Session, user: User) -> str:
    token = generate_email_token()
    token_hash = hash_token_value(token)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    db.add(
        UserVerificationToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
    )
    db.commit()

    email_body = (
        "Hello,\n\n"
        "Use the following token to verify your email address:\n\n"
        f"{token}\n\n"
        "Submit it to POST /auth/verify-email using JSON:\n"
        '{"token": "YOUR_VERIFICATION_TOKEN"}\n\n'
        "This token expires in 1 hour. "
        "If you did not create this account, ignore this email."
    )

    send_email("Verify your email", user.email, email_body)

    if settings.app_env == "test":
        return token

    return "Verification email sent."


def verify_email_token(db: Session, token: str) -> User:
    token_hash = hash_token_value(token)
    record = db.scalar(
        select(UserVerificationToken).where(UserVerificationToken.token_hash == token_hash)
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification token")
    expires_at = _ensure_utc(record.expires_at)
    if record.used_at is not None or expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification token is expired or already used")
    user = db.get(User, record.user_id)
    user.is_verified = True
    record.used_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    return user


def request_password_reset(db: Session, email: str) -> str:
    user = _get_user_by_email(db, email.lower().strip())

    if user is None:
        return "If that account exists, a password reset link has been sent."

    token = generate_email_token()

    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token_value(token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        )
    )
    db.commit()

    email_body = (
        "Hello,\n\n"
        "Use the following token to reset your password:\n\n"
        f"{token}\n\n"
        "Submit it to POST /auth/reset-password using JSON with "
        "the token and your new password:\n"
        '{"token": "YOUR_RESET_TOKEN", '
        '"new_password": "YOUR_NEW_PASSWORD"}\n\n'
        "This token expires in 15 minutes and can only be used once. "
        "If you did not request a password reset, ignore this email."
    )

    send_email("Password reset", user.email, email_body)

    if settings.app_env == "test":
        return token

    return "If that account exists, a password reset link has been sent."

def reset_password(db: Session, token: str, new_password: str) -> User:
    token_hash = hash_token_value(token)
    record = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash))
    if not record:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid password reset token")
    expires_at = _ensure_utc(record.expires_at)
    if record.used_at is not None or expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password reset token is expired or already used")
    user = db.get(User, record.user_id)
    user.hashed_password = hash_password(new_password)
    record.used_at = datetime.now(timezone.utc)
    db.query(RefreshToken).filter(RefreshToken.user_id == user.id).update({"revoked_at": datetime.now(timezone.utc)})
    db.commit()
    return user


def request_otp(db: Session, email: str) -> str:
    user = _get_user_by_email(db, email.lower().strip())

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    rate_limit(f"otp:{email}", settings.otp_rate_limit_per_minute)

    code = generate_otp_code()

    challenge = OTPChallenge(
        user_id=user.id,
        email=user.email,
        code_hash=hash_token_value(code),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        attempts=0,
    )

    db.add(challenge)
    db.commit()

    email_body = (
        "Hello,\n\n"
        f"Your one-time password (OTP) is: {code}\n\n"
        "This OTP expires in 5 minutes. "
        "Do not share it with anyone."
    )

    send_email("Your OTP code", user.email, email_body)

    if settings.app_env == "test":
        return code

    return "OTP sent."


def verify_otp(db: Session, email: str, code: str) -> dict[str, str]:
    user = _get_user_by_email(db, email.lower())
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    challenge = (
        db.query(OTPChallenge)
        .filter(OTPChallenge.user_id == user.id)
        .order_by(OTPChallenge.created_at.desc())
        .first()
    )
    if not challenge:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No OTP challenge found")
    if challenge.verified_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP already used")
    expires_at = _ensure_utc(challenge.expires_at)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP expired")
    if challenge.attempts >= 5:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP attempts exceeded")
    if hash_token_value(code) != challenge.code_hash:
        challenge.attempts += 1
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP code")
    challenge.verified_at = datetime.now(timezone.utc)
    user.is_verified = True
    db.commit()
    access_token, refresh_token = _create_token_pair(db, user)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


def get_authenticated_user(db: Session, token: str) -> User:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token type is invalid")
    user_id = int(payload.get("sub"))
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if payload.get("jti"):
        revoked = db.scalar(
            select(RevokedToken).where(
                RevokedToken.user_id == user.id,
                RevokedToken.token_type == "access",
                RevokedToken.token_jti == payload["jti"],
            )
        )
        if revoked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token has been revoked")
    return user


def generate_refresh_token_family() -> str:
    return str(uuid.uuid4())


def revoke_family_tokens(db: Session, user_id: int, family_id: str) -> None:
    db.query(RefreshToken).filter(RefreshToken.user_id == user_id, RefreshToken.family_id == family_id).update({"revoked_at": datetime.now(timezone.utc)})
    db.commit()


def rotate_refresh_token(db: Session, refresh_token_value: str) -> dict[str, str]:
    token_hash = hash_token_value(refresh_token_value)
    current = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    if not current:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found")
    if current.revoked_at is not None:
        revoke_family_tokens(db, current.user_id, current.family_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been revoked")
    expires_at = _ensure_utc(current.expires_at)
    if expires_at < datetime.now(timezone.utc):
        current.revoked_at = datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
    user = db.get(User, current.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    new_access = create_access_token(str(user.id), str(uuid.uuid4()))
    new_refresh = create_refresh_token(str(user.id), str(uuid.uuid4()))
    current.revoked_at = datetime.now(timezone.utc)
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hash_token_value(new_refresh),
            family_id=current.family_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    db.commit()
    return {"access_token": new_access, "refresh_token": new_refresh, "token_type": "bearer"}


def logout_user(db: Session, user: User, refresh_token_value: str | None, access_token_value: str | None) -> str:
    if refresh_token_value:
        refresh_hash = hash_token_value(refresh_token_value)
        refresh_record = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == refresh_hash))
        if refresh_record:
            refresh_record.revoked_at = datetime.now(timezone.utc)
            revoke_family_tokens(db, user.id, refresh_record.family_id)
    if access_token_value:
        payload = decode_token(access_token_value)
        token_jti = payload.get("jti")
        if token_jti:
            existing = db.scalar(
                select(RevokedToken).where(
                    RevokedToken.user_id == user.id,
                    RevokedToken.token_type == "access",
                    RevokedToken.token_jti == token_jti,
                )
            )
            if not existing:
                db.add(RevokedToken(user_id=user.id, token_type="access", token_jti=token_jti, reason="logout"))
    db.commit()
    return "Logged out successfully"


def link_oauth_identity(db: Session, user: User, provider: str, provider_user_id: str, email: str | None) -> User:
    match = db.scalar(
        select(OAuthIdentity).where(
            OAuthIdentity.provider == provider,
            OAuthIdentity.provider_user_id == provider_user_id,
        )
    )
    if match:
        if match.user_id != user.id:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This external identity is already linked to another account")
        return user
    db.add(
        OAuthIdentity(
            user_id=user.id,
            provider=provider,
            provider_user_id=provider_user_id,
            email=email,
        )
    )
    db.commit()
    return user


def handle_oauth_user(db: Session, provider: str, provider_user_id: str, email: str | None) -> tuple[User, dict[str, str]]:
    existing_identity = db.scalar(
        select(OAuthIdentity).where(
            OAuthIdentity.provider == provider,
            OAuthIdentity.provider_user_id == provider_user_id,
        )
    )
    if existing_identity:
        user = db.get(User, existing_identity.user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linked user not found")
    else:
        if email:
            user = _get_user_by_email(db, email.lower())
            if user is None:
                user = User(
                    email=email.lower(),
                    username=email.split("@")[0],
                    hashed_password=hash_password(secrets.token_urlsafe(32)),
                    is_active=True,
                    is_verified=True,
                )
                db.add(user)
                db.commit()
                db.refresh(user)
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No email available for OAuth user")
        db.add(
            OAuthIdentity(
                user_id=user.id,
                provider=provider,
                provider_user_id=provider_user_id,
                email=email,
            )
        )
        db.commit()
    access_token, refresh_token = _create_token_pair(db, user)
    return user, {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

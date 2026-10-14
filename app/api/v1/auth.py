from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_current_user
from app.core.config import settings
from app.core.rate_limit import rate_limit
from app.database.session import get_db
from app.models.user import User
from app.schemas.auth import (
    EmailVerificationRequest,
    LoginRequest,
    MessageResponse,
    OTPRequest,
    OTPVerifyRequest,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    ProfileResponse,
    RefreshRequest,
    TokenPair,
    UserCreate,
    UserRead,
)
from app.services import auth_service, oauth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserCreate, request: Request, db: Session = Depends(get_db)) -> User:
    rate_limit(f"register:{request.client.host if request.client else 'unknown'}", settings.rate_limit_per_minute)
    return auth_service.register_user(db, payload)


@router.post("/login", response_model=TokenPair)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    rate_limit(f"login:{request.client.host if request.client else 'unknown'}", settings.rate_limit_per_minute)
    return auth_service.login_user(db, payload.email, payload.password)


@router.post("/refresh", response_model=TokenPair)
def refresh_token(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    rate_limit(f"refresh:{request.client.host if request.client else 'unknown'}", settings.rate_limit_per_minute)
    return auth_service.rotate_refresh_token(db, payload.refresh_token)


@router.post("/logout", response_model=MessageResponse)
def logout(
    payload: RefreshRequest | None = None,
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> dict[str, str]:
    refresh_token = payload.refresh_token if payload else None
    access_value = request.headers.get("Authorization", "").replace("Bearer ", "", 1).strip() if request else None
    message = auth_service.logout_user(db, current_user, refresh_token, access_value)
    return {"message": message}


@router.get("/me", response_model=ProfileResponse)
def me(current_user: User = Depends(get_current_active_user)) -> User:
    return current_user


@router.get("/users/{user_id}", response_model=ProfileResponse)
def get_user_profile(user_id: int, current_user: User = Depends(get_current_active_user)) -> User:
    if user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You cannot access another user's data")
    return current_user


@router.get("/premium")
def premium(current_user: User = Depends(get_current_active_user)) -> dict[str, Any]:
    return {"message": "Premium content unlocked", "user_id": current_user.id, "email": current_user.email}


@router.post("/request-verification", response_model=MessageResponse)
def request_verification(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)) -> dict[str, str]:
    auth_service.request_verification_token(db, current_user)
    return {"message": "Verification email sent."}


@router.post("/verify-email", response_model=MessageResponse)
def verify_email(payload: EmailVerificationRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    auth_service.verify_email_token(db, payload.token)
    return {"message": "Email verified successfully"}


@router.post("/request-password-reset", response_model=MessageResponse)
def request_password_reset(payload: PasswordResetRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    auth_service.request_password_reset(db, payload.email)
    return {"message": "If that account exists, a password reset link has been sent."}


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(payload: PasswordResetConfirmRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    auth_service.reset_password(db, payload.token, payload.new_password)
    return {"message": "Password reset successfully"}


@router.post("/otp/request", response_model=MessageResponse)
def request_otp(payload: OTPRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    rate_limit(f"otp_request:{request.client.host if request.client else 'unknown'}", settings.otp_rate_limit_per_minute)
    auth_service.request_otp(db, payload.email)
    return {"message": "OTP sent."}


@router.post("/otp/verify", response_model=TokenPair)
def verify_otp(payload: OTPVerifyRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    rate_limit(f"otp_verify:{request.client.host if request.client else 'unknown'}", settings.otp_rate_limit_per_minute)
    return auth_service.verify_otp(db, payload.email, payload.code)


@router.get("/google/login")
def google_login() -> dict[str, str]:
    return {"authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=placeholder&redirect_uri=http://localhost:8000/auth/google/callback&response_type=code&scope=openid+email+profile&state=google-state"}


@router.get("/google/callback")
async def google_callback(code: str | None = None, state: str | None = None, db: Session = Depends(get_db)) -> dict[str, str]:
    if not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing OAuth code")
    if not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing OAuth state")
    user_info = await oauth_service.get_google_user(code, state)
    _, tokens = auth_service.handle_oauth_user(db, user_info["provider"], user_info["provider_user_id"], user_info.get("email"))
    return tokens


@router.get("/github/login")
def github_login() -> dict[str, str]:
    return {"authorization_url": "https://github.com/login/oauth/authorize?client_id=placeholder&redirect_uri=http://localhost:8000/auth/github/callback&scope=user:email&state=github-state"}


@router.get("/github/callback")
async def github_callback(code: str | None = None, state: str | None = None, db: Session = Depends(get_db)) -> dict[str, str]:
    if not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing OAuth code")
    if not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing OAuth state")
    user_info = await oauth_service.get_github_user(code, state)
    _, tokens = auth_service.handle_oauth_user(db, user_info["provider"], user_info["provider_user_id"], user_info.get("email"))
    return tokens

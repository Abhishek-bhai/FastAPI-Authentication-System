import hashlib
import hmac
import secrets
import time
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_current_user
from app.core.config import settings
from app.core.rate_limit import rate_limit
from app.database.session import get_db
from app.models.user import User
from app.schemas.auth import (
    EmailVerificationRequest, LoginRequest, MessageResponse, OTPRequest,
    OTPVerifyRequest, PasswordResetConfirmRequest, PasswordResetRequest,
    ProfileResponse, RefreshRequest, TokenPair, UserCreate, UserRead,
)
from app.services import auth_service, oauth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])
OAUTH_STATE_TTL_SECONDS = 600


def _oauth_state_signature(provider: str, state: str, issued_at: int) -> str:
    message = f"{provider}:{state}:{issued_at}".encode()
    return hmac.new(settings.secret_key.encode(), message, hashlib.sha256).hexdigest()


def _new_oauth_state(provider: str) -> tuple[str, str]:
    state = secrets.token_urlsafe(32)
    issued_at = int(time.time())
    cookie_value = f"{issued_at}.{_oauth_state_signature(provider, state, issued_at)}"
    return state, cookie_value


def _validate_oauth_state(provider: str, state: str | None, cookie_value: str | None) -> None:
    if not state or not cookie_value:
        raise HTTPException(status_code=400, detail="Missing or invalid OAuth state")
    try:
        issued_text, signature = cookie_value.split(".", 1)
        issued_at = int(issued_text)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid OAuth state")
    age = int(time.time()) - issued_at
    if age < 0 or age > OAUTH_STATE_TTL_SECONDS:
        raise HTTPException(status_code=400, detail="OAuth state expired")
    expected = _oauth_state_signature(provider, state, issued_at)
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=400, detail="OAuth state mismatch")


def _oauth_credentials_ready(provider: str) -> bool:
    client_id = getattr(settings, f"{provider}_client_id")
    client_secret = getattr(settings, f"{provider}_client_secret")
    placeholders = {
        "google": {"google-client-id", "your-google-client-id"},
        "github": {"github-client-id", "your-github-client-id"},
    }
    return bool(client_id and client_secret and client_id not in placeholders[provider]
                and client_secret not in {f"{provider}-client-secret", f"your-{provider}-client-secret"})


def _set_oauth_cookie(response: Response, provider: str, value: str) -> None:
    response.set_cookie(
        key=f"oauth_state_{provider}", value=value, max_age=OAUTH_STATE_TTL_SECONDS,
        httponly=True, secure=not settings.debug, samesite="lax",
        path=f"/auth/{provider}/callback",
    )


def _clear_oauth_cookie(response: Response, provider: str) -> None:
    response.delete_cookie(
        key=f"oauth_state_{provider}", httponly=True, secure=not settings.debug,
        samesite="lax", path=f"/auth/{provider}/callback",
    )


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserCreate, request: Request, db: Session = Depends(get_db)) -> User:
    rate_limit(f"register:{request.client.host if request.client else 'unknown'}", settings.rate_limit_per_minute)
    return auth_service.register_user(db, payload)


@router.post("/login", response_model=TokenPair)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    rate_limit(f"login:{request.client.host if request.client else 'unknown'}", settings.rate_limit_per_minute)
    return auth_service.login_user(db, payload.email, payload.password)


@router.post("/token", response_model=TokenPair)
def issue_oauth2_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    rate_limit(f"login:{request.client.host if request.client else 'unknown'}", settings.rate_limit_per_minute)
    return auth_service.login_user(db, form_data.username, form_data.password)


@router.post("/refresh", response_model=TokenPair)
def refresh_token(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    rate_limit(f"refresh:{request.client.host if request.client else 'unknown'}", settings.rate_limit_per_minute)
    return auth_service.rotate_refresh_token(db, payload.refresh_token)


@router.post("/logout", response_model=MessageResponse)
def logout(payload: RefreshRequest | None = None, request: Request = None, db: Session = Depends(get_db),
           current_user: User = Depends(get_current_active_user)) -> dict[str, str]:
    refresh_token = payload.refresh_token if payload else None
    access_value = request.headers.get("Authorization", "").replace("Bearer ", "", 1).strip() if request else None
    return {"message": auth_service.logout_user(db, current_user, refresh_token, access_value)}


@router.get("/me", response_model=ProfileResponse)
def me(current_user: User = Depends(get_current_active_user)) -> User:
    return current_user


@router.get("/users/{user_id}", response_model=ProfileResponse)
def get_user_profile(user_id: int, current_user: User = Depends(get_current_active_user)) -> User:
    if user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You cannot access another user's data")
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
def google_login(response: Response) -> dict[str, str]:
    if not _oauth_credentials_ready("google"):
        raise HTTPException(status_code=400, detail="Google OAuth is not configured")
    state, cookie = _new_oauth_state("google")
    _set_oauth_cookie(response, "google", cookie)
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.google_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
    }
    return {"authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)}


@router.get("/google/callback")
async def google_callback(request: Request, response: Response, code: str | None = None,
                          state: str | None = None, db: Session = Depends(get_db)) -> dict[str, str]:
    if not code:
        raise HTTPException(status_code=400, detail="Missing OAuth code")
    _validate_oauth_state("google", state, request.cookies.get("oauth_state_google"))
    _clear_oauth_cookie(response, "google")
    user_info = await oauth_service.get_google_user(code, state)
    _, tokens = auth_service.handle_oauth_user(db, user_info["provider"], user_info["provider_user_id"], user_info.get("email"))
    return tokens


@router.get("/github/login")
def github_login(response: Response) -> dict[str, str]:
    if not _oauth_credentials_ready("github"):
        raise HTTPException(status_code=400, detail="GitHub OAuth is not configured")
    state, cookie = _new_oauth_state("github")
    _set_oauth_cookie(response, "github", cookie)
    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": settings.github_redirect_uri,
        "scope": "read:user user:email",
        "state": state,
    }
    return {"authorization_url": "https://github.com/login/oauth/authorize?" + urlencode(params)}


@router.get("/github/callback")
async def github_callback(request: Request, response: Response, code: str | None = None,
                          state: str | None = None, db: Session = Depends(get_db)) -> dict[str, str]:
    if not code:
        raise HTTPException(status_code=400, detail="Missing OAuth code")
    _validate_oauth_state("github", state, request.cookies.get("oauth_state_github"))
    _clear_oauth_cookie(response, "github")
    user_info = await oauth_service.get_github_user(code, state)
    _, tokens = auth_service.handle_oauth_user(db, user_info["provider"], user_info["provider_user_id"], user_info.get("email"))
    return tokens

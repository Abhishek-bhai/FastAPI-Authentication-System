from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class UserCreate(BaseModel):
    email: EmailStr
    username: str | None = Field(default=None, max_length=100)
    password: str = Field(..., min_length=8, max_length=1024)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., max_length=1024)


class RefreshRequest(BaseModel):
    refresh_token: str


class UserRead(BaseModel):
    id: int
    email: EmailStr
    username: str | None = None
    is_active: bool
    is_verified: bool

    model_config = ConfigDict(from_attributes=True)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class EmailVerificationRequest(BaseModel):
    token: str


class VerificationEmailRequest(BaseModel):
    email: EmailStr


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=1024)


class OTPRequest(BaseModel):
    email: EmailStr


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=6, max_length=6)


class OAuthCallbackRequest(BaseModel):
    code: str
    state: str | None = None


class OAuthIdentityPayload(BaseModel):
    provider: str
    provider_user_id: str
    email: str | None = None


class MessageResponse(BaseModel):
    message: str


class ProfileResponse(BaseModel):
    id: int
    email: EmailStr
    username: str | None = None
    is_verified: bool
    created_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)

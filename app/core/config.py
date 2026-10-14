from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "FastAPI Authentication System"
    app_env: str = "development"
    debug: bool = True
    database_url: str = "sqlite:///./app.db"
    secret_key: str = "dev-secret-key-change-me"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    smtp_host: str = "smtp.example.com"
    smtp_port: int = 587
    smtp_username: str = "user@example.com"
    smtp_password: str = "password"
    smtp_from: str = "noreply@example.com"
    google_client_id: str = "google-client-id"
    google_client_secret: str = "google-client-secret"
    google_redirect_uri: str = "http://localhost:8000/auth/google/callback"
    github_client_id: str = "github-client-id"
    github_client_secret: str = "github-client-secret"
    github_redirect_uri: str = "http://localhost:8000/auth/github/callback"
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    rate_limit_per_minute: int = 60
    otp_rate_limit_per_minute: int = 5

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_production_security(self):
        env_name = (self.app_env or "").strip().lower()
        is_production = env_name in {"production", "prod"}

        if not is_production:
            return self

        if self.debug:
            raise ValueError("DEBUG must be false in production.")

        insecure_secret_values = {
            "",
            "dev-secret-key-change-me",
            "changeme",
            "change-me",
            "replace-with-a-long-random-secret",
        }
        if self.secret_key in insecure_secret_values or len(self.secret_key) < 32:
            raise ValueError("A strong SECRET_KEY is required in production.")

        insecure_email_values = {"", "user@example.com", "your-email@example.com"}
        if (
            self.smtp_host in {"", "smtp.example.com"}
            or self.smtp_username in insecure_email_values
            or self.smtp_password in {"", "password", "your-password"}
        ):
            raise ValueError("SMTP credentials must be configured for production.")

        insecure_oauth_values = {"", "google-client-id", "your-google-client-id", "github-client-id", "your-github-client-id"}
        if (
            self.google_client_id in insecure_oauth_values
            or self.google_client_secret in {"", "google-client-secret", "your-google-client-secret"}
            or self.github_client_id in insecure_oauth_values
            or self.github_client_secret in {"", "github-client-secret", "your-github-client-secret"}
        ):
            raise ValueError("Google and GitHub OAuth client credentials must be configured for production.")

        return self


settings = Settings()

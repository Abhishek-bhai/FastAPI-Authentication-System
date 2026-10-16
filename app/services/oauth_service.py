from typing import Any

import httpx
from fastapi import HTTPException
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

from app.core.config import settings


def credentials_ready(provider: str) -> bool:
    if provider not in {"google", "github"}:
        raise ValueError(f"Unsupported OAuth provider: {provider}")

    client_id = getattr(settings, f"{provider}_client_id", "").strip()
    client_secret = getattr(settings, f"{provider}_client_secret", "").strip()
    placeholders = {
        "google": {
            "client_ids": {"google-client-id", "your-google-client-id"},
            "client_secrets": {
                "google-client-secret",
                "your-google-client-secret",
                "replace-with-your-google-client-secret",
            },
        },
        "github": {
            "client_ids": {"github-client-id", "your-github-client-id"},
            "client_secrets": {
                "github-client-secret",
                "your-github-client-secret",
                "replace-with-your-github-client-secret",
            },
        },
    }[provider]
    return bool(
        client_id
        and client_secret
        and client_id.lower() not in placeholders["client_ids"]
        and client_secret.lower() not in placeholders["client_secrets"]
    )


async def get_google_user(code: str, state: str | None = None) -> dict[str, Any]:
    if not credentials_ready("google"):
        raise HTTPException(status_code=400, detail="Google OAuth is not configured")
    if not state:
        raise HTTPException(status_code=400, detail="Missing OAuth state")

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "redirect_uri": settings.google_redirect_uri,
                    "grant_type": "authorization_code",
                },
            )
            response.raise_for_status()
            token_data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="Google OAuth provider request failed") from exc

    encoded_token = token_data.get("id_token")
    if not encoded_token:
        raise HTTPException(status_code=400, detail="Google token exchange failed")
    try:
        claims = id_token.verify_oauth2_token(
            encoded_token, google_requests.Request(), settings.google_client_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Google identity token could not be verified") from exc

    email, subject = claims.get("email"), claims.get("sub")
    if not email or not subject or claims.get("email_verified") is not True:
        raise HTTPException(status_code=401, detail="Google account must have a verified email")
    return {"provider_user_id": str(subject), "email": email.lower(), "provider": "google"}


async def get_github_user(code: str, state: str | None = None) -> dict[str, Any]:
    if not credentials_ready("github"):
        raise HTTPException(status_code=400, detail="GitHub OAuth is not configured")
    if not state:
        raise HTTPException(status_code=400, detail="Missing OAuth state")

    headers = {"Accept": "application/json", "X-GitHub-Api-Version": "2022-11-28"}
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            token_response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret,
                    "code": code,
                    "redirect_uri": settings.github_redirect_uri,
                },
                headers=headers,
            )
            token_response.raise_for_status()
            access_token = token_response.json().get("access_token")
            if not access_token:
                raise HTTPException(status_code=400, detail="GitHub token exchange failed")

            auth_headers = {**headers, "Authorization": f"Bearer {access_token}"}
            profile_response = await client.get("https://api.github.com/user", headers=auth_headers)
            profile_response.raise_for_status()
            profile = profile_response.json()
            emails_response = await client.get("https://api.github.com/user/emails", headers=auth_headers)
            emails_response.raise_for_status()
            emails = emails_response.json() or []
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="GitHub OAuth provider request failed") from exc

    primary = next(
        (item for item in emails if item.get("primary") and item.get("verified") and item.get("email")),
        None,
    )
    if not profile.get("id") or not primary:
        raise HTTPException(status_code=401, detail="GitHub account must have a verified primary email")
    return {"provider_user_id": str(profile["id"]), "email": primary["email"].lower(), "provider": "github"}

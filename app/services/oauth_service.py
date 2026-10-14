import base64
import json
from typing import Any

import httpx
from fastapi import HTTPException, status

from app.core.config import settings


def _decode_jwt_payload_without_verify(token: str) -> dict[str, Any]:
    part = token.split(".")[1]
    padded = part + "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode()))


async def get_google_user(code: str, state: str | None = None) -> dict[str, Any]:
    if not settings.google_client_id or settings.google_client_id == "google-client-id":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Google OAuth is not configured")
    if not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing OAuth state")

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": settings.google_client_id,
        "client_secret": settings.google_client_secret,
        "redirect_uri": settings.google_redirect_uri,
        "grant_type": "authorization_code",
    }
    async with httpx.AsyncClient(timeout=20) as client:
        token_response = await client.post(token_url, data=data)
        token_response.raise_for_status()
        token_data = token_response.json()
        id_token = token_data.get("id_token")
        if not id_token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Google token exchange failed")
        payload = _decode_jwt_payload_without_verify(id_token)
    email = payload.get("email")
    sub = payload.get("sub") or payload.get("user_id")
    if not email or not sub:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Google identity did not include required claims")
    return {"provider_user_id": str(sub), "email": email, "provider": "google"}


async def get_github_user(code: str, state: str | None = None) -> dict[str, Any]:
    if not settings.github_client_id or settings.github_client_id == "github-client-id":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="GitHub OAuth is not configured")
    if not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing OAuth state")
    async with httpx.AsyncClient(timeout=20) as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": settings.github_redirect_uri,
            },
            headers={"Accept": "application/json"},
        )
        token_response.raise_for_status()
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="GitHub token exchange failed")
        user_response = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
        )
        user_response.raise_for_status()
        profile = user_response.json()
        email = profile.get("email")
        if not email:
            emails_response = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
            )
            emails_response.raise_for_status()
            emails = emails_response.json() or []
            primary = next((item for item in emails if item.get("primary") and item.get("verified")), None)
            email = primary.get("email") if primary else None
        if not profile.get("id"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="GitHub identity did not include required claims")
        return {"provider_user_id": str(profile["id"]), "email": email, "provider": "github"}

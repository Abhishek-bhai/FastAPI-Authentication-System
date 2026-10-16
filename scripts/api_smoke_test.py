"""Smoke-test login, protected endpoints, logout, and token revocation.

Run against a locally running API using an existing account. The password is
prompted interactively, and issued token values are kept in memory only.
"""

import argparse
from getpass import getpass

import httpx


def require_status(response: httpx.Response, expected: int, operation: str) -> None:
    if response.status_code != expected:
        raise SystemExit(f"{operation} failed (HTTP {response.status_code}; expected {expected})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--email", required=True)
    args = parser.parse_args()
    password = getpass("Account password: ")

    try:
        with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=10) as client:
            login = client.post("/auth/login", json={"email": args.email, "password": password})
            require_status(login, 200, "Login")
            tokens = login.json()
            access_token = tokens.get("access_token")
            refresh_token = tokens.get("refresh_token")
            if not access_token or not refresh_token:
                raise SystemExit("Login response did not contain the expected tokens")
            headers = {"Authorization": f"Bearer {access_token}"}
            require_status(client.get("/auth/me", headers=headers), 200, "Protected profile")
            require_status(client.get("/auth/premium", headers=headers), 200, "Protected premium endpoint")
            require_status(
                client.post("/auth/logout", json={"refresh_token": refresh_token}, headers=headers),
                200,
                "Logout",
            )
            require_status(
                client.post("/auth/refresh", json={"refresh_token": refresh_token}),
                401,
                "Refresh-token revocation check",
            )
            require_status(
                client.get("/auth/me", headers=headers),
                401,
                "Access-token revocation check",
            )
    except httpx.RequestError as exc:
        raise SystemExit(f"Could not contact the API at {args.base_url}: {exc}") from exc

    print("API smoke test passed: login, protected routes, logout, and revocation.")


if __name__ == "__main__":
    main()

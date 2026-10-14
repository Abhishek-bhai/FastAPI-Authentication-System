import time
from threading import Lock

from fastapi import HTTPException, status

_rate_buckets: dict[str, list[float]] = {}
_lock = Lock()


def rate_limit(key: str, limit: int, window_seconds: int = 60) -> None:
    now = time.monotonic()
    window_start = now - window_seconds
    with _lock:
        entries = _rate_buckets.setdefault(key, [])
        entries[:] = [ts for ts in entries if ts > window_start]
        if len(entries) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )
        entries.append(now)

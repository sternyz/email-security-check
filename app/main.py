"""FastAPI wrapper for the Email Security Checker. See docs/requirements.md §2-3.

Input (work email) -> results, rate limited per client IP (app/rate_limit.py).
Lead capture/CRM delivery is Tier 3 (see CLAUDE.md) and isn't wired up yet.
"""

import math
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr

from app.rate_limit import MAX_CONCURRENT_CHECKS, PER_IP_LIMITS, RateLimiter
from checks.runner import compute_verdict, run_all_checks

app = FastAPI(title="Email Security Checker")

_STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

limiter = RateLimiter(PER_IP_LIMITS)
check_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CHECKS)

RATE_LIMITED_MESSAGE = "You've run a lot of checks in a short time. Give it a few minutes and try again."
BUSY_MESSAGE = "We're running a lot of checks right now. Try again in a few seconds."


class CheckRequest(BaseModel):
    email: EmailStr


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")


@app.post("/api/check")
def check_email(payload: CheckRequest, request: Request) -> dict:
    # Slot first, so a "busy" rejection doesn't use up the visitor's quota.
    if not check_slots.acquire(blocking=False):
        raise HTTPException(
            status_code=503,
            detail=BUSY_MESSAGE,
            headers={"Retry-After": "5"},
        )
    try:
        # Behind Caddy, uvicorn's --proxy-headers makes this the visitor's IP.
        client_ip = request.client.host if request.client else "unknown"
        retry_after = limiter.hit(client_ip)
        if retry_after is not None:
            raise HTTPException(
                status_code=429,
                detail=RATE_LIMITED_MESSAGE,
                headers={"Retry-After": str(math.ceil(retry_after))},
            )

        domain = payload.email.split("@", 1)[1]
        results = run_all_checks(domain)
    finally:
        check_slots.release()

    verdict = compute_verdict(results)
    return {"domain": domain, "results": results, "verdict": verdict}

"""FastAPI wrapper for the Email Security Checker. See docs/requirements.md §2-3.

Input (work email) -> results, rate limited per client IP (app/rate_limit.py).
Every check records the email as a Growably lead, and the two CTA buttons add
their own tags (app/leads.py).
"""

import logging
import math
import re
import threading
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, field_validator

from app import leads
from app.rate_limit import LEAD_LIMITS, MAX_CONCURRENT_CHECKS, PER_IP_LIMITS, RateLimiter
from checks.runner import compute_verdict, run_all_checks

# Our own loggers (emailcheck.*) at INFO, so lead deliveries show in journalctl.
logging.basicConfig(level=logging.WARNING, format="%(levelname)s:     %(name)s: %(message)s")
logging.getLogger("emailcheck").setLevel(logging.INFO)

app = FastAPI(title="Email Security Checker")

_STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

limiter = RateLimiter(PER_IP_LIMITS)
lead_limiter = RateLimiter(LEAD_LIMITS)
check_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CHECKS)

RATE_LIMITED_MESSAGE = "You've run a lot of checks in a short time. Give it a few minutes and try again."
BUSY_MESSAGE = "We're running a lot of checks right now. Try again in a few seconds."
LEAD_RATE_LIMITED_MESSAGE = "That's a lot of requests in a short time. Give it a few minutes and try again."
LEAD_FAILED_MESSAGE = "Something went wrong on our end. Please try again in a minute."

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(value: str) -> str:
    """Accepts a bare domain or a URL (e.g. a CRM 'website' merge field)."""
    domain = value.strip().lower()
    domain = re.sub(r"^[a-z]+://", "", domain).split("/", 1)[0].removeprefix("www.")
    if not _DOMAIN_RE.match(domain):
        raise ValueError("not a valid domain")
    return domain


class CheckRequest(BaseModel):
    email: EmailStr


class DomainRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def _valid_domain(cls, value: str) -> str:
        return normalize_domain(value)


class ReportRequest(BaseModel):
    email: EmailStr


class WalkthroughRequest(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=100)
    phone: str | None = Field(default=None, max_length=40, pattern=r"^[0-9+()\-.\s]*$")

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("name is required")
        return value

    @field_validator("phone")
    @classmethod
    def _blank_phone_is_none(cls, value: str | None) -> str | None:
        return value.strip() or None if value else None


def _client_ip(request: Request) -> str:
    # Behind Caddy, uvicorn's --proxy-headers makes this the visitor's IP.
    return request.client.host if request.client else "unknown"


def _domain_of(email: str) -> str:
    return email.split("@", 1)[1].lower()


def _run_checks(domain: str, request: Request) -> dict:
    # Slot first, so a "busy" rejection doesn't use up the visitor's quota.
    if not check_slots.acquire(blocking=False):
        raise HTTPException(status_code=503, detail=BUSY_MESSAGE, headers={"Retry-After": "5"})
    try:
        retry_after = limiter.hit(_client_ip(request))
        if retry_after is not None:
            raise HTTPException(
                status_code=429,
                detail=RATE_LIMITED_MESSAGE,
                headers={"Retry-After": str(math.ceil(retry_after))},
            )
        results = run_all_checks(domain)
    finally:
        check_slots.release()

    return {"domain": domain, "results": results, "verdict": compute_verdict(results)}


def _check_lead_quota(request: Request) -> None:
    retry_after = lead_limiter.hit(_client_ip(request))
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail=LEAD_RATE_LIMITED_MESSAGE,
            headers={"Retry-After": str(math.ceil(retry_after))},
        )


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")


@app.post("/api/check")
def check_email(payload: CheckRequest, request: Request, background: BackgroundTasks) -> dict:
    domain = _domain_of(payload.email)
    body = _run_checks(domain, request)
    # After the response is sent, so a slow CRM never delays the results.
    background.add_task(leads.record_check, payload.email, domain, body["verdict"], body["results"])
    return body


@app.post("/api/check-domain")
def check_domain(payload: DomainRequest, request: Request) -> dict:
    """Re-runs a report from its link (/?d=domain), e.g. from the report email.
    No email involved, so nothing is sent to the CRM."""
    return _run_checks(payload.domain, request)


@app.post("/api/lead/report")
def request_report(payload: ReportRequest, request: Request) -> dict:
    _check_lead_quota(request)
    lead = leads.Lead(email=payload.email, domain=_domain_of(payload.email), tags=[leads.TAG_REPORT])
    if not leads.send_lead(lead):
        raise HTTPException(status_code=502, detail=LEAD_FAILED_MESSAGE)
    return {"ok": True}


@app.post("/api/lead/walkthrough")
def request_walkthrough(payload: WalkthroughRequest, request: Request) -> dict:
    _check_lead_quota(request)
    lead = leads.Lead(
        email=payload.email,
        domain=_domain_of(payload.email),
        tags=[leads.TAG_WALKTHROUGH],
        name=payload.name,
        phone=payload.phone,
    )
    if not leads.send_lead(lead):
        raise HTTPException(status_code=502, detail=LEAD_FAILED_MESSAGE)
    return {"ok": True}

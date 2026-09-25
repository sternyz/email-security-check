"""FastAPI wrapper for the Email Security Checker. See docs/requirements.md §2-3.

Tier 2 only: input (work email) -> results. Lead capture/CRM delivery and
rate limiting are Tier 3 (see CLAUDE.md) and aren't wired up here yet.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr

from checks.runner import compute_verdict, run_all_checks

app = FastAPI(title="Email Security Checker")

_STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


class CheckRequest(BaseModel):
    email: EmailStr


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")


@app.post("/api/check")
def check_email(payload: CheckRequest) -> dict:
    domain = payload.email.split("@", 1)[1]
    results = run_all_checks(domain)
    verdict = compute_verdict(results)
    return {"domain": domain, "results": results, "verdict": verdict}

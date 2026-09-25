"""Lead delivery to Growably CRM. See CLAUDE.md "Integration points".

Growably is a white-labeled HighLevel (LeadConnector) account, so delivery
uses the HighLevel API v2. Everything goes through send_lead(); the transport
is picked at startup from the environment:

- GROWABLY_TOKEN + GROWABLY_LOCATION_ID set: HighLevel API (a sub-account
  Private Integration token with contacts read/write).
- otherwise: a log-only stub, so local dev and tests never touch the CRM.

Growably workflows key off the tags (see TAG_* below) to send the report
email and notify the team — the app only records the lead.

HighLevelTransport follows the public v2 docs but has NOT been verified
against a live Growably account yet (no token at time of writing). Confirm
the request shapes the first time it runs for real.
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Protocol

import httpx

logger = logging.getLogger("emailcheck.leads")

TAG_CHECKED = "email-checker"
TAG_REPORT = "checker-report-requested"
TAG_WALKTHROUGH = "checker-walkthrough-requested"

LEAD_SOURCE = "Email Security Checker"
REPORT_URL = "https://dmarc.factoryinfo.tech/?d={domain}"


@dataclass
class Lead:
    email: str
    domain: str
    tags: list[str]
    name: str | None = None
    phone: str | None = None
    # Plain-text results summary, attached to the contact as a note.
    note: str | None = None
    extra: dict = field(default_factory=dict)


class Transport(Protocol):
    def send(self, lead: Lead) -> None: ...


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}"


class LogTransport:
    """Stand-in until Growably credentials are configured."""

    def __init__(self) -> None:
        self.sent: list[Lead] = []

    def send(self, lead: Lead) -> None:
        self.sent.append(lead)
        logger.info("lead (stub, not sent): %s tags=%s", mask_email(lead.email), lead.tags)


class HighLevelTransport:
    BASE_URL = "https://services.leadconnectorhq.com"
    API_VERSION = "2021-07-28"

    def __init__(self, token: str, location_id: str, client: httpx.Client | None = None) -> None:
        self._location_id = location_id
        self._client = client or httpx.Client(
            base_url=self.BASE_URL,
            timeout=10.0,
            headers={
                "Authorization": f"Bearer {token}",
                "Version": self.API_VERSION,
                "Accept": "application/json",
            },
        )

    def send(self, lead: Lead) -> None:
        contact = {
            "locationId": self._location_id,
            "email": lead.email,
            # The prospect's work-email domain is their company site; it also
            # lets a Growably email template build the report link.
            "website": f"https://{lead.domain}",
            "source": LEAD_SOURCE,
        }
        if lead.name:
            contact["name"] = lead.name
        if lead.phone:
            contact["phone"] = lead.phone

        # Upsert dedupes on email. Tags go through the add-tags endpoint,
        # since tags sent on an update can replace the contact's existing ones.
        response = self._client.post("/contacts/upsert", json=contact)
        response.raise_for_status()
        contact_id = response.json()["contact"]["id"]

        if lead.tags:
            self._client.post(f"/contacts/{contact_id}/tags", json={"tags": lead.tags}).raise_for_status()
        if lead.note:
            self._client.post(f"/contacts/{contact_id}/notes", json={"body": lead.note}).raise_for_status()


def _transport_from_env() -> Transport:
    token = os.environ.get("GROWABLY_TOKEN")
    location_id = os.environ.get("GROWABLY_LOCATION_ID")
    if token and location_id:
        return HighLevelTransport(token, location_id)
    return LogTransport()


transport: Transport = _transport_from_env()


def send_lead(lead: Lead) -> bool:
    """Deliver a lead; returns whether it succeeded. Never raises: a CRM
    outage mustn't break the checker for the visitor, so failures are logged
    (without the full email) instead."""
    try:
        transport.send(lead)
        return True
    except Exception:
        logger.exception("lead delivery failed for %s tags=%s", mask_email(lead.email), lead.tags)
        return False


def results_note(domain: str, verdict: dict, results: list[dict]) -> str:
    lines = [
        f"Email Security Checker results for {domain}",
        verdict["message"],
        "",
        *(f"{r['label']}: {r['status']}" for r in results),
        "",
        f"Report: {REPORT_URL.format(domain=domain)}",
    ]
    return "\n".join(lines)


def record_check(email: str, domain: str, verdict: dict, results: list[dict]) -> None:
    """Background task for /api/check. Builds the note here, inside the
    try, so nothing about lead capture can fail the visitor's check."""
    try:
        note = results_note(domain, verdict, results)
    except Exception:
        logger.exception("couldn't build results note for %s", domain)
        note = None
    send_lead(Lead(email=email, domain=domain, tags=[TAG_CHECKED], note=note))

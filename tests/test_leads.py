"""Tests for app/leads.py and the lead-capture endpoints in app/main.py.

No network and no CRM: endpoints run against a recording stub transport, and
HighLevelTransport is driven through httpx.MockTransport to pin the request
shapes it sends (verified once against the live Growably account).
"""

import json
import threading

import httpx
import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import leads
from app.rate_limit import RateLimiter

FAKE_RESULTS = [
    {"key": "dmarc", "label": "DMARC", "tier": "core", "status": "warn"},
    {"key": "spf", "label": "SPF", "tier": "core", "status": "pass"},
]
FAKE_VERDICT = {"level": "partial", "message": "Missing 1 of 3."}


class FailingTransport:
    def send(self, lead):
        raise RuntimeError("CRM down")


@pytest.fixture
def stub(monkeypatch):
    transport = leads.LogTransport()
    monkeypatch.setattr(leads, "transport", transport)
    return transport


@pytest.fixture
def client(monkeypatch, stub):
    monkeypatch.setattr(main, "limiter", RateLimiter([(100, 60)]))
    monkeypatch.setattr(main, "lead_limiter", RateLimiter([(2, 60)]))
    monkeypatch.setattr(main, "check_slots", threading.BoundedSemaphore(3))
    monkeypatch.setattr(main, "run_all_checks", lambda domain: FAKE_RESULTS)
    monkeypatch.setattr(main, "compute_verdict", lambda results: FAKE_VERDICT)
    return TestClient(main.app)


# --- endpoints ---

def test_every_check_records_a_lead_with_results_note(client, stub):
    response = client.post("/api/check", json={"email": "Pat@Example.com"})
    assert response.status_code == 200

    [lead] = stub.sent
    assert lead.email == "Pat@example.com"  # email-validator lowercases the domain
    assert lead.domain == "example.com"
    assert lead.tags == [leads.TAG_CHECKED]
    assert "DMARC: warn" in lead.note
    assert "https://dmarc.factoryinfo.tech/?d=example.com" in lead.note


def test_check_still_returns_results_when_crm_is_down(client, monkeypatch):
    monkeypatch.setattr(leads, "transport", FailingTransport())
    response = client.post("/api/check", json={"email": "pat@example.com"})
    assert response.status_code == 200
    assert response.json()["domain"] == "example.com"


def test_check_survives_a_broken_note_builder(client, stub, monkeypatch):
    def boom(*args):
        raise KeyError("message")

    monkeypatch.setattr(leads, "results_note", boom)
    assert client.post("/api/check", json={"email": "pat@example.com"}).status_code == 200
    assert stub.sent[-1].note is None  # lead still recorded, just without the note


def test_check_domain_runs_without_recording_a_lead(client, stub):
    response = client.post("/api/check-domain", json={"domain": "https://www.Example.com/"})
    assert response.status_code == 200
    assert response.json()["domain"] == "example.com"
    assert stub.sent == []


@pytest.mark.parametrize("bad", ["", "localhost", "exa mple.com", "-bad.com", "a" * 64 + ".com", "example"])
def test_check_domain_rejects_invalid_domains(client, bad):
    assert client.post("/api/check-domain", json={"domain": bad}).status_code == 422


def test_report_request_tags_the_contact(client, stub):
    response = client.post("/api/lead/report", json={"email": "pat@example.com"})
    assert response.status_code == 200
    assert stub.sent[-1].tags == [leads.TAG_REPORT]


def test_walkthrough_sends_name_and_phone(client, stub):
    response = client.post(
        "/api/lead/walkthrough",
        json={"email": "pat@example.com", "name": "  Pat Doe ", "phone": "+1 (406) 555-0100"},
    )
    assert response.status_code == 200
    lead = stub.sent[-1]
    assert (lead.name, lead.phone, lead.tags) == ("Pat Doe", "+1 (406) 555-0100", [leads.TAG_WALKTHROUGH])


def test_walkthrough_phone_is_optional(client, stub):
    response = client.post("/api/lead/walkthrough", json={"email": "pat@example.com", "name": "Pat", "phone": ""})
    assert response.status_code == 200
    assert stub.sent[-1].phone is None


@pytest.mark.parametrize(
    "body",
    [
        {"email": "pat@example.com", "name": "   "},
        {"email": "pat@example.com"},
        {"email": "pat@example.com", "name": "Pat", "phone": "call me <script>"},
        {"email": "nope", "name": "Pat"},
    ],
)
def test_walkthrough_validation(client, body):
    assert client.post("/api/lead/walkthrough", json=body).status_code == 422


def test_cta_returns_502_when_crm_fails(client, monkeypatch):
    monkeypatch.setattr(leads, "transport", FailingTransport())
    response = client.post("/api/lead/report", json={"email": "pat@example.com"})
    assert response.status_code == 502
    assert response.json()["detail"] == main.LEAD_FAILED_MESSAGE


def test_cta_endpoints_are_rate_limited(client):
    for _ in range(2):
        assert client.post("/api/lead/report", json={"email": "pat@example.com"}).status_code == 200
    response = client.post("/api/lead/report", json={"email": "pat@example.com"})
    assert response.status_code == 429
    assert "Retry-After" in response.headers


# --- HighLevel transport request shapes ---

def _recording_client(calls):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path == "/contacts/upsert":
            return httpx.Response(200, json={"contact": {"id": "c123"}})
        return httpx.Response(201, json={})

    return httpx.Client(
        base_url=leads.HighLevelTransport.BASE_URL,
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer t", "Version": leads.HighLevelTransport.API_VERSION},
    )


def test_highlevel_upserts_then_adds_tags_and_note():
    calls = []
    transport = leads.HighLevelTransport("t", "loc1", client=_recording_client(calls))
    transport.send(
        leads.Lead(email="pat@example.com", domain="example.com", tags=["a", "b"], name="Pat", note="hello")
    )

    assert [c.url.path for c in calls] == ["/contacts/upsert", "/contacts/c123/tags", "/contacts/c123/notes"]
    upsert = json.loads(calls[0].content)
    assert upsert == {
        "locationId": "loc1",
        "email": "pat@example.com",
        "website": "https://example.com",
        "source": leads.LEAD_SOURCE,
        "name": "Pat",
    }
    assert "tags" not in upsert  # tags go via the add-tags endpoint so existing ones are kept
    assert json.loads(calls[1].content) == {"tags": ["a", "b"]}
    assert json.loads(calls[2].content) == {"body": "hello"}
    assert calls[0].headers["Version"] == "2021-07-28"


def test_highlevel_skips_note_call_when_there_is_no_note():
    calls = []
    leads.HighLevelTransport("t", "loc1", client=_recording_client(calls)).send(
        leads.Lead(email="pat@example.com", domain="example.com", tags=["a"])
    )
    assert [c.url.path for c in calls] == ["/contacts/upsert", "/contacts/c123/tags"]


def test_send_lead_reports_failure_instead_of_raising(monkeypatch):
    monkeypatch.setattr(leads, "transport", FailingTransport())
    assert leads.send_lead(leads.Lead(email="pat@example.com", domain="example.com", tags=[])) is False


def test_transport_from_env(monkeypatch):
    monkeypatch.delenv("GROWABLY_TOKEN", raising=False)
    monkeypatch.delenv("GROWABLY_LOCATION_ID", raising=False)
    assert isinstance(leads._transport_from_env(), leads.LogTransport)

    monkeypatch.setenv("GROWABLY_TOKEN", "t")
    assert isinstance(leads._transport_from_env(), leads.LogTransport)  # both are required

    monkeypatch.setenv("GROWABLY_LOCATION_ID", "loc1")
    assert isinstance(leads._transport_from_env(), leads.HighLevelTransport)


def test_mask_email():
    assert leads.mask_email("pat@example.com") == "p***@example.com"

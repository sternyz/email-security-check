"""Tests for app/main.py.

Hits live public DNS through the real check functions (same convention as
the rest of the suite) rather than mocking the whole pipeline — this is
mainly verifying the HTTP layer (request/response shape, email parsing,
validation) since the check logic itself is already covered elsewhere.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_index_serves_the_landing_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "Check My Domain" in response.text


def test_check_endpoint_returns_domain_and_six_results():
    response = client.post("/api/check", json={"email": "someone@anthropic.com"})
    assert response.status_code == 200

    body = response.json()
    assert body["domain"] == "anthropic.com"
    assert len(body["results"]) == 6
    assert {r["key"] for r in body["results"]} == {
        "dmarc",
        "spf",
        "dkim",
        "mta_sts",
        "dnssec",
        "subdomains",
    }
    assert {r["tier"] for r in body["results"]} == {"core", "extra"}
    # anthropic.com is a known fixture: core all pass; mta_sts and dnssec fail.
    assert body["verdict"]["level"] == "core_pass"
    assert body["verdict"]["core_passing"] == 3
    assert body["verdict"]["extra_passing"] == 1


def test_check_endpoint_rejects_malformed_email():
    response = client.post("/api/check", json={"email": "not-an-email"})
    assert response.status_code == 422

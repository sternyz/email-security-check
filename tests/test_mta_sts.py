"""Tests for checks/mta_sts.py.

Two tests hit live public DNS and HTTPS, per the project's build-order
convention (docs/requirements.md §5): a known-good domain (enforce mode)
and a known-bad one (no MTA-STS at all). There's no stable real-world
domain in "testing" mode to use as a live fixture — it's a transitional
state most domains move out of quickly — so that path, along with the
unreachable-policy-file case, is mocked instead.
"""

import dns.resolver
import httpx
import pytest

from checks import mta_sts


def _mock_txt(monkeypatch, qname_to_txt: dict[str, str | None]):
    """Patch dns.resolver.resolve to serve a TXT record per exact qname, or raise NXDOMAIN."""

    def fake_resolve(qname, rdtype):
        value = qname_to_txt.get(qname)
        if value is None:
            raise dns.resolver.NXDOMAIN
        record = type("Rdata", (), {"strings": [value.encode()]})()
        return [record]

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)


def _mock_policy_fetch(monkeypatch, *, status_code: int = 200, text: str = "", raises: bool = False):
    """Patch httpx.get to return a canned policy-file response, or raise a connection error."""

    def fake_get(url, timeout=None):
        if raises:
            raise httpx.ConnectError("connection failed")
        return type("Response", (), {"status_code": status_code, "text": text})()

    monkeypatch.setattr(httpx, "get", fake_get)


# -- Live DNS + HTTPS: known-good domain --------------------------------------


def test_google_com_passes():
    """google.com publishes an MTA-STS record and an enforce-mode policy file."""
    result = mta_sts.check_mta_sts("google.com")
    assert result.status == "pass"
    assert "mode: enforce" in result.raw_evidence
    assert result.explanation == mta_sts.PASS_EXPLANATION


# -- Live DNS: known-bad domain ------------------------------------------------


def test_factoryinfotech_com_fails_with_no_mta_sts_record():
    """factoryinfotech.com has no _mta-sts TXT record at all."""
    result = mta_sts.check_mta_sts("factoryinfotech.com")
    assert result.status == "fail"
    assert result.raw_evidence == ""
    assert result.explanation == mta_sts.FAIL_EXPLANATION


# -- Mocked edge cases --------------------------------------------------------


def test_testing_mode_warns(monkeypatch):
    domain = "testing-mode-example.test"
    _mock_txt(monkeypatch, {f"_mta-sts.{domain}": "v=STSv1; id=20260101000000Z;"})
    _mock_policy_fetch(monkeypatch, text="version: STSv1\nmode: testing\nmx: mail.example.test\nmax_age: 86400\n")

    result = mta_sts.check_mta_sts(domain)
    assert result.status == "warn"
    assert result.explanation == mta_sts.WARN_EXPLANATION


def test_unreachable_policy_file_fails(monkeypatch):
    domain = "record-but-no-policy.test"
    _mock_txt(monkeypatch, {f"_mta-sts.{domain}": "v=STSv1; id=20260101000000Z;"})
    _mock_policy_fetch(monkeypatch, raises=True)

    result = mta_sts.check_mta_sts(domain)
    assert result.status == "fail"
    assert result.explanation == mta_sts.FAIL_EXPLANATION


def test_policy_file_missing_mode_fails(monkeypatch):
    domain = "malformed-policy.test"
    _mock_txt(monkeypatch, {f"_mta-sts.{domain}": "v=STSv1; id=20260101000000Z;"})
    _mock_policy_fetch(monkeypatch, text="version: STSv1\nmx: mail.example.test\nmax_age: 86400\n")

    result = mta_sts.check_mta_sts(domain)
    assert result.status == "fail"
    assert result.explanation == mta_sts.FAIL_EXPLANATION


def test_non_200_policy_response_fails(monkeypatch):
    domain = "policy-404.test"
    _mock_txt(monkeypatch, {f"_mta-sts.{domain}": "v=STSv1; id=20260101000000Z;"})
    _mock_policy_fetch(monkeypatch, status_code=404, text="Not Found")

    result = mta_sts.check_mta_sts(domain)
    assert result.status == "fail"
    assert result.explanation == mta_sts.FAIL_EXPLANATION

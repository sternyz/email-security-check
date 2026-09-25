"""Tests for checks/dmarc.py.

Two tests hit live public DNS against real domains, per the project's
build-order convention (docs/requirements.md §5): a known-good domain and a
known-bad/misconfigured one. The rest mock dns.resolver.resolve so the
edge cases (missing record, pct<100) don't depend on a third party's DNS
staying in a particular state.
"""

import dns.resolver
import pytest

from checks import dmarc


def _mock_txt(monkeypatch, value: str | None):
    """Patch dns.resolver.resolve to return a single TXT record, or raise NXDOMAIN."""

    def fake_resolve(qname, rdtype):
        if value is None:
            raise dns.resolver.NXDOMAIN
        record = type("Rdata", (), {"strings": [value.encode()]})()
        return [record]

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)


# -- Live DNS: known-good domain --------------------------------------------


def test_google_com_passes():
    """google.com publishes p=reject at pct=100 (implicit) — should pass."""
    result = dmarc.check_dmarc("google.com")
    assert result.status == "pass"
    assert "p=reject" in result.raw_evidence
    assert result.explanation == dmarc.PASS_EXPLANATION


# -- Live DNS: known-bad/misconfigured domain --------------------------------


def test_factoryinfotech_com_warns_on_watch_only_policy():
    """factoryinfotech.com currently publishes p=none — exists but doesn't block."""
    result = dmarc.check_dmarc("factoryinfotech.com")
    assert result.status == "warn"
    assert "p=none" in result.raw_evidence
    assert result.explanation == dmarc.WARN_EXPLANATION


# -- Mocked edge cases --------------------------------------------------------


def test_missing_record_fails(monkeypatch):
    _mock_txt(monkeypatch, None)
    result = dmarc.check_dmarc("no-dmarc-example.test")
    assert result.status == "fail"
    assert result.raw_evidence == ""
    assert result.explanation == dmarc.FAIL_EXPLANATION


def test_reject_below_full_pct_is_downgraded_to_warn(monkeypatch):
    _mock_txt(monkeypatch, "v=DMARC1; p=reject; pct=50")
    result = dmarc.check_dmarc("partial-enforcement.test")
    assert result.status == "warn"
    assert result.explanation == dmarc.WARN_EXPLANATION


def test_quarantine_at_full_pct_passes(monkeypatch):
    _mock_txt(monkeypatch, "v=DMARC1; p=quarantine; pct=100")
    result = dmarc.check_dmarc("quarantine-example.test")
    assert result.status == "pass"
    assert result.explanation == dmarc.PASS_EXPLANATION


def test_missing_p_tag_fails(monkeypatch):
    _mock_txt(monkeypatch, "v=DMARC1; rua=mailto:reports@example.test")
    result = dmarc.check_dmarc("no-policy-tag.test")
    assert result.status == "fail"
    assert result.explanation == dmarc.FAIL_EXPLANATION

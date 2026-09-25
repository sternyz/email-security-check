"""Tests for checks/dkim.py.

Two tests hit live public DNS, per the project's build-order convention
(docs/requirements.md §5): a known-good domain and a known-bad one.
example.com is a stable known-bad fixture — as an IANA reserved domain it
wildcards every DKIM selector to a placeholder record with an empty p= tag
(a revoked/no-op key), so it reliably fails the check without depending on
a live domain's real mail configuration. The rest mock dns.resolver.resolve
for edge cases (no selectors answer at all, a later selector in the list,
an explicitly empty p= tag).
"""

import dns.resolver
import pytest

from checks import dkim


def _mock_selector_records(monkeypatch, qname_to_txt: dict[str, str | None]):
    """Patch dns.resolver.resolve to serve a TXT record per exact qname, or raise NXDOMAIN."""

    def fake_resolve(qname, rdtype):
        value = qname_to_txt.get(qname)
        if value is None:
            raise dns.resolver.NXDOMAIN
        record = type("Rdata", (), {"strings": [value.encode()]})()
        return [record]

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)


# -- Live DNS: known-good domain --------------------------------------------


def test_factoryinfotech_com_passes_on_google_selector():
    """factoryinfotech.com publishes a valid DKIM key under the 'google' selector."""
    result = dkim.check_dkim("factoryinfotech.com")
    assert result.status == "pass"
    assert "google._domainkey" in result.raw_evidence
    assert result.explanation == dkim.PASS_EXPLANATION


# -- Live DNS: known-bad domain ------------------------------------------------


def test_example_com_fails_on_wildcard_revoked_keys():
    """example.com wildcards every selector to a placeholder record with an empty p= (revoked)."""
    result = dkim.check_dkim("example.com")
    assert result.status == "fail"
    assert result.raw_evidence == ""
    assert result.explanation == dkim.FAIL_EXPLANATION


# -- Mocked edge cases --------------------------------------------------------


def test_no_selectors_answer_fails(monkeypatch):
    _mock_selector_records(monkeypatch, {})
    result = dkim.check_dkim("no-dkim-example.test")
    assert result.status == "fail"
    assert result.raw_evidence == ""
    assert result.explanation == dkim.FAIL_EXPLANATION


def test_matches_a_later_selector_in_the_list(monkeypatch):
    domain = "mailgun-only.test"
    _mock_selector_records(
        monkeypatch,
        {f"mailgun._domainkey.{domain}": "v=DKIM1; k=rsa; p=abc123"},
    )
    result = dkim.check_dkim(domain)
    assert result.status == "pass"
    assert "mailgun._domainkey" in result.raw_evidence
    assert result.explanation == dkim.PASS_EXPLANATION


def test_empty_p_tag_is_treated_as_no_signature(monkeypatch):
    domain = "revoked-key.test"
    _mock_selector_records(
        monkeypatch,
        {f"{sel}._domainkey.{domain}": "v=DKIM1; p=" for sel in dkim.COMMON_SELECTORS},
    )
    result = dkim.check_dkim(domain)
    assert result.status == "fail"
    assert result.explanation == dkim.FAIL_EXPLANATION

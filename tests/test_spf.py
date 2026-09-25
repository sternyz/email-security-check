"""Tests for checks/spf.py.

One test hits live public DNS against a known-good domain, per the project's
build-order convention (docs/requirements.md §5). There is no stable
known-bad *real* domain to test against for SPF: any domain still sending
mail keeps its SPF record working (a broken record breaks their own
deliverability), so missing/duplicate/over-limit records don't reliably
exist in the wild the way DMARC's p=none does. All fail paths are mocked
instead, via a domain->TXT-records map patched into dns.resolver.resolve.
"""

import dns.resolver
import pytest

from checks import spf


def _mock_multi_txt(monkeypatch, domain_records: dict[str, list[str] | None]):
    """Patch dns.resolver.resolve to serve TXT records from a domain->values map."""

    def fake_resolve(qname, rdtype):
        values = domain_records.get(qname)
        if values is None:
            raise dns.resolver.NXDOMAIN
        return [type("Rdata", (), {"strings": [v.encode()]})() for v in values]

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)


# -- Live DNS: known-good domain --------------------------------------------


def test_google_com_passes():
    """google.com publishes a single SPF record with one include, well under the limit."""
    result = spf.check_spf("google.com")
    assert result.status == "pass"
    assert "include:_spf.google.com" in result.raw_evidence
    assert result.explanation == spf.PASS_EXPLANATION


# -- Mocked edge cases --------------------------------------------------------


def test_missing_record_fails(monkeypatch):
    _mock_multi_txt(monkeypatch, {"no-spf-example.test": None})
    result = spf.check_spf("no-spf-example.test")
    assert result.status == "fail"
    assert result.raw_evidence == ""
    assert result.explanation == spf.FAIL_MISSING_EXPLANATION


def test_duplicate_records_fail(monkeypatch):
    _mock_multi_txt(
        monkeypatch,
        {"dup-spf-example.test": ["v=spf1 -all", "v=spf1 include:other.test -all"]},
    )
    result = spf.check_spf("dup-spf-example.test")
    assert result.status == "fail"
    assert result.explanation == spf.FAIL_OVER_LIMIT_EXPLANATION


def test_over_lookup_limit_fails(monkeypatch):
    includes = " ".join(f"include:inc{i}.test" for i in range(1, 12))
    domain_records = {"over-limit.test": [f"v=spf1 {includes} ~all"]}
    for i in range(1, 12):
        domain_records[f"inc{i}.test"] = ["v=spf1 ip4:1.2.3.4 ~all"]
    _mock_multi_txt(monkeypatch, domain_records)

    result = spf.check_spf("over-limit.test")
    assert result.status == "fail"
    assert result.explanation == spf.FAIL_OVER_LIMIT_EXPLANATION


def test_exactly_ten_lookups_passes(monkeypatch):
    includes = " ".join(f"include:inc{i}.test" for i in range(1, 11))
    domain_records = {"at-limit.test": [f"v=spf1 {includes} ~all"]}
    for i in range(1, 11):
        domain_records[f"inc{i}.test"] = ["v=spf1 ip4:1.2.3.4 ~all"]
    _mock_multi_txt(monkeypatch, domain_records)

    result = spf.check_spf("at-limit.test")
    assert result.status == "pass"
    assert result.explanation == spf.PASS_EXPLANATION


def test_redirect_counts_as_a_lookup(monkeypatch):
    domain_records = {
        "redirect-example.test": ["v=spf1 redirect=_spf.redirect-example.test"],
        "_spf.redirect-example.test": ["v=spf1 ip4:1.2.3.4 -all"],
    }
    _mock_multi_txt(monkeypatch, domain_records)

    result = spf.check_spf("redirect-example.test")
    assert result.status == "pass"
    assert result.explanation == spf.PASS_EXPLANATION

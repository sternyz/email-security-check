"""Tests for checks/subdomains.py.

Two tests hit live public DNS, per the project's build-order convention
(docs/requirements.md §5): a known-good domain and a known-bad one.
"www" is deliberately excluded from checks/common_subdomains.py (see that
file's docstring), which is what makes a real live-good fixture possible
here at all — with it included, virtually every real domain failed.

- anthropic.com: mail.anthropic.com is live and has its own SPF record,
  and the root DMARC record's sp=reject covers all subdomains — no gap.
- factoryinfotech.com: autodiscover.factoryinfotech.com is live with no
  SPF of its own, and the root DMARC record is p=none with no sp= tag, so
  it doesn't cover subdomains either — two independent gaps.

The rest mock dns.resolver.resolve for edge cases that need precise
control: no live candidates at all, DMARC's sp=/p= inheritance/fallback
behavior, and MX/SPF-derived candidate discovery.
"""

import dns.resolver
import pytest

from checks import subdomains


def _mock_dns(monkeypatch, responses: dict):
    """Patch dns.resolver.resolve keyed by exact (qname, rdtype); missing/None raises NXDOMAIN."""

    def fake_resolve(qname, rdtype):
        value = responses.get((qname, rdtype))
        if value is None:
            raise dns.resolver.NXDOMAIN
        return value

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)


def _live():
    """A placeholder 'answer' for A/AAAA/MX presence checks that don't inspect content."""
    return ["placeholder"]


def _txt(value: str):
    return [type("Rdata", (), {"strings": [value.encode()]})()]


def _mx(exchange: str):
    return [type("Rdata", (), {"exchange": exchange})()]


# -- Live DNS: known-good domain --------------------------------------------


def test_anthropic_com_passes():
    """mail.anthropic.com has its own SPF, and root sp=reject covers subdomains generally."""
    result = subdomains.check_subdomains("anthropic.com")
    assert result.status == "pass"
    assert "mail.anthropic.com" in result.raw_evidence
    assert result.explanation == subdomains.PASS_EXPLANATION


# -- Live DNS: known-bad domain ------------------------------------------------


def test_factoryinfotech_com_fails_on_spf_and_dmarc_gaps():
    """autodiscover is live with no SPF of its own, and root DMARC (p=none) doesn't cover subdomains."""
    result = subdomains.check_subdomains("factoryinfotech.com")
    assert result.status == "fail"
    assert "autodiscover.factoryinfotech.com" in result.raw_evidence
    assert "policy (sp/p)=none" in result.raw_evidence
    assert result.explanation == subdomains.FAIL_EXPLANATION


# -- Mocked edge cases --------------------------------------------------------


def test_no_live_candidates_passes_vacuously(monkeypatch):
    domain = "no-subdomains-example.test"
    responses = {(domain, "MX"): None, (domain, "TXT"): None}
    for label in subdomains.COMMON_SUBDOMAINS:
        for rdtype in ("A", "AAAA", "MX"):
            responses[(f"{label}.{domain}", rdtype)] = None
    _mock_dns(monkeypatch, responses)

    result = subdomains.check_subdomains(domain)
    assert result.status == "pass"
    assert result.raw_evidence == ""
    assert result.explanation == subdomains.PASS_EXPLANATION


def test_root_dmarc_sp_none_fails_even_with_good_subdomain_spf(monkeypatch):
    """A subdomain's own SPF being fine doesn't help if sp= explicitly weakens DMARC coverage."""
    domain = "weak-sp-example.test"
    responses = {
        (domain, "MX"): None,
        (domain, "TXT"): _txt("v=spf1 -all"),
        (f"_dmarc.{domain}", "TXT"): _txt("v=DMARC1; p=reject; sp=none"),
        (f"mail.{domain}", "A"): _live(),
        (f"mail.{domain}", "TXT"): _txt("v=spf1 -all"),
        (f"autodiscover.{domain}", "A"): None,
        (f"autodiscover.{domain}", "AAAA"): None,
        (f"autodiscover.{domain}", "MX"): None,
        (f"smtp.{domain}", "A"): None,
        (f"smtp.{domain}", "AAAA"): None,
        (f"smtp.{domain}", "MX"): None,
    }
    _mock_dns(monkeypatch, responses)

    result = subdomains.check_subdomains(domain)
    assert result.status == "fail"
    assert "policy (sp/p)=none" in result.raw_evidence
    assert result.explanation == subdomains.FAIL_EXPLANATION


def test_root_dmarc_p_reject_covers_subdomains_when_sp_absent(monkeypatch):
    """No sp= tag falls back to p= for subdomain coverage, per RFC 7489 §6.3."""
    domain = "p-fallback-example.test"
    responses = {
        (domain, "MX"): None,
        (domain, "TXT"): _txt("v=spf1 -all"),
        (f"_dmarc.{domain}", "TXT"): _txt("v=DMARC1; p=reject"),
        (f"mail.{domain}", "A"): _live(),
        (f"mail.{domain}", "TXT"): _txt("v=spf1 -all"),
        (f"autodiscover.{domain}", "A"): None,
        (f"autodiscover.{domain}", "AAAA"): None,
        (f"autodiscover.{domain}", "MX"): None,
        (f"smtp.{domain}", "A"): None,
        (f"smtp.{domain}", "AAAA"): None,
        (f"smtp.{domain}", "MX"): None,
    }
    _mock_dns(monkeypatch, responses)

    result = subdomains.check_subdomains(domain)
    assert result.status == "pass"
    assert "policy (sp/p)=reject" in result.raw_evidence
    assert result.explanation == subdomains.PASS_EXPLANATION


def test_mx_and_spf_derived_subdomains_are_probed_too(monkeypatch):
    """Candidates aren't just the static common list — MX targets and SPF includes count too."""
    domain = "derived-example.test"
    responses = {
        (domain, "MX"): _mx(f"relay.{domain}"),
        (domain, "TXT"): _txt(f"v=spf1 include:_spf.{domain} -all"),
        (f"_dmarc.{domain}", "TXT"): _txt("v=DMARC1; p=reject; sp=reject"),
        (f"mail.{domain}", "A"): None,
        (f"mail.{domain}", "AAAA"): None,
        (f"mail.{domain}", "MX"): None,
        (f"autodiscover.{domain}", "A"): None,
        (f"autodiscover.{domain}", "AAAA"): None,
        (f"autodiscover.{domain}", "MX"): None,
        (f"smtp.{domain}", "A"): None,
        (f"smtp.{domain}", "AAAA"): None,
        (f"smtp.{domain}", "MX"): None,
        (f"relay.{domain}", "A"): _live(),
        (f"relay.{domain}", "TXT"): None,  # no SPF of its own -> gap
        (f"_spf.{domain}", "A"): _live(),
        (f"_spf.{domain}", "TXT"): _txt("v=spf1 -all"),
    }
    _mock_dns(monkeypatch, responses)

    result = subdomains.check_subdomains(domain)
    assert result.status == "fail"
    assert f"relay.{domain}: spf=fail" in result.raw_evidence
    assert f"_spf.{domain}: spf=pass" in result.raw_evidence

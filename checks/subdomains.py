"""Subdomains check — "The gap behind a pass." See docs/requirements.md §1."""

import dns.exception
import dns.resolver

from checks import dmarc as _dmarc
from checks.common_subdomains import COMMON_SUBDOMAINS
from checks.models import CheckResult
from checks.spf import check_spf

PASS_EXPLANATION = "Your subdomains are covered too — no gap behind the main domain."
FAIL_EXPLANATION = (
    "A domain can be locked down while every subdomain stays wide open. It "
    "reads as protected and is not, which is why this one is worth checking "
    "separately."
)

_RESOLVE_ERRORS = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
)


def _subdomain_label(hostname: str, domain: str) -> str | None:
    """Return the label portion if hostname is a strict subdomain of domain, else None."""
    hostname = hostname.rstrip(".").lower()
    domain = domain.lower()
    suffix = f".{domain}"
    if hostname != domain and hostname.endswith(suffix):
        return hostname[: -len(suffix)]
    return None


def _mx_subdomain_labels(domain: str) -> list[str]:
    """Subdomain labels found in the root domain's own MX targets."""
    try:
        answers = dns.resolver.resolve(domain, "MX")
    except _RESOLVE_ERRORS:
        return []

    labels = []
    for rdata in answers:
        label = _subdomain_label(str(rdata.exchange), domain)
        if label:
            labels.append(label)
    return labels


def _spf_include_subdomain_labels(domain: str) -> list[str]:
    """Subdomain labels found in the root domain's own SPF include: targets."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
    except _RESOLVE_ERRORS:
        return []

    labels = []
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if not txt.strip().lower().startswith("v=spf1"):
            continue
        for term in txt.split():
            if term.lower().startswith("include:"):
                label = _subdomain_label(term.split(":", 1)[1], domain)
                if label:
                    labels.append(label)
    return labels


def _discover_candidate_labels(domain: str) -> list[str]:
    """Common subdomains, plus any subdomain hostnames found in the root's own MX/SPF records."""
    candidates = list(COMMON_SUBDOMAINS)
    for label in _mx_subdomain_labels(domain) + _spf_include_subdomain_labels(domain):
        if label not in candidates:
            candidates.append(label)
    return candidates


def _is_live(fqdn: str) -> bool:
    for rdtype in ("A", "AAAA", "MX"):
        try:
            dns.resolver.resolve(fqdn, rdtype)
            return True
        except _RESOLVE_ERRORS:
            continue
    return False


def _dmarc_subdomain_coverage(domain: str) -> tuple[str | None, bool]:
    """Whether the root domain's own DMARC record protects its subdomains too.

    DMARC subdomains inherit the organizational domain's policy via the
    `sp=` tag (RFC 7489 §6.3), or the `p=` tag when `sp=` is absent — there
    is no need to look for a subdomain's own _dmarc record, and doing so
    would flag inherited (i.e. already-covered) subdomains as gaps.
    """
    records = _dmarc._lookup_dmarc_records(domain)
    if not records:
        return None, False

    policy = _dmarc._parse_tag(records[0], "sp") or _dmarc._parse_tag(records[0], "p")
    if policy is None:
        return None, False

    policy = policy.lower()
    return policy, policy in ("quarantine", "reject")


def check_subdomains(domain: str) -> CheckResult:
    live_fqdns = [
        f"{label}.{domain}" for label in _discover_candidate_labels(domain) if _is_live(f"{label}.{domain}")
    ]

    if not live_fqdns:
        return CheckResult(status="pass", raw_evidence="", explanation=PASS_EXPLANATION)

    evidence_lines = []
    has_gap = False

    # SPF has no inheritance mechanism, so each live subdomain needs its own record.
    for fqdn in live_fqdns:
        spf_result = check_spf(fqdn)
        evidence_lines.append(f"{fqdn}: spf={spf_result.status}")
        if spf_result.status == "fail":
            has_gap = True

    # DMARC does inherit, so this is a single root-level check, not per subdomain.
    policy, covers_subdomains = _dmarc_subdomain_coverage(domain)
    evidence_lines.append(f"{domain}: dmarc subdomain policy (sp/p)={policy or 'missing'}")
    if not covers_subdomains:
        has_gap = True

    raw_evidence = "\n".join(evidence_lines)

    if has_gap:
        return CheckResult(status="fail", raw_evidence=raw_evidence, explanation=FAIL_EXPLANATION)

    return CheckResult(status="pass", raw_evidence=raw_evidence, explanation=PASS_EXPLANATION)

"""DNSSEC check — "Can your DNS be forged." See docs/requirements.md §1."""

import dns.exception
import dns.flags
import dns.resolver

from checks.models import CheckResult

PASS_EXPLANATION = "DNS answers for your domain are signed and can't be tampered with in transit."
FAIL_EXPLANATION = "Signed DNS answers cannot be tampered with between the lookup and the answer. Unsigned ones can."

_RESOLVE_ERRORS = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
)

# Public resolvers that perform DNSSEC validation themselves, so we can read
# their AD (Authenticated Data) bit instead of validating the signature
# chain ourselves. The deployment host's own configured resolver may not
# validate, so we deliberately query these rather than the system default.
_VALIDATING_RESOLVERS = ["1.1.1.1", "8.8.8.8"]


def _make_validating_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = _VALIDATING_RESOLVERS
    resolver.use_edns(0, dns.flags.DO, 4096)
    return resolver


def _lookup_ds_record(resolver: dns.resolver.Resolver, domain: str) -> str | None:
    """Return the DS record published at the registrar for <domain>, if any."""
    try:
        answers = resolver.resolve(domain, "DS")
    except _RESOLVE_ERRORS:
        return None
    return "\n".join(str(rdata) for rdata in answers)


def _is_validated(resolver: dns.resolver.Resolver, domain: str) -> bool:
    """Ask a validating resolver whether it authenticated the signature chain.

    A resolver that validates DNSSEC returns SERVFAIL (surfaced by dnspython
    as NoNameservers) for a zone whose signatures don't check out, so that
    counts as not validated rather than an error to propagate.
    """
    try:
        answer = resolver.resolve(domain, "A")
    except _RESOLVE_ERRORS:
        return False
    return bool(answer.response.flags & dns.flags.AD)


def check_dnssec(domain: str) -> CheckResult:
    resolver = _make_validating_resolver()

    ds_record = _lookup_ds_record(resolver, domain)
    if ds_record is None:
        return CheckResult(status="fail", raw_evidence="", explanation=FAIL_EXPLANATION)

    if not _is_validated(resolver, domain):
        return CheckResult(status="fail", raw_evidence=ds_record, explanation=FAIL_EXPLANATION)

    return CheckResult(status="pass", raw_evidence=ds_record, explanation=PASS_EXPLANATION)

"""DKIM check — "Is your mail signed." See docs/requirements.md §1."""

import dns.exception
import dns.resolver

from checks.dkim_selectors import COMMON_SELECTORS
from checks.models import CheckResult

PASS_EXPLANATION = "A signature proves a message really came from you and wasn't altered on the way."
FAIL_EXPLANATION = (
    "We couldn't find a signature using the selectors common platforms use. "
    "Without one, there's no way to verify a message claiming to be from you "
    "actually is."
)

_RESOLVE_ERRORS = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
)


def _lookup_dkim_record(domain: str, selector: str) -> str | None:
    """Return the DKIM TXT record for <selector>._domainkey.<domain>, if valid."""
    try:
        answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
    except _RESOLVE_ERRORS:
        return None

    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if _is_valid_dkim_record(txt):
            return txt
    return None


def _is_valid_dkim_record(record: str) -> bool:
    """A usable DKIM record declares a public key via a non-empty p= tag.

    An empty p= means the key has been revoked (RFC 6376 §3.6.1) — treat
    that the same as no record at all.
    """
    for part in record.split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            return bool(part.split("=", 1)[1].strip())
    return False


def check_dkim(domain: str) -> CheckResult:
    for selector in COMMON_SELECTORS:
        record = _lookup_dkim_record(domain, selector)
        if record:
            raw_evidence = f"{selector}._domainkey.{domain}: {record}"
            return CheckResult(status="pass", raw_evidence=raw_evidence, explanation=PASS_EXPLANATION)

    return CheckResult(status="fail", raw_evidence="", explanation=FAIL_EXPLANATION)

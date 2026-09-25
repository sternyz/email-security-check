"""SPF check — "Is your sender list still working." See docs/requirements.md §1."""

import dns.exception
import dns.resolver

from checks.models import CheckResult

PASS_EXPLANATION = "Your sender list is valid and under the lookup limit."
FAIL_OVER_LIMIT_EXPLANATION = (
    "We count the DNS lookups your record needs. Go over ten and the whole "
    "record silently stops working, with no warning to anyone. Two records "
    "published at once breaks it outright."
)
FAIL_MISSING_EXPLANATION = "There's no sender list at all — anything can claim to send as you."

_RESOLVE_ERRORS = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
)

# Mechanisms that require a DNS lookup per RFC 7208 §4.6.4. "redirect" is a
# modifier, not a mechanism, and is handled separately below.
_LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists")
_MAX_LOOKUPS = 10


def _lookup_spf_records(domain: str) -> list[str]:
    """Return every TXT record on <domain> that looks like an SPF record."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
    except _RESOLVE_ERRORS:
        return []

    records = []
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if txt.strip().lower().startswith("v=spf1"):
            records.append(txt)
    return records


def _count_lookups(record: str, seen: set[str]) -> int:
    """Recursively count DNS-lookup mechanisms/modifiers per RFC 7208 §4.6.4."""
    count = 0
    redirect_target = None

    for term in record.split():
        stripped = term.lstrip("+-~?")
        lower = stripped.lower()

        matched_mech = None
        for mech in _LOOKUP_MECHANISMS:
            if lower == mech or (lower.startswith(mech) and lower[len(mech) : len(mech) + 1] in (":", "/")):
                matched_mech = mech
                break

        if matched_mech:
            count += 1
            if matched_mech == "include" and ":" in stripped:
                target = stripped.split(":", 1)[1]
                if target not in seen:
                    seen.add(target)
                    nested = _lookup_spf_records(target)
                    if nested:
                        count += _count_lookups(nested[0], seen)
            continue

        if lower.startswith("redirect="):
            redirect_target = stripped.split("=", 1)[1]

    if redirect_target:
        count += 1
        if redirect_target not in seen:
            seen.add(redirect_target)
            nested = _lookup_spf_records(redirect_target)
            if nested:
                count += _count_lookups(nested[0], seen)

    return count


def check_spf(domain: str) -> CheckResult:
    records = _lookup_spf_records(domain)

    if not records:
        return CheckResult(status="fail", raw_evidence="", explanation=FAIL_MISSING_EXPLANATION)

    raw_evidence = "\n".join(records)

    if len(records) > 1:
        return CheckResult(status="fail", raw_evidence=raw_evidence, explanation=FAIL_OVER_LIMIT_EXPLANATION)

    lookup_count = _count_lookups(records[0], seen={domain})

    if lookup_count > _MAX_LOOKUPS:
        return CheckResult(status="fail", raw_evidence=raw_evidence, explanation=FAIL_OVER_LIMIT_EXPLANATION)

    return CheckResult(status="pass", raw_evidence=raw_evidence, explanation=PASS_EXPLANATION)

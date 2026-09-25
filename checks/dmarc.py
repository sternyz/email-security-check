"""DMARC check — "Is impersonation actually stopped." See docs/requirements.md §1."""

import dns.exception
import dns.resolver

from checks.models import CheckResult

PASS_EXPLANATION = "Impersonation attempts are blocked, not just logged."
WARN_EXPLANATION = (
    "The rule can be missing, set to watch without blocking, or applied to only "
    "a share of messages. Watch-only is the one almost everyone assumes is "
    "finished when it is not."
)
FAIL_EXPLANATION = (
    "There's no rule telling receiving servers what to do with forged mail. "
    "Right now, nothing stops it."
)

_RESOLVE_ERRORS = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
)


def _lookup_dmarc_records(domain: str) -> list[str]:
    """Return every TXT record under _dmarc.<domain> that looks like a DMARC record."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
    except _RESOLVE_ERRORS:
        return []

    records = []
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if txt.strip().lower().startswith("v=dmarc1"):
            records.append(txt)
    return records


def _parse_tag(record: str, tag: str) -> str | None:
    for part in record.split(";"):
        part = part.strip()
        if part.lower().startswith(f"{tag}="):
            return part.split("=", 1)[1].strip()
    return None


def check_dmarc(domain: str) -> CheckResult:
    records = _lookup_dmarc_records(domain)

    if not records:
        return CheckResult(status="fail", raw_evidence="", explanation=FAIL_EXPLANATION)

    raw_evidence = "\n".join(records)
    record = records[0]

    policy = _parse_tag(record, "p")
    if policy is None:
        return CheckResult(status="fail", raw_evidence=raw_evidence, explanation=FAIL_EXPLANATION)
    policy = policy.lower()

    if policy == "none":
        return CheckResult(status="warn", raw_evidence=raw_evidence, explanation=WARN_EXPLANATION)

    if policy not in ("quarantine", "reject"):
        return CheckResult(status="fail", raw_evidence=raw_evidence, explanation=FAIL_EXPLANATION)

    pct_raw = _parse_tag(record, "pct")
    pct = int(pct_raw) if pct_raw and pct_raw.isdigit() else 100
    if pct < 100:
        return CheckResult(status="warn", raw_evidence=raw_evidence, explanation=WARN_EXPLANATION)

    return CheckResult(status="pass", raw_evidence=raw_evidence, explanation=PASS_EXPLANATION)

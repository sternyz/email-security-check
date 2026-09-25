"""MTA-STS check — "Is incoming mail encrypted." See docs/requirements.md §1."""

import dns.exception
import dns.resolver
import httpx

from checks.models import CheckResult

PASS_EXPLANATION = "Incoming mail is protected — it can't be silently downgraded and intercepted in transit."
WARN_EXPLANATION = (
    "Testing mode only reports downgrade attempts after the fact — it "
    "doesn't stop them. Enforce is what actually blocks it; testing alone "
    "still leaves mail exposed while it looks handled."
)
FAIL_EXPLANATION = "Without it, mail on its way to you can be quietly downgraded to plain text and read in transit."

_RESOLVE_ERRORS = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
)

_FETCH_TIMEOUT_SECONDS = 5.0


def _lookup_mta_sts_record(domain: str) -> str | None:
    """Return the _mta-sts.<domain> TXT record, if it looks like an MTA-STS marker."""
    try:
        answers = dns.resolver.resolve(f"_mta-sts.{domain}", "TXT")
    except _RESOLVE_ERRORS:
        return None

    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if txt.strip().lower().startswith("v=stsv1"):
            return txt
    return None


def _fetch_policy(domain: str) -> str | None:
    """Fetch the MTA-STS policy file over HTTPS, per RFC 8461 §3.2."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        response = httpx.get(url, timeout=_FETCH_TIMEOUT_SECONDS)
    except httpx.HTTPError:
        return None

    if response.status_code != 200:
        return None
    return response.text


def _parse_mode(policy_text: str) -> str | None:
    for line in policy_text.splitlines():
        line = line.strip()
        if line.lower().startswith("mode:"):
            return line.split(":", 1)[1].strip().lower()
    return None


def check_mta_sts(domain: str) -> CheckResult:
    txt_record = _lookup_mta_sts_record(domain)
    if txt_record is None:
        return CheckResult(status="fail", raw_evidence="", explanation=FAIL_EXPLANATION)

    policy_text = _fetch_policy(domain)
    if policy_text is None:
        return CheckResult(status="fail", raw_evidence=txt_record, explanation=FAIL_EXPLANATION)

    raw_evidence = f"{txt_record}\n{policy_text}"
    mode = _parse_mode(policy_text)

    if mode == "enforce":
        return CheckResult(status="pass", raw_evidence=raw_evidence, explanation=PASS_EXPLANATION)
    if mode == "testing":
        return CheckResult(status="warn", raw_evidence=raw_evidence, explanation=WARN_EXPLANATION)

    return CheckResult(status="fail", raw_evidence=raw_evidence, explanation=FAIL_EXPLANATION)

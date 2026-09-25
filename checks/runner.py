"""Runs all six Tier 1 checks against a domain and computes an overall verdict.

See docs/requirements.md §1 (checks + card headlines) and §3 (verdict banner
copy). The banner copy template has one gap this module has to fill in
without exact spec text — flagged inline below; worth a look before this
ships:

- The "most severe fail" ranking (which check's explanation gets featured
  in a partial-verdict banner) isn't specified anywhere. Ranked here as
  impersonation risk (DMARC/SPF/DKIM) > interception/integrity risk
  (MTA-STS/DNSSEC) > the narrower Subdomains gap, with fail always
  outranking warn.
- The banner template is "Right now, [most severe fail's consequence]."
  The card explanations are standalone sentences that don't fit after
  "Right now,", so each check has its own short consequence clause in
  BANNER_CONSEQUENCES below (banner-only copy, drafted to match the
  spec's tone; not in requirements.md).
- "Mostly/all fail" vs. "Partial" isn't given a numeric threshold —
  implemented as 5 or 6 of 6 missing.
"""

from checks.dkim import check_dkim
from checks.dmarc import check_dmarc
from checks.dnssec import check_dnssec
from checks.mta_sts import check_mta_sts
from checks.spf import check_spf
from checks.subdomains import check_subdomains

ALL_PASS_MESSAGE = (
    "Your domain passes all six checks. Someone is doing their job here — this is what good looks like."
)
MOSTLY_FAIL_MESSAGE = (
    "Your domain has almost none of the standard email protections in place. "
    "Anyone can send email as your company right now, and nothing in your "
    "setup will catch it."
)

_MOSTLY_FAIL_THRESHOLD = 5

# Order is also "most severe" priority order (see module docstring) — leftmost wins a tie.
CHECKS = [
    ("dmarc", "DMARC", "Is impersonation actually stopped", check_dmarc),
    ("spf", "SPF", "Is your sender list still working", check_spf),
    ("dkim", "DKIM", "Is your mail signed", check_dkim),
    ("mta_sts", "MTA-STS", "Is incoming mail encrypted", check_mta_sts),
    ("dnssec", "DNSSEC", "Can your DNS be forged", check_dnssec),
    ("subdomains", "Subdomains", "The gap behind a pass", check_subdomains),
]

_PRIORITY = {key: index for index, (key, *_rest) in enumerate(CHECKS)}

# Completes "Right now, ___." in the partial-verdict banner, keyed by
# (check key, status). Only statuses a check can actually return are listed.
BANNER_CONSEQUENCES = {
    ("dmarc", "fail"): "nothing stops someone from sending email as your company",
    ("dmarc", "warn"): "email pretending to be you is being watched, not blocked",
    ("spf", "fail"): "your sender list isn't working, so anything can claim to send as you",
    ("dkim", "fail"): "your mail isn't signed, so nothing proves a message really came from you",
    ("mta_sts", "fail"): "mail on its way to you can be quietly downgraded to plain text and read in transit",
    ("mta_sts", "warn"): "encryption for incoming mail is only being tested, not enforced",
    ("dnssec", "fail"): "your DNS answers aren't signed, so they can be forged between the lookup and the answer",
    ("subdomains", "fail"): "your subdomains are left open behind a protected main domain",
}


def run_all_checks(domain: str) -> list[dict]:
    results = []
    for key, label, headline, fn in CHECKS:
        result = fn(domain)
        results.append(
            {
                "key": key,
                "label": label,
                "headline": headline,
                "status": result.status,
                "explanation": result.explanation,
                "raw_evidence": result.raw_evidence,
            }
        )
    return results


def _most_severe(results: list[dict]) -> dict:
    def sort_key(result: dict) -> tuple[int, int]:
        status_rank = 0 if result["status"] == "fail" else 1  # fail outranks warn
        return (status_rank, _PRIORITY[result["key"]])

    return min(results, key=sort_key)


def compute_verdict(results: list[dict]) -> dict:
    total = len(results)
    missing = sum(1 for r in results if r["status"] != "pass")

    if missing == 0:
        return {"level": "all_pass", "message": ALL_PASS_MESSAGE}

    if missing >= _MOSTLY_FAIL_THRESHOLD:
        return {"level": "mostly_fail", "message": MOSTLY_FAIL_MESSAGE}

    non_passing = [r for r in results if r["status"] != "pass"]
    worst = _most_severe(non_passing)
    consequence = BANNER_CONSEQUENCES[(worst["key"], worst["status"])]
    message = (
        f"Your domain is missing {missing} of {total} protections. "
        f"Right now, {consequence}. Here's what's missing and what it means."
    )
    return {"level": "partial", "message": message, "missing": missing, "total": total}

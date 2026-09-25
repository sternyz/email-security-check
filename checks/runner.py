"""Runs all six Tier 1 checks against a domain and computes an overall verdict.

See docs/requirements.md §1 (checks + card headlines) and §3 (verdict banner
copy). Checks are split into two tiers:

- "core" (DMARC, SPF, DKIM): the three that decide whether someone can send
  email pretending to be you. These drive the score and the verdict banner.
- "extra" (MTA-STS, DNSSEC, Subdomains): worth adding on top, but a failure
  here is shown softly and never makes the verdict worse on its own.

Verdict levels, and where they depart from requirements.md §3 (which counts
all six equally):

- all_pass: all six pass. Spec copy as-is.
- core_pass: all three core checks pass, some extras don't. Not in the spec;
  CORE_PASS_MESSAGE is drafted copy.
- partial: one or two core checks don't pass. Spec template, but counts
  "[N] of 3 essential protections" rather than "[N] of 6 protections". The
  "Right now, [consequence]." clause comes from BANNER_CONSEQUENCES
  (drafted, banner-only copy — the card explanations are standalone
  sentences that don't fit after "Right now,").
- mostly_fail: none of the three core checks pass. Spec copy as-is.

Within the core tier, the featured "most severe" check is fail before warn,
then DMARC > SPF > DKIM (CHECKS order).
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
CORE_PASS_MESSAGE = (
    "The three essentials are in place, so faking email from your domain is hard. "
    "{extras} Here's what they add."
)
_EXTRAS_MISSING = {
    1: "One of the three extra protections isn't set up yet.",
    2: "Two of the three extra protections aren't set up yet.",
    3: "None of the three extra protections are set up yet.",
}
MOSTLY_FAIL_MESSAGE = (
    "Your domain has almost none of the standard email protections in place. "
    "Anyone can send email as your company right now, and nothing in your "
    "setup will catch it."
)

# Order is also "most severe" priority order within a tier — leftmost wins a tie.
CHECKS = [
    ("dmarc", "DMARC", "Is impersonation actually stopped", "core", check_dmarc),
    ("spf", "SPF", "Is your sender list still working", "core", check_spf),
    ("dkim", "DKIM", "Is your mail signed", "core", check_dkim),
    ("mta_sts", "MTA-STS", "Is incoming mail encrypted", "extra", check_mta_sts),
    ("dnssec", "DNSSEC", "Can your DNS be forged", "extra", check_dnssec),
    ("subdomains", "Subdomains", "The gap behind a pass", "extra", check_subdomains),
]

_PRIORITY = {key: index for index, (key, *_rest) in enumerate(CHECKS)}

# Completes "Right now, ___." in the partial-verdict banner, keyed by
# (check key, status). Only core checks can be featured, and only statuses
# they can actually return are listed.
BANNER_CONSEQUENCES = {
    ("dmarc", "fail"): "nothing stops someone from sending email as your company",
    ("dmarc", "warn"): "email pretending to be you is being watched, not blocked",
    ("spf", "fail"): "your sender list isn't working, so anything can claim to send as you",
    ("dkim", "fail"): "we couldn't find a signature on your mail, so nothing proves a message really came from you",
}


def run_all_checks(domain: str) -> list[dict]:
    results = []
    for key, label, headline, tier, fn in CHECKS:
        result = fn(domain)
        results.append(
            {
                "key": key,
                "label": label,
                "headline": headline,
                "tier": tier,
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
    core = [r for r in results if r["tier"] == "core"]
    extra = [r for r in results if r["tier"] == "extra"]
    core_missing = [r for r in core if r["status"] != "pass"]
    extra_missing = [r for r in extra if r["status"] != "pass"]
    counts = {
        "core_passing": len(core) - len(core_missing),
        "core_total": len(core),
        "extra_passing": len(extra) - len(extra_missing),
        "extra_total": len(extra),
    }

    if not core_missing and not extra_missing:
        return {"level": "all_pass", "message": ALL_PASS_MESSAGE, **counts}

    if not core_missing:
        message = CORE_PASS_MESSAGE.format(extras=_EXTRAS_MISSING[len(extra_missing)])
        return {"level": "core_pass", "message": message, **counts}

    if len(core_missing) == len(core):
        return {"level": "mostly_fail", "message": MOSTLY_FAIL_MESSAGE, **counts}

    worst = _most_severe(core_missing)
    consequence = BANNER_CONSEQUENCES[(worst["key"], worst["status"])]
    message = (
        f"Your domain is missing {len(core_missing)} of {len(core)} essential protections. "
        f"Right now, {consequence}. Here's what's missing and what it means."
    )
    return {"level": "partial", "message": message, **counts}

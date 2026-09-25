"""Tests for checks/runner.py's verdict logic.

Pure-function tests against synthetic result dicts — no DNS involved, since
run_all_checks() itself is just a thin wrapper around the already-tested
individual checks (covered live/mocked in their own test files).
"""

from checks.runner import BANNER_CONSEQUENCES, CHECKS, compute_verdict

_TIERS = {key: tier for key, _label, _headline, tier, _fn in CHECKS}
_CORE = [k for k, t in _TIERS.items() if t == "core"]
_EXTRA = [k for k, t in _TIERS.items() if t == "extra"]


def _results(**statuses: str) -> list[dict]:
    """All six checks passing, except the ones given as key=status."""
    return [
        {"key": key, "tier": tier, "status": statuses.get(key, "pass"), "explanation": ""}
        for key, tier in _TIERS.items()
    ]


def test_tiers_are_spf_dkim_dmarc_then_the_rest():
    assert set(_CORE) == {"dmarc", "spf", "dkim"}
    assert set(_EXTRA) == {"mta_sts", "dnssec", "subdomains"}


def test_all_pass():
    verdict = compute_verdict(_results())
    assert verdict["level"] == "all_pass"
    assert (verdict["core_passing"], verdict["extra_passing"]) == (3, 3)


def test_extras_failing_alone_is_core_pass_not_partial():
    verdict = compute_verdict(_results(mta_sts="fail", dnssec="fail"))
    assert verdict["level"] == "core_pass"
    assert verdict["message"] == (
        "The three essentials are in place, so faking email from your domain is hard. "
        "Two of the three extra protections aren't set up yet. Here's what they add."
    )
    assert (verdict["core_passing"], verdict["extra_passing"]) == (3, 1)


def test_core_pass_wording_for_one_and_three_extras_missing():
    one = compute_verdict(_results(subdomains="fail"))["message"]
    three = compute_verdict(_results(mta_sts="warn", dnssec="fail", subdomains="fail"))["message"]
    assert "One of the three extra protections isn't set up yet." in one
    assert "None of the three extra protections are set up yet." in three


def test_partial_counts_only_core_and_follows_spec_template():
    verdict = compute_verdict(_results(dmarc="warn", mta_sts="fail", dnssec="fail", subdomains="fail"))
    assert verdict["level"] == "partial"
    assert verdict["message"] == (
        "Your domain is missing 1 of 3 essential protections. Right now, email "
        "pretending to be you is being watched, not blocked. Here's what's "
        "missing and what it means."
    )
    assert (verdict["core_passing"], verdict["extra_passing"]) == (2, 0)


def test_mostly_fail_when_no_core_check_passes_even_if_extras_do():
    verdict = compute_verdict(_results(dmarc="fail", spf="fail", dkim="fail"))
    assert verdict["level"] == "mostly_fail"


def test_fail_outranks_warn_when_picking_most_severe():
    verdict = compute_verdict(_results(dmarc="warn", dkim="fail"))
    assert BANNER_CONSEQUENCES[("dkim", "fail")] in verdict["message"]
    assert BANNER_CONSEQUENCES[("dmarc", "warn")] not in verdict["message"]


def test_priority_order_breaks_ties_between_two_fails():
    verdict = compute_verdict(_results(spf="fail", dkim="fail"))
    # spf ranks above dkim in CHECKS order, so it should win the tie.
    assert BANNER_CONSEQUENCES[("spf", "fail")] in verdict["message"]
    assert BANNER_CONSEQUENCES[("dkim", "fail")] not in verdict["message"]


def test_every_core_check_has_a_banner_consequence():
    # Warn is only possible for DMARC (p=none) among the core checks.
    expected = {(key, "fail") for key in _CORE} | {("dmarc", "warn")}
    assert set(BANNER_CONSEQUENCES) == expected

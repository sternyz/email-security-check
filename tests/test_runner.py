"""Tests for checks/runner.py's verdict logic.

Pure-function tests against synthetic result dicts — no DNS involved, since
run_all_checks() itself is just a thin wrapper around the already-tested
individual checks (covered live/mocked in their own test files).
"""

from checks.runner import BANNER_CONSEQUENCES, CHECKS, compute_verdict

_ALL_KEYS = [key for key, *_rest in CHECKS]


def _result(key: str, status: str, explanation: str = "") -> dict:
    return {"key": key, "status": status, "explanation": explanation}


def test_all_pass():
    results = [_result(key, "pass") for key in _ALL_KEYS]
    verdict = compute_verdict(results)
    assert verdict["level"] == "all_pass"


def test_mostly_fail_when_five_or_more_missing():
    results = [_result(key, "fail") for key in _ALL_KEYS[:5]] + [_result(_ALL_KEYS[5], "pass")]
    verdict = compute_verdict(results)
    assert verdict["level"] == "mostly_fail"


def test_partial_reports_missing_count():
    results = [_result(key, "pass") for key in _ALL_KEYS]
    results[0] = _result(_ALL_KEYS[0], "fail", "dmarc is broken")  # dmarc
    results[3] = _result(_ALL_KEYS[3], "warn", "mta-sts is testing-only")  # mta_sts
    verdict = compute_verdict(results)
    assert verdict["level"] == "partial"
    assert verdict["missing"] == 2
    assert verdict["total"] == 6


def test_partial_message_follows_spec_template():
    results = [_result(key, "pass") for key in _ALL_KEYS]
    results[3] = _result("mta_sts", "fail")
    verdict = compute_verdict(results)
    assert verdict["message"] == (
        "Your domain is missing 1 of 6 protections. Right now, mail on its way "
        "to you can be quietly downgraded to plain text and read in transit. "
        "Here's what's missing and what it means."
    )


def test_fail_outranks_warn_when_picking_most_severe():
    results = [_result(key, "pass") for key in _ALL_KEYS]
    results[0] = _result("dmarc", "warn")
    results[3] = _result("mta_sts", "fail")
    verdict = compute_verdict(results)
    assert BANNER_CONSEQUENCES[("mta_sts", "fail")] in verdict["message"]
    assert BANNER_CONSEQUENCES[("dmarc", "warn")] not in verdict["message"]


def test_priority_order_breaks_ties_between_two_fails():
    results = [_result(key, "pass") for key in _ALL_KEYS]
    results[2] = _result("dkim", "fail")
    results[4] = _result("dnssec", "fail")
    verdict = compute_verdict(results)
    # dkim ranks above dnssec in CHECKS order, so it should win the tie.
    assert BANNER_CONSEQUENCES[("dkim", "fail")] in verdict["message"]
    assert BANNER_CONSEQUENCES[("dnssec", "fail")] not in verdict["message"]


def test_every_check_has_a_banner_consequence_for_fail():
    # Warn is only possible for DMARC (p=none) and MTA-STS (mode: testing).
    expected = {(key, "fail") for key in _ALL_KEYS} | {("dmarc", "warn"), ("mta_sts", "warn")}
    assert set(BANNER_CONSEQUENCES) == expected

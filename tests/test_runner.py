"""Tests for checks/runner.py's verdict logic.

Pure-function tests against synthetic result dicts — no DNS involved, since
run_all_checks() itself is just a thin wrapper around the already-tested
individual checks (covered live/mocked in their own test files).
"""

from checks.runner import CHECKS, compute_verdict

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


def test_fail_outranks_warn_when_picking_most_severe():
    results = [_result(key, "pass") for key in _ALL_KEYS]
    results[0] = _result("dmarc", "warn", "dmarc warn text")
    results[3] = _result("mta_sts", "fail", "mta-sts fail text")
    verdict = compute_verdict(results)
    assert "mta-sts fail text" in verdict["message"]
    assert "dmarc warn text" not in verdict["message"]


def test_priority_order_breaks_ties_between_two_fails():
    results = [_result(key, "pass") for key in _ALL_KEYS]
    results[2] = _result("dkim", "fail", "dkim fail text")
    results[4] = _result("dnssec", "fail", "dnssec fail text")
    verdict = compute_verdict(results)
    # dkim ranks above dnssec in CHECKS order, so it should win the tie.
    assert "dkim fail text" in verdict["message"]
    assert "dnssec fail text" not in verdict["message"]

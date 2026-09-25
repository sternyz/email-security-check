"""Tests for checks/dnssec.py.

All three tests hit live public DNS against real, deliberately stable
domains rather than mocking — each one is a dedicated, long-standing
fixture for exactly this purpose, so there's no live-vs-mocked tradeoff
to make here the way there was for SPF/MTA-STS:

- cloudflare.com: signed and validates (known-good).
- dnssec-failed.org: maintained specifically to have a broken DNSSEC
  signature chain (a DS record exists, but validation fails) — this is
  the standard reference domain for testing DNSSEC-validation failure.
- google.com: a long-standing, publicly documented quirk — Google has
  never published DNSSEC for google.com itself (unlike domains it hosts
  on Cloud DNS), so it's a stable real example of "no DS record at all."
"""

from checks import dnssec


def test_cloudflare_com_passes():
    result = dnssec.check_dnssec("cloudflare.com")
    assert result.status == "pass"
    assert result.raw_evidence != ""
    assert result.explanation == dnssec.PASS_EXPLANATION


def test_dnssec_failed_org_fails_validation():
    """DS record exists, but the zone's signatures don't validate."""
    result = dnssec.check_dnssec("dnssec-failed.org")
    assert result.status == "fail"
    assert result.raw_evidence != ""  # DS record was found; validation is what failed
    assert result.explanation == dnssec.FAIL_EXPLANATION


def test_google_com_fails_with_no_ds_record():
    """google.com has never published a DS record for itself."""
    result = dnssec.check_dnssec("google.com")
    assert result.status == "fail"
    assert result.raw_evidence == ""
    assert result.explanation == dnssec.FAIL_EXPLANATION

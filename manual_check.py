"""Ad hoc runner for trying the checks built so far against an arbitrary domain.

Not part of the app — Tier 2 (FastAPI + frontend) will replace this with a
real interface. Usage: python manual_check.py <domain>
"""

import sys

from checks.dkim import check_dkim
from checks.dmarc import check_dmarc
from checks.dnssec import check_dnssec
from checks.mta_sts import check_mta_sts
from checks.spf import check_spf
from checks.subdomains import check_subdomains

CHECKS = [
    ("DMARC", check_dmarc),
    ("SPF", check_spf),
    ("DKIM", check_dkim),
    ("MTA-STS", check_mta_sts),
    ("DNSSEC", check_dnssec),
    ("Subdomains", check_subdomains),
]


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python manual_check.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    for name, fn in CHECKS:
        result = fn(domain)
        print(f"{name}: {result.status}")
        print(f"  {result.explanation}")
        print(f"  evidence: {result.raw_evidence}")
        print()


if __name__ == "__main__":
    main()

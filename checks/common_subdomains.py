"""Common subdomains to probe for the "gap behind a pass" check.

Kept in one place, same pattern as checks/dkim_selectors.py — easy to
extend without touching check logic in checks/subdomains.py. Base list is
from docs/requirements.md §1, minus "www": virtually every real domain has
a live www with no SPF/DMARC of its own (nobody sends mail as
"user@www.example.com"), so including it made this check fail on nearly
every domain regardless of actual email-security posture. The remaining
three are all plausible mail-sending vectors, which is what this check is
actually trying to catch.
"""

COMMON_SUBDOMAINS = ["mail", "autodiscover", "smtp"]

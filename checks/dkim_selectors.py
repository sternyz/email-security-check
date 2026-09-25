"""Common DKIM selectors to probe.

Selectors can't be enumerated externally, so we maintain this list in one
place per CLAUDE.md conventions — easy to extend as new platforms/ESPs come
up without touching the check logic in checks/dkim.py. List and rationale
from docs/requirements.md §1.
"""

COMMON_SELECTORS = [
    "google",  # Google Workspace
    "selector1",  # Microsoft 365
    "selector2",  # Microsoft 365
    "k1",  # Common ESP selector (e.g. Mailchimp/Mandrill-style setups)
    "s1",
    "s2",
    "mandrill",
    "mailgun",
    "default",
]

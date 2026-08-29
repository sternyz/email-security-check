# Project: Email Security Checker (Factory IT)

## What this is
A lead-gen tool for Factory IT. Prospect enters a work email, we run six public DNS/email-security checks against their domain, show plain-English results, and route the lead to Growably CRM. See `docs/requirements.md` for full spec — read it before starting any work, and re-check it if a task references a section number.

## Stack
- **Backend / checks:** Python (use `dnspython` for DNS lookups; `httpx` or `requests` for the MTA-STS policy fetch over HTTPS)
- **Web framework:** FastAPI
- **Frontend:** plain HTML/JS served by FastAPI — no heavy frontend framework needed for this scope
- **Deployment:** DigitalOcean VM, same host as Profitmog. This is co-located, shared infrastructure — treat it that way (see "Deployment notes" below).

## Build order — follow this, don't skip ahead
1. Tier 1: the six checks, each in its own file under `checks/`, each independently testable
2. Tier 2: FastAPI wrapper + minimal HTML frontend
3. Tier 3: Growably CRM integration + rate limiting

Work one check at a time. For each check: implement it, write a test against a known-good domain and a known-bad/misconfigured domain, confirm both pass before moving to the next check. Don't build all six in one pass — I want reviewable diffs.

## Conventions
- Each check function returns a consistent shape: `status` (`pass` / `warn` / `fail`), `raw_evidence` (the actual DNS record(s) found, for the technical-detail view), and `explanation` (plain-English string).
- Use the exact copy from `docs/requirements.md` §1–3 for explanations and page copy as the first draft. Don't rewrite the tone — ask before changing wording, since this copy was deliberately drafted to match a specific style.
- DKIM selector probing: no way to enumerate selectors externally, so maintain a list of common selectors (Google Workspace, Microsoft 365, common ESPs) in one place, easy to extend later — don't hardcode selector strings inline in the check logic.
- SPF check must explicitly handle: no record (fail), multiple records (fail — this breaks SPF outright), and DNS lookup count over 10 (fail — record is silently non-functional per RFC 7208).
- DMARC check must distinguish `p=none` (warn — exists but doesn't block) from `p=quarantine`/`p=reject` (pass) from missing entirely (fail). Don't collapse this to a binary pass/fail.

## Deployment notes
- This shares a VM with Profitmog. Run it in its own process/container — don't install dependencies globally on the host, and don't assume you own the whole machine's resources.
- Flag anything that could affect shared VM resources (memory, open ports, background workers) before implementing it, rather than assuming it's fine.

## Integration points (details TBD — ask before assuming)
- **Growably CRM**: lead destination for captured emails. No API details yet — when you get to Tier 3, stub this behind a single function/interface so the actual API call can be swapped in once we have credentials/docs.

## Explicitly out of scope for this build
- Scheduled/recurring rechecks and regression alerts (see requirements.md §7 — this is future scope, not part of this build. Don't add scheduling infrastructure preemptively.)

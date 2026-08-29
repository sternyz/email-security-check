# Email Security Checker — Requirements

**Audience:** Cold/warm prospects (lead-gen tool, not a public utility)
**Model:** Free instant check → plain-English results → low-friction CTA → lead capture

---

## 1. The six checks (Tier 1 — core engine)

Each check returns: `status` (pass / warn / fail), `raw_evidence` (the actual DNS record(s) found), and `explanation` (plain-English string per the copy below).

### DMARC — "Is impersonation actually stopped"
- Look up `_dmarc.<domain>` TXT record.
- Parse `p=` tag: `reject`/`quarantine` → pass; `none` → warn (not fail — it exists but doesn't block); missing entirely → fail.
- Also parse `pct=` — if less than 100, note that enforcement only applies to a share of mail (downgrade pass → warn).
- Copy:
  - **Pass:** "Impersonation attempts are blocked, not just logged."
  - **Warn (p=none or partial pct):** "The rule can be missing, set to watch without blocking, or applied to only a share of messages. Watch-only is the one almost everyone assumes is finished when it is not."
  - **Fail:** "There's no rule telling receiving servers what to do with forged mail. Right now, nothing stops it."

### SPF — "Is your sender list still working"
- Look up TXT record starting with `v=spf1`.
- Count DNS lookup mechanisms (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`) recursively — RFC 7208 caps this at 10.
- Fail conditions: no SPF record; **more than one** SPF record published (breaks it outright); lookup count exceeds 10 (record silently stops working — flag as fail, not warn, since the practical effect is total failure).
- Copy:
  - **Pass:** "Your sender list is valid and under the lookup limit."
  - **Fail (over limit or duplicate):** "We count the DNS lookups your record needs. Go over ten and the whole record silently stops working, with no warning to anyone. Two records published at once breaks it outright."
  - **Fail (missing):** "There's no sender list at all — anything can claim to send as you."

### DKIM — "Is your mail signed"
- Since selectors can't be enumerated externally, probe common selectors: `google`, `selector1`, `selector2`, `k1`, `s1`, `s2`, `mandrill`, `mailgun`, `default`, plus provider-specific ones inferred from MX (e.g., Google Workspace, Microsoft 365).
- Pass if any known selector resolves to a valid public key TXT record.
- Copy:
  - **Pass:** "A signature proves a message really came from you and wasn't altered on the way."
  - **Fail:** "We couldn't find a signature using the selectors common platforms use. Without one, there's no way to verify a message claiming to be from you actually is."

### MTA-STS — "Is incoming mail encrypted"
- Look up `_mta-sts.<domain>` TXT record and fetch the policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
- Pass if both exist and policy mode is `enforce`; warn if mode is `testing`; fail if missing.
- Copy:
  - **Pass:** "Incoming mail is protected — it can't be silently downgraded and intercepted in transit."
  - **Fail:** "Without it, mail on its way to you can be quietly downgraded to plain text and read in transit."

### DNSSEC — "Can your DNS be forged"
- Check for a signed chain of trust (DS record at the registrar + RRSIG on the zone).
- Pass if fully signed and validating; fail if absent.
- Copy:
  - **Pass:** "DNS answers for your domain are signed and can't be tampered with in transit."
  - **Fail:** "Signed DNS answers cannot be tampered with between the lookup and the answer. Unsigned ones can."

### Subdomains — "The gap behind a pass"
- Enumerate common subdomains (`mail`, `www`, `autodiscover`, `smtp`, plus any found in MX/SPF includes) and re-run SPF/DMARC checks against them.
- Fail if the root domain passes but a live subdomain has no SPF/DMARC of its own.
- Copy:
  - **Pass:** "Your subdomains are covered too — no gap behind the main domain."
  - **Fail:** "A domain can be locked down while every subdomain stays wide open. It reads as protected and is not, which is why this one is worth checking separately."

---

## 2. Landing page copy (Tier 2)

**Headline:**
> Can someone send an email pretending to be you?

**Sub-copy:**
> Enter your work email. We check the public records that decide two things: whether anyone can send email as you, and whether your own email is trusted everywhere it lands. Every result explained in plain English, with the full technical detail underneath. Free, no signup.

**Input:** `you@yourcompany.com` → **Check My Domain**
**Microcopy below button:** *Takes about five seconds. We only read public DNS records — nothing private.*

*(Note: input is a work email, not a bare domain — this is a deliberate lead-capture move. Domain is parsed from the email for the check; the email itself is the lead.)*

---

## 3. Results page

### Overall verdict banner
- **All pass:** "Your domain passes all six checks. Someone is doing their job here — this is what good looks like."
- **Partial (most common):** "Your domain is missing [N] of 6 protections. Right now, [most severe fail's consequence]. Here's what's missing and what it means."
- **Mostly/all fail:** "Your domain has almost none of the standard email protections in place. Anyone can send email as your company right now, and nothing in your setup will catch it."

### Card layout (per check)
`[CATEGORY LABEL]` → plain-language question as headline → one paragraph explaining the failure mode (not the fix — the fix lives in the CTA, not the card).

### Closing CTA (below all six cards)
> None of this is complicated to fix. Most of it is a handful of DNS records — the kind of thing that should already be handled for you.
>
> Want us to walk you through fixing what's missing? No cost, no pitch — just send us this report and we'll tell you exactly what to change.

`[ Email me this report ]`   `[ Have someone walk me through it ]`

---

## 4. Hands-Off IT Management positioning (for homepage / post-results tie-in)

> **Hands-Off IT Management**
>
> We handle every problem with your technology — so you don't have to.
>
> Stop running around trying to figure out why something broke, how to connect your systems, or which tool is the right one. That's our job now, not yours.
>
> The average business owner spends hours every month on IT admin, software decisions, or putting out technical fires. You don't need to spend a single one of them.

*(Note: soften or replace the "15 hours/month" stat unless we have our own data to back it — an unsourced number is the kind of thing a skeptical prospect pokes at.)*

Suggested placement: directly after the results page CTA, framed as the payoff — e.g. *"This is what hands-off looks like. We'd have caught the missing DMARC enforcement before you ever had to think about it."*

---

## 5. Build order (for Claude Code sessions)

1. **Tier 1 core engine** — one file per check (`checks/dmarc.py`, `checks/spf.py`, etc.), each independently testable against a known-good and known-bad domain. Build and test one check at a time, not all six in one pass.
2. **Tier 2 web front end** — input → results, using the copy above verbatim as the initial draft (tune later against real results).
3. **Tier 3 lead capture** — email report delivery, CRM/HaloPSA hook, rate limiting.

## 6. Decisions

- **Hosting:** Subdomain of factoryinfotech.com, hosted on the same DigitalOcean VM as Profitmog.
- **Lead destination:** Growably CRM.
- **Scope:** One-off checks only for this build — no recurring/scheduled rechecks.

## 7. Future scope (not this build)

- **Monthly recheck / regression alerts** — re-run the six checks on a schedule per lead/client and flag when something that used to pass starts failing (e.g., DMARC quietly reverted to `p=none`, SPF record edited past the lookup limit). This is a meaningfully bigger scope than Tier 1–3: needs a scheduler, persistent storage per domain, and a notification path (email/Growably). Worth revisiting as a paid add-on or ongoing-monitoring upsell once the core tool is live and generating leads.

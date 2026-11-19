# Changelog

## 0.2.0 — 2026-11-19

- `dns_audit.py`: SPF parsing with lookup and void-count limits, DMARC tag validation, MTA-STS,
  TLS-RPT and BIMI checks
- `dns_audit.py`: `--selectors google,selector1` checks several DKIM selectors in one run;
  `--dkim-selector` remains for a single selector
- `dns_audit.py`: exit code `1` when SPF is missing or invalid, DMARC is missing or `p=none`,
  or the domain publishes a null MX — so the audit can gate a deploy or a monitoring check
- revoked DKIM keys (`p=` empty) are reported as revoked, not as configured
- test suites for both tools (50 tests), run by GitHub Actions on Python 3.9, 3.11 and 3.13

## 0.1.0 — 2026-11-19

- initial release: `verify_email.py` (syntax, MX, SMTP RCPT, same-session catch-all probe) and
  `dns_audit.py` (MX, SPF, DMARC, DKIM)

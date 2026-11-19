# email-audit

Two small tools for checking whether an email address or a domain can actually receive mail —
without a paid verification API.

- `verify_email.py` — mailbox-level check: syntax, MX, `RCPT TO`, and a catch-all probe.
- `dns_audit.py` — domain-level posture: MX, SPF, DMARC and DKIM on common selectors.

No Python packages, no API keys. Only `dig` (`bind9-dnsutils` on Debian/Ubuntu, `bind-utils` on Fedora).

## Why

Most "email verifier" tools return one of two answers: valid or invalid. The interesting case is the
third one — **catch-all**. A domain that accepts every address answers `250` to a random recipient,
so mailbox existence cannot be confirmed by SMTP at all. Tools that report those as "verified" are
the reason cold-outreach lists bounce at 10–20 %.

`verify_email.py` reports catch-all as catch-all and never upgrades it, and `accepted` is only
returned when the random probe was rejected **and** the real address was accepted in the same SMTP
session.

## Usage

```bash
python3 verify_email.py info@example.com
# info@example.com -> accepted
```

```bash
python3 verify_email.py --csv contacts.csv --column business_email > results.csv
# writes: email,status,detail,mx
```

```bash
python3 dns_audit.py example.com
```

```
example.com
  MX         none
  SPF        present, policy '-'
  DMARC      present, policy 'reject'
  DKIM       no key on common selectors
```

`--json` on both tools gives machine-readable output.

## What the results mean

| Status | Meaning |
| --- | --- |
| `accepted` | Probe rejected, real address accepted, same session |
| `rejected` | The server says the mailbox does not exist |
| `catch-all` | The domain accepts every address — not verifiable |
| `greylisted` | Temporary rejection, retry later |
| `no-mx` | No mail server, or a null MX (`0 .`) |
| `unconfirmed` | Server answered something ambiguous (`252`, odd codes) |
| `invalid-syntax` | Fails length, local-part or label rules |

For `dns_audit.py`: SPF `-all` is strict, `~all` is soft-fail, `+all` means anyone can send as the
domain. DMARC `p=none` only reports, `p=quarantine` and `p=reject` enforce.

## Limits (read this before trusting the output)

- **Catch-all domains cannot be verified** by SMTP. No tool can, including the paid ones.
- **DKIM selector names are arbitrary.** The audit checks `default`, `google`, `selector1`,
  `selector2`, `k1`, `s1`, `dkim`, `mail`. A domain using `20161025._domainkey` will show
  "no key on common selectors" even though DKIM works — the selector comes from the mail headers
  or the provider's documentation.
- A record like `v=DKIM1; p=` is a **revoked** key and is reported as such, not as configured.
- `accepted` means the server accepted the recipient at that moment. Delivery can still fail later.
- Port 25 must be open outbound. Many VPS and residential ISPs block it.
- Large batches get rate-limited or greylisted. Probe each domain once, pace the rest, and respect
  the receiving server's limits.

## Responsible use

This is for checking your own lists before sending, not for harvesting addresses or probing servers
at volume. Bulk SMTP probing is abusive and will get your IP blocked. Only check addresses you have
a lawful basis to contact, and follow the rules for commercial email in the recipient's country.

## License

MIT — see [LICENSE](LICENSE).

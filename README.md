# email-audit

Two small tools for checking whether an email address or a domain can actually receive mail —
without a paid verification API.

- `verify_email.py` — mailbox-level check: syntax, MX, `RCPT TO`, and a catch-all probe.
- `dns_audit.py` — domain-level posture: MX, SPF, DMARC, MTA-STS, TLS-RPT, BIMI, and DKIM when you pass a selector.

No Python packages, no API keys. Only `dig` (`bind9-dnsutils` on Debian/Ubuntu, `bind-utils` on Fedora).

## Why

Most "email verifier" tools return one of two answers: valid or invalid. The interesting case is the
third one — **catch-all**. A domain that accepts every address answers `250` to a random recipient,
so mailbox existence cannot be confirmed by SMTP at all. Tools that report those as "verified" are
the reason cold-outreach lists bounce at 10–20 %.

`verify_email.py` reports catch-all as catch-all and never upgrades it, and `accepted` is only
returned when the random probe was rejected as a nonexistent mailbox **and** the real address was
accepted in the same SMTP session.

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
python3 dns_audit.py --json example.com
python3 dns_audit.py --dkim-selector s1 example.com
```

`--json` is on `dns_audit.py` only.

## What the results mean

| Status | Meaning |
| --- | --- |
| `accepted` | Probe was refused as a nonexistent mailbox, real address accepted (`250`/`251`), same session |
| `rejected` | The server says the mailbox does not exist |
| `catch-all` | The domain accepts every address — not verifiable |
| `full-inbox` | Probe was refused, real mailbox is over quota (`552` or a full-inbox reply) |
| `disabled` | Probe was refused, real mailbox is disabled |
| `blocked` | Policy or DNSBL block. Not proof the mailbox is missing, and not accepted |
| `greylisted` | Temporary rejection, retry later |
| `no-mx` | No mail server, or a null MX (`0 .`) |
| `unconfirmed` | Ambiguous answer (`252`, relay/policy `554`, quota on the random probe) |
| `invalid-syntax` | Fails length, local-part or label rules |
| `unreachable` | DNS or SMTP transport failed |

A `4xx` is never stored as `rejected` or `accepted`. A block, a full probe mailbox, or a disabled
probe does not open an `accepted` result. Role names (`postmaster`, `abuse`, `hostmaster`,
`webmaster`, `noc`, `security`, `admin`, `administrator`, `root`) are noted in `detail` and do not
change the status.

For `dns_audit.py`: SPF `-all` is strict, `~all` is soft-fail, `+all` means anyone can send as the
domain. No `all` mechanism leaves the policy blank — it is not reported as `+all`. More than 10 SPF
DNS lookups, or more than 2 void lookups, is an error (RFC 7208). DMARC `p=none` only reports,
`p=quarantine` and `p=reject` enforce. A missing `p` tag is warned, not filled in. BIMI is read
only at `default._bimi`. DKIM is not queried unless `--dkim-selector` is set.

## Limits (read this before trusting the output)

- **Catch-all domains cannot be verified** by SMTP. No tool can, including the paid ones.
- **DKIM selector names are arbitrary.** This tool does not guess them. Pass the selector from the
  message headers or the provider's documentation: `--dkim-selector s1`.
- A record like `v=DKIM1; p=` is a **revoked** key and is reported as such, not as configured.
- MTA-STS policy text is fetched only when a `_mta-sts` TXT record exists. A failed fetch leaves
  `mode` empty.
- BIMI logos and mark certificates are not downloaded. TLS-RPT `rua` URLs are not fetched.
- There is no public-suffix list, so DMARC is not walked up to an organizational domain, and an
  external `rua` destination is warned, not verified.
- `accepted` means the server accepted the recipient at that moment. Delivery can still fail later.
- Port 25 must be open outbound. Many VPS and residential ISPs block it.
- Large batches get rate-limited or greylisted. Probe each domain once, pace the rest, and respect
  the receiving server's limits. The tool does not retry the same host to slip past a greylist.

## Responsible use

This is for checking your own lists before sending, not for harvesting addresses or probing servers
at volume. Bulk SMTP probing is abusive and will get your IP blocked. Only check addresses you have
a lawful basis to contact, and follow the rules for commercial email in the recipient's country.

## License

MIT — see [LICENSE](LICENSE).

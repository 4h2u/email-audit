#!/usr/bin/env python3
"""DNS email-posture audit: MX, SPF, DMARC and DKIM selectors for one or more domains.

Usage:
    python3 dns_audit.py example.com [example2.com ...]
    python3 dns_audit.py --json example.com

Requires `dig` (bind9-dnsutils / bind-utils). No third-party Python packages.
"""
import argparse
import json
import re
import subprocess
import sys

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "dkim", "mail")
TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|\S+')


def dig(kind, name):
    """Return the dig answers as a list of strings, or None if dig itself failed."""
    try:
        proc = subprocess.run(["dig", "+short", kind, name], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def txt(name):
    """TXT records, with the surrounding quotes removed."""
    out = []
    for line in dig("TXT", name) or []:
        parts = TOKEN.findall(line)
        out.append("".join(p[1:-1] if p.startswith('"') else p for p in parts))
    return out


def spf(domain):
    for record in txt(domain):
        if record.lower().startswith("v=spf1"):
            mechanisms = record.split()[1:]
            all_value = next((m for m in mechanisms if m.lower().lstrip("-~+?").startswith("all")), "")
            includes = [m for m in mechanisms if m.lower().startswith("include:")]
            dns_lookups = len(includes) + sum(1 for m in mechanisms if m.lower().startswith(("a", "mx", "ptr", "exists")))
            return {
                "record": record,
                "policy": all_value[:1] or "+",
                "dns_lookups_estimate": dns_lookups,
                "lookup_limit_risk": dns_lookups > 8,
            }
    return None


def dmarc(domain):
    for record in txt(f"_dmarc.{domain}"):
        if record.lower().startswith("v=dmarc1"):
            tags = dict(
                part.split("=", 1) for part in record.split(";") if "=" in part
            )
            tags = {k.strip().lower(): v.strip() for k, v in tags.items()}
            return {"record": record, "policy": tags.get("p", ""), "rua": tags.get("rua", ""), "pct": tags.get("pct", "")}
    return None


def dkim(domain):
    """Selectors that publish a non-empty public key.

    A record like "v=DKIM1; p=" means the key was revoked: it verifies nothing,
    so it must not count as DKIM being configured.
    """
    found = []
    for selector in DKIM_SELECTORS:
        for record in txt(f"{selector}._domainkey.{domain}"):
            match = re.search(r"\bp=([A-Za-z0-9+/=]+)", record)
            if not match:
                continue
            if not match.group(1):
                found.append({"selector": selector, "has_key": False, "revoked": True})
            else:
                found.append({"selector": selector, "has_key": True, "revoked": False})
            break
    return found


def audit(domain):
    mx = dig("MX", domain) or []
    return {
        "domain": domain,
        "mx": [line.split()[-1].rstrip(".") for line in mx if " " in line],
        "spf": spf(domain),
        "dmarc": dmarc(domain),
        "dkim": dkim(domain),
    }


def line(label, value):
    print(f"  {label:<10} {value}")


def report(result):
    print(f"\n{result['domain']}")
    line("MX", ", ".join(result["mx"]) or "none")
    spf_result = result["spf"]
    if spf_result:
        risk = " (over 8 DNS lookups)" if spf_result["lookup_limit_risk"] else ""
        line("SPF", f"present, policy '{spf_result['policy']}'{risk}")
    else:
        line("SPF", "MISSING - mail from this domain can be forged")
    dmarc_result = result["dmarc"]
    if dmarc_result:
        line("DMARC", f"present, policy '{dmarc_result['policy']}'")
    else:
        line("DMARC", "MISSING - no instruction to receivers on failure")
    live = [item["selector"] for item in result["dkim"] if item["has_key"]]
    revoked = [item["selector"] for item in result["dkim"] if not item["has_key"]]
    if live:
        line("DKIM", ", ".join(live))
    elif revoked:
        line("DKIM", f"revoked key on {', '.join(revoked)} (p= is empty)")
    else:
        line("DKIM", "no key on common selectors")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="dns_audit.py")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a report")
    parser.add_argument("domains", nargs="+")
    args = parser.parse_args(argv)
    results = [audit(domain.strip()) for domain in args.domains]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            report(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())

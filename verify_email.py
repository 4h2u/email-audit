#!/usr/bin/env python3
"""Syntax, MX, and SMTP RCPT check with a same-session catch-all probe.

accepted is returned only when the catch-all probe on that SMTP session got
550/551/552/553/554 and the real RCPT got 250 or 251.
"""
import argparse
import csv
import random
import re
import smtplib
import socket
import string
import subprocess
import sys

TEMP = frozenset((421, 450, 451, 452))
REJECT = frozenset((550, 551, 552, 553, 554))
CATCHALL = frozenset((250, 251, 252))
ACCEPT = frozenset((250, 251))

_LOCAL_RE = re.compile(r"[A-Za-z0-9_+-]+(?:\.[A-Za-z0-9_+-]+)*")
_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def valid_syntax(email):
    if not isinstance(email, str) or len(email) > 254 or email.count("@") != 1:
        return False
    local, domain = email.split("@", 1)
    if not local or len(local) > 64 or not _LOCAL_RE.fullmatch(local):
        return False
    if ".." in local or local.startswith(".") or local.endswith("."):
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    return all(_LABEL_RE.fullmatch(label) is not None for label in labels)


def parse_mx(text):
    """Parse `dig +short MX` text into preference-sorted (pref, host) pairs.

    None means a null MX (`0 .` or exchange `.`) is present. An empty list
    means no MX lines, so the caller may fall back to an A record.
    """
    rows = []
    null = False
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            pref = int(parts[0])
        except ValueError:
            continue
        exchange = parts[1]
        if exchange == "." or exchange.rstrip(".") == "":
            null = True
            continue
        rows.append((pref, exchange.rstrip(".")))
    if null:
        return None
    rows.sort(key=lambda item: item[0])
    return rows


def first_ipv4(text):
    for line in (text or "").splitlines():
        tok = line.strip().rstrip(".")
        if _IPV4_RE.fullmatch(tok):
            return tok
    return None


def targets_from_lookup(mx_text, a_text=""):
    """Hosts to try, or None when a null MX forbids A-record fallback.

    Empty MX text is the only case that consults a_text. Existing MX lines
    are returned sorted and a_text is ignored.
    """
    parsed = parse_mx(mx_text)
    if parsed is None:
        return None
    if parsed:
        return parsed
    ip = first_ipv4(a_text)
    if not ip:
        return []
    return [(0, ip)]


def _temp(code):
    return code in TEMP or (isinstance(code, int) and 400 <= code <= 499)


def _reject(code):
    return code in REJECT or (isinstance(code, int) and 500 <= code <= 599)


def decide(probe, real):
    """Map one host's probe/real RCPT codes to a status. None is transport."""
    if probe is None:
        return "unreachable"
    if probe in CATCHALL:
        return "catch-all"
    if _temp(probe):
        return "greylisted"
    if not _reject(probe):
        return "unconfirmed"
    if real is None:
        return "unreachable"
    if real in ACCEPT:
        return "accepted"
    if real == 252:
        return "unconfirmed"
    if _reject(real):
        return "rejected"
    if _temp(real):
        return "greylisted"
    return "unconfirmed"


def _client_name():
    fqdn = socket.getfqdn() or ""
    low = fqdn.lower().rstrip(".")
    if "." in fqdn and low != "localhost" and not low.startswith("localhost."):
        return fqdn
    return (socket.gethostname() or "localhost") + ".local"


def _dig(kind, name):
    try:
        proc = subprocess.run(
            ["dig", "+short", kind, name],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout or ""


def _close(smtp):
    try:
        smtp.close()
    except Exception:
        pass


def _starttls(smtp, tls):
    if tls["tried"]:
        return False
    tls["tried"] = True
    try:
        smtp.starttls()
        smtp.ehlo(_client_name())
    except Exception:
        return False
    return True


def _mail(smtp, tls):
    try:
        code, _ = smtp.mail("")
    except Exception:
        return None
    if code == 530 and _starttls(smtp, tls):
        try:
            code, _ = smtp.mail("")
        except Exception:
            return None
    elif code == 530:
        return None
    return code


def _rcpt(smtp, address, tls):
    try:
        code, _ = smtp.rcpt(address)
    except Exception:
        return None
    if code != 530:
        return code
    if not _starttls(smtp, tls):
        return None
    try:
        mail_code, _ = smtp.mail("")
    except Exception:
        return None
    if mail_code != 250:
        return None
    try:
        code, _ = smtp.rcpt(address)
    except Exception:
        return None
    return code


def _detail(probe, real, implicit):
    parts = []
    if implicit:
        parts.append("implicit-a")
    if probe is not None:
        parts.append(f"probe={probe}")
    if real is not None:
        parts.append(f"real={real}")
    return " ".join(parts)


def _probe_address(domain):
    local = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
    return f"{local}@{domain}"


def _session(host, domain, emails, implicit):
    """One connection. Returns (done, retry, saw_greylist)."""
    name = _client_name()
    smtp = smtplib.SMTP(timeout=8, local_hostname=name)
    done = {}
    retry = list(emails)
    saw_grey = False
    try:
        smtp.connect(host, 25)
        smtp.ehlo(name)
        tls = {"tried": False}
        mail_code = _mail(smtp, tls)
        if mail_code is None:
            return done, retry, saw_grey
        if mail_code != 250:
            return done, retry, saw_grey
        probe_code = _rcpt(smtp, _probe_address(domain), tls)
        if probe_code is None:
            return done, retry, saw_grey
        gate = decide(probe_code, None)
        if gate == "catch-all":
            for email in emails:
                done[email] = ("catch-all", _detail(probe_code, None, implicit), host)
            return done, [], saw_grey
        if gate == "greylisted":
            return done, list(emails), True
        if gate == "rejected":
            for email in emails:
                done[email] = ("rejected", _detail(probe_code, None, implicit), host)
            return done, [], saw_grey
        if gate != "unreachable":
            for email in emails:
                done[email] = (gate, _detail(probe_code, None, implicit), host)
            return done, [], saw_grey
        # Exact REJECT probe: decide(probe, None) is unreachable until real RCPT.
        retry = []
        for index, email in enumerate(emails):
            try:
                smtp.rset()
            except Exception:
                return done, emails[index:], saw_grey
            mail_code = _mail(smtp, tls)
            if mail_code is None or mail_code != 250:
                return done, emails[index:], saw_grey
            real = _rcpt(smtp, email, tls)
            if real is None:
                return done, emails[index:], saw_grey
            status = decide(probe_code, real)
            if status in ("greylisted", "unreachable"):
                saw_grey = saw_grey or status == "greylisted"
                retry.append(email)
                continue
            done[email] = (status, _detail(probe_code, real, implicit), host)
        return done, retry, saw_grey
    except Exception:
        return done, retry, saw_grey
    finally:
        _close(smtp)


def _check_domain(domain, emails):
    mx_text = _dig("MX", domain)
    if mx_text is None:
        return {email: ("unreachable", "dig", "") for email in emails}
    parsed = parse_mx(mx_text)
    if parsed is None:
        return {email: ("no-mx", "null-mx", "") for email in emails}
    implicit = False
    hosts = parsed[:3]
    if not hosts:
        a_text = _dig("A", domain)
        if a_text is None:
            return {email: ("unreachable", "dig", "") for email in emails}
        ip = first_ipv4(a_text)
        if not ip:
            return {email: ("no-mx", "no-mx", "") for email in emails}
        hosts = [(0, ip)]
        implicit = True
    pending = list(emails)
    done = {}
    saw_grey = False
    grey_mx = ""
    grey_detail = "implicit-a" if implicit else "greylist"
    for _pref, host in hosts:
        if not pending:
            break
        newly, pending, grey = _session(host, domain, pending, implicit)
        done.update(newly)
        if grey:
            saw_grey = True
            grey_mx = host
            grey_detail = "implicit-a greylist" if implicit else "greylist"
    for email in pending:
        if saw_grey:
            done[email] = ("greylisted", grey_detail, grey_mx)
        else:
            detail = "implicit-a transport" if implicit else "transport"
            done[email] = ("unreachable", detail, "")
    return done


def verify_all(emails):
    """Verify emails, probing each domain once and reusing that session."""
    groups = {}
    order = []
    cleaned = []
    for raw in emails:
        text = raw.strip() if isinstance(raw, str) else ""
        cleaned.append(text)
        if not valid_syntax(text):
            continue
        domain = text.split("@", 1)[1].lower()
        if domain not in groups:
            order.append(domain)
            groups[domain] = []
        groups[domain].append(text)
    cache = {}
    for domain in order:
        unique = list(dict.fromkeys(groups[domain]))
        cache.update(_check_domain(domain, unique))
    out = []
    for raw, text in zip(emails, cleaned):
        if not valid_syntax(text):
            out.append((raw, "invalid-syntax", "syntax", ""))
        else:
            status, detail, mx = cache[text]
            out.append((raw, status, detail, mx))
    return out


def verify(email):
    return verify_all([email])[0][1]


def _run_csv(path, column):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        if column not in fieldnames:
            print(f"column not found: {column}", file=sys.stderr)
            sys.exit(2)
        rows = [row.get(column) or "" for row in reader]
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(["email", "status", "detail", "mx"])
    for raw, status, detail, mx in verify_all(rows):
        writer.writerow([raw.strip() if isinstance(raw, str) else raw, status, detail, mx])


def main(argv=None):
    parser = argparse.ArgumentParser(prog="verify_email.py")
    parser.add_argument("--csv", metavar="PATH")
    parser.add_argument("--column", default="business_email")
    parser.add_argument("emails", nargs="*")
    args = parser.parse_args(argv)
    if args.csv:
        _run_csv(args.csv, args.column)
        return 0
    if not args.emails:
        parser.error("email required")
    for raw, status, _detail, _mx in verify_all(args.emails):
        print(f"{raw} -> {status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

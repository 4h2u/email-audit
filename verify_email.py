#!/usr/bin/env python3
"""Syntax, MX, and SMTP RCPT check with a same-session catch-all probe.

accepted is returned only when the random probe was refused as a nonexistent
mailbox and the real RCPT was accepted (250 or 251) in the same SMTP session.
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

_LOCAL_RE = re.compile(r"[A-Za-z0-9_+-]+(?:\.[A-Za-z0-9_+-]+)*")
_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_ENHANCED_RE = re.compile(r"\b([245])\.(\d{1,3})\.(\d{1,3})\b")
_DISABLED_WORD = re.compile(r"\b(?:disabled|discontinued|inactive)\b")

_BLOCK_KEYWORDS = (
    "spamhaus",
    "proofpoint",
    "cloudmark",
    "blacklist",
    "blacklisted",
    "block list",
    "blocklist",
    "dnsbl",
    "abusix",
    "poor reputation",
    "junkmail",
    "sbrs",
    "banned",
)
_FULL_PHRASES = (
    "mailbox full",
    "over quota",
    "quota exceeded",
    "insufficient storage",
    "out of storage",
    "too many messages",
)
_UNKNOWN_PHRASES = (
    "does not exist",
    "user unknown",
    "user not found",
    "no such user",
    "mailbox not found",
    "no mailbox",
    "recipient invalid",
    "invalid address",
    "no such recipient",
    "unknown user",
    "undeliverable",
    "may not exist",
    "unable to verify user",
)
# RFC 2142 names plus admin/administrator/root; not a deliverability result.
_ROLES = frozenset((
    "postmaster",
    "abuse",
    "hostmaster",
    "webmaster",
    "noc",
    "security",
    "admin",
    "administrator",
    "root",
))


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


def _as_text(message):
    if message is None:
        return ""
    if isinstance(message, bytes):
        return message.decode("utf-8", "replace")
    if isinstance(message, str):
        return message
    if isinstance(message, (list, tuple)):
        return " ".join(_as_text(item) for item in message)
    return str(message)


def _enhanced(text):
    found = []
    for match in _ENHANCED_RE.finditer(text or ""):
        found.append((int(match.group(1)), int(match.group(2)), int(match.group(3))))
    return found


def classify_reply(code, text=""):
    """Classify one SMTP reply. Text is matched case-insensitively."""
    if not isinstance(code, int) or isinstance(code, bool):
        return "unconfirmed"
    lowered = _as_text(text).lower()
    if code >= 400:
        if any(word in lowered for word in _BLOCK_KEYWORDS):
            return "blocked"
        enhanced = _enhanced(lowered)
        if (
            code == 552
            or any(phrase in lowered for phrase in _FULL_PHRASES)
            or any(subject == 2 and detail == 2 for _cls, subject, detail in enhanced)
        ):
            return "full-inbox"
        if 500 <= code <= 599 and any(phrase in lowered for phrase in _UNKNOWN_PHRASES):
            return "rejected"
        if any(subject == 2 and detail == 1 for _cls, subject, detail in enhanced):
            return "disabled"
        if 500 <= code <= 599 and _DISABLED_WORD.search(lowered):
            return "disabled"
        if any(cls == 5 and subject == 7 for cls, subject, _detail in enhanced):
            return "blocked"
        if code == 550 or any(
            cls == 5 and subject == 1 and detail in (0, 1)
            for cls, subject, detail in enhanced
        ):
            return "rejected"
        if 500 <= code <= 599:
            return "unconfirmed"
        if 400 <= code <= 499:
            return "greylisted"
        return "unconfirmed"
    if code in (250, 251):
        return "positive"
    if code == 252:
        return "ambiguous"
    return "unconfirmed"


def is_role(local):
    if not isinstance(local, str):
        return False
    return local.lower() in _ROLES


def _annotate(email, detail):
    local = ""
    if isinstance(email, str) and "@" in email:
        local = email.split("@", 1)[0]
    if not is_role(local):
        return detail
    if detail:
        return detail + " role"
    return "role"


def _row(email, status, detail, mx):
    return (status, _annotate(email, detail), mx)


def _leftover(saw_blocked, saw_grey):
    if saw_blocked:
        return "blocked"
    if saw_grey:
        return "greylisted"
    return "unreachable"


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
        code, message = smtp.rcpt(address)
    except Exception:
        return None, ""
    if code != 530:
        return code, _as_text(message)
    if not _starttls(smtp, tls):
        return None, ""
    try:
        mail_code, _ = smtp.mail("")
    except Exception:
        return None, ""
    if mail_code != 250:
        return None, ""
    try:
        code, message = smtp.rcpt(address)
    except Exception:
        return None, ""
    return code, _as_text(message)


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


def _real_status(kind):
    if kind == "positive":
        return "accepted"
    if kind == "full-inbox":
        return "full-inbox"
    if kind == "disabled":
        return "disabled"
    if kind == "rejected":
        return "rejected"
    return "unconfirmed"


def _unfinished(emails, done, retry):
    seen = set(done)
    seen.update(retry)
    missing = [email for email in emails if email not in seen]
    if not missing:
        return retry
    return list(retry) + missing


def _dialogue(smtp, domain, emails, implicit, host=""):
    """MAIL/RCPT on an open session.

    Returns (done, retry, saw_blocked, saw_grey). done maps an address to
    (status, detail, host). Blocked, greylisted, and transport failures stay
    in retry for the next MX.
    """
    done = {}
    retry = list(emails)
    saw_blocked = False
    saw_grey = False
    try:
        tls = {"tried": False}
        mail_code = _mail(smtp, tls)
        if mail_code is None or mail_code != 250:
            return done, retry, saw_blocked, saw_grey
        probe_code, probe_text = _rcpt(smtp, _probe_address(domain), tls)
        if probe_code is None:
            return done, retry, saw_blocked, saw_grey
        kind = classify_reply(probe_code, probe_text)
        detail = _detail(probe_code, None, implicit)
        if kind in ("positive", "ambiguous"):
            for email in emails:
                done[email] = _row(email, "catch-all", detail, host)
            return done, [], saw_blocked, saw_grey
        if kind == "blocked":
            return done, list(emails), True, saw_grey
        if kind == "greylisted":
            return done, list(emails), saw_blocked, True
        if kind != "rejected":
            for email in emails:
                done[email] = _row(email, "unconfirmed", detail, host)
            return done, [], saw_blocked, saw_grey
        retry = []
        for index, email in enumerate(emails):
            try:
                smtp.rset()
            except Exception:
                return done, emails[index:], saw_blocked, saw_grey
            mail_code = _mail(smtp, tls)
            if mail_code is None or mail_code != 250:
                return done, emails[index:], saw_blocked, saw_grey
            real_code, real_text = _rcpt(smtp, email, tls)
            if real_code is None:
                return done, emails[index:], saw_blocked, saw_grey
            real_kind = classify_reply(real_code, real_text)
            if real_kind == "blocked":
                saw_blocked = True
                retry.append(email)
                continue
            if real_kind == "greylisted":
                saw_grey = True
                retry.append(email)
                continue
            done[email] = _row(
                email,
                _real_status(real_kind),
                _detail(probe_code, real_code, implicit),
                host,
            )
        return done, retry, saw_blocked, saw_grey
    except Exception:
        return done, _unfinished(emails, done, retry), saw_blocked, saw_grey


def _session(host, domain, emails, implicit):
    """One connection. Returns (done, retry, saw_blocked, saw_grey)."""
    name = _client_name()
    smtp = smtplib.SMTP(timeout=8, local_hostname=name)
    try:
        smtp.connect(host, 25)
        smtp.ehlo(name)
        return _dialogue(smtp, domain, emails, implicit, host)
    except Exception:
        return {}, list(emails), False, False
    finally:
        _close(smtp)


def _check_domain(domain, emails):
    mx_text = _dig("MX", domain)
    if mx_text is None:
        return {email: _row(email, "unreachable", "dig", "") for email in emails}
    parsed = parse_mx(mx_text)
    if parsed is None:
        return {email: _row(email, "no-mx", "null-mx", "") for email in emails}
    implicit = False
    hosts = parsed[:3]
    if not hosts:
        a_text = _dig("A", domain)
        if a_text is None:
            return {email: _row(email, "unreachable", "dig", "") for email in emails}
        ip = first_ipv4(a_text)
        if not ip:
            return {email: _row(email, "no-mx", "no-mx", "") for email in emails}
        hosts = [(0, ip)]
        implicit = True
    pending = list(emails)
    done = {}
    saw_grey = False
    saw_blocked = False
    grey_mx = ""
    blocked_mx = ""
    for _pref, host in hosts:
        if not pending:
            break
        newly, pending, blocked, grey = _session(host, domain, pending, implicit)
        done.update(newly)
        if blocked:
            saw_blocked = True
            blocked_mx = host
        if grey:
            saw_grey = True
            grey_mx = host
    status = _leftover(saw_blocked, saw_grey)
    if status == "blocked":
        detail = "implicit-a blocked" if implicit else "blocked"
        mx = blocked_mx
    elif status == "greylisted":
        detail = "implicit-a greylist" if implicit else "greylist"
        mx = grey_mx
    else:
        detail = "implicit-a transport" if implicit else "transport"
        mx = ""
    for email in pending:
        done[email] = _row(email, status, detail, mx)
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
            out.append((raw, "invalid-syntax", _annotate(text, "syntax"), ""))
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

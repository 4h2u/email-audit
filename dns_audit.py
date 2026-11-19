#!/usr/bin/env python3
"""DNS posture audit for one mail domain. Stdlib and dig only.

Rules follow the public behavior of domainaware/checkdmarc (SPF lookup and
void limits, DMARC tag warnings, null MX, MTA-STS, TLS-RPT, BIMI). This is
a reimplementation, not a copy. No DKIM selector is guessed.
"""

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request

TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|\S+')
SPF_LOOKUP_LIMIT = 10
SPF_VOID_LIMIT = 2
MTA_STS_MAX_AGE = 31557600
COUNTED = {"include", "a", "mx", "ptr", "exists", "redirect"}
DMARC_REMOVED = ("pct", "rf", "ri")
DMARC_POLICIES = {"none", "quarantine", "reject"}


def dig(kind, name):
    """Return raw dig +short lines, [] when dig answers empty, None on failure."""
    try:
        done = subprocess.run(
            ["dig", "+short", "+time=5", "+tries=1", kind, name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0:
        return None
    return [line.strip() for line in done.stdout.splitlines() if line.strip()]


def decode_txt(line):
    line = line.strip()
    if '"' not in line:
        return line
    parts = TOKEN.findall(line)
    return "".join(
        part[1:-1] if part.startswith('"') and part.endswith('"') else part
        for part in parts
    )


def _txt(lookup, name):
    lines = lookup("TXT", name)
    if lines is None:
        return None
    return [decode_txt(line) for line in lines]


def _norm(name):
    return name.strip().rstrip(".").lower()


def _mech(term):
    body = term.strip()
    if body[:1] in "+-~?":
        body = body[1:]
    if "=" in body and ":" not in body.split("=", 1)[0]:
        name, _value = body.split("=", 1)
        return name.lower(), body
    name = body.split(":", 1)[0].split("/", 1)[0]
    return name.lower(), body


def _target(name, body, current):
    if name in ("redirect", "exp"):
        value = body.split("=", 1)[1] if "=" in body else ""
    elif ":" in body:
        value = body.split(":", 1)[1].split("/", 1)[0]
    else:
        value = ""
    value = value.strip().rstrip(".")
    return _norm(value) if value else current


def _cidr_error(name, body):
    if "/" not in body or name in ("redirect", "exp", "include", "exists", "all"):
        return ""
    cidr = body.rsplit("/", 1)[1]
    limit = 128 if name == "ip6" else 32
    if (
        not cidr.isdigit()
        or (len(cidr) > 1 and cidr.startswith("0"))
        or int(cidr) > limit
    ):
        return f"invalid CIDR length {cidr}"
    return ""


def _starts(record, prefix):
    return record.lower().startswith(prefix.lower())


class _Spf:
    def __init__(self):
        self.lookups = 0
        self.voids = 0
        self.warnings = []
        self.errors = []
        self.unknown = False
        self.stop = False

    def count(self):
        if self.stop or self.unknown:
            return False
        self.lookups += 1
        if self.lookups > SPF_LOOKUP_LIMIT:
            self.errors.append(
                f"{self.lookups}/{SPF_LOOKUP_LIMIT} maximum DNS lookups"
            )
            self.stop = True
            return False
        return True

    def void(self):
        self.voids += 1
        if self.voids > SPF_VOID_LIMIT:
            self.errors.append(
                f"{self.voids}/{SPF_VOID_LIMIT} maximum void DNS lookups"
            )
            self.stop = True

    def fail(self, text):
        self.errors.append(text)
        self.stop = True


def _policy(record):
    for term in record.split()[1:]:
        if _mech(term)[0] == "all":
            raw = term.strip()
            return raw[0] if raw[:1] in "+-~?" else "+"
    return ""


def _eval_spf(domain, record, lookup, state, stack):
    domain = _norm(domain)
    if domain in stack:
        state.fail(f"SPF loop at {domain}")
        return
    stack.add(domain)
    terms = record.split()[1:]
    parsed = [_mech(term) for term in terms]
    has_all = any(name == "all" for name, _body in parsed)
    redirects = [body for name, body in parsed if name == "redirect"]
    exps = [body for name, body in parsed if name == "exp"]
    if len(redirects) > 1:
        state.fail("Multiple redirect modifiers")
    if len(exps) > 1:
        state.fail("Multiple exp values are not permitted")
    if has_all and redirects:
        state.warnings.append(
            "The redirect modifier was ignored because the record contains an all mechanism"
        )
    for name, body in parsed:
        if state.stop or state.unknown:
            break
        cidr = _cidr_error(name, body)
        if cidr:
            state.fail(cidr)
            break
        if name == "ptr":
            state.warnings.append("The ptr mechanism should not be used (RFC 7208)")
        if name == "redirect" and has_all:
            continue
        if name == "exp":
            _note_exp(body, domain, lookup, state)
            continue
        if name not in COUNTED:
            continue
        if not state.count():
            break
        target = _target(name, body, domain)
        if "%" in body:
            continue
        if name == "include":
            _spf_include(target, lookup, state, stack)
        elif name == "redirect":
            _spf_redirect(target, lookup, state, stack)
        elif name == "mx":
            _spf_mx(target, lookup, state)
        elif name in ("a", "ptr", "exists"):
            _spf_address(target, lookup, state)
    stack.remove(domain)


def _note_exp(body, domain, lookup, state):
    target = _target("exp", body, domain)
    if "%" in body:
        state.warnings.append(f"exp value {target} contains a macro and was not resolved")
        return
    found = _txt(lookup, target)
    if found is None:
        state.warnings.append(f"Failed to get TXT records at exp value {target}")
    elif not found:
        state.warnings.append(f"No TXT records at exp value {target}")


def _spf_include(target, lookup, state, stack):
    if target in stack:
        state.fail(f"SPF include loop at {target}")
        return
    found = _txt(lookup, target)
    if found is None:
        state.unknown = True
        state.stop = True
        return
    nested = [item for item in found if _starts(item, "v=spf1")]
    if not nested:
        state.void()
        return
    if len(nested) > 1:
        state.fail(f"{target} has multiple SPF TXT records")
        return
    _eval_spf(target, nested[0], lookup, state, stack)


def _spf_redirect(target, lookup, state, stack):
    if target in stack:
        state.fail(f"SPF redirect loop at {target}")
        return
    found = _txt(lookup, target)
    if found is None:
        state.unknown = True
        state.stop = True
        return
    nested = [item for item in found if _starts(item, "v=spf1")]
    if not nested:
        # dig +short cannot separate NXDOMAIN from NODATA. Empty is the void.
        state.void()
        return
    if len(nested) > 1:
        state.fail(f"{target} has multiple SPF TXT records")
        return
    _eval_spf(target, nested[0], lookup, state, stack)


def _spf_mx(target, lookup, state):
    found = lookup("MX", target)
    if found is None:
        state.unknown = True
        state.stop = True
        return
    if len(found) > SPF_LOOKUP_LIMIT:
        state.fail(f"{target} has more than {SPF_LOOKUP_LIMIT} MX records")
        return
    if not found:
        state.void()


def _spf_address(target, lookup, state):
    found = lookup("A", target)
    if found is None:
        state.unknown = True
        state.stop = True
        return
    if not found:
        state.void()


def spf(domain, lookup):
    found = _txt(lookup, domain)
    if found is None:
        return _spf_result("", None, None, False, "DNS lookup failed", [], ["DNS lookup failed"])
    records = [item for item in found if _starts(item, "v=spf1")]
    if not records:
        return None
    if len(records) > 1:
        return _spf_result(
            "",
            None,
            None,
            False,
            "The domain has multiple SPF TXT records",
            [],
            ["The domain has multiple SPF TXT records"],
        )
    state = _Spf()
    _eval_spf(domain, records[0], lookup, state, set())
    if state.unknown:
        return _spf_result(
            records[0],
            None,
            None,
            False,
            "DNS lookup failed",
            state.warnings,
            state.errors + ["DNS lookup failed"],
        )
    error = "; ".join(state.errors)
    return _spf_result(
        records[0],
        state.lookups,
        state.voids,
        not state.errors,
        error,
        state.warnings,
        state.errors,
    )


def _spf_result(record, lookups, voids, valid, error, warnings, errors):
    return {
        "record": record,
        "policy": _policy(record) if record and valid else "",
        "dns_lookups": lookups,
        "void_lookups": voids,
        "valid": valid,
        "error": error,
        "warnings": warnings,
        "errors": errors,
    }


def _tags(record):
    found = []
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        found.append((key.strip().lower(), value.strip()))
    return found


def _dupes(tags):
    seen = set()
    dupes = set()
    for key, _value in tags:
        if key in seen:
            dupes.add(key)
        seen.add(key)
    return dupes


def _mailto(uri):
    text = uri.strip()
    if not text.lower().startswith("mailto:"):
        return ""
    return text[7:].split("!")[0].split("?")[0].strip()


def dmarc(domain, lookup):
    found = _txt(lookup, f"_dmarc.{domain}")
    if found is None:
        return {
            "record": "",
            "policy": "",
            "warnings": [],
            "errors": ["DNS lookup failed"],
            "tags": {},
        }
    records = [item for item in found if _starts(item, "v=DMARC1")]
    if not records:
        return None
    if len(records) > 1:
        return {
            "record": "",
            "policy": "",
            "warnings": [],
            "errors": ["multiple DMARC records"],
            "tags": {},
        }
    record = records[0]
    tags = _tags(record)
    warnings = []
    errors = []
    keys = [key for key, _value in tags]
    if not keys or keys[0] != "v" or tags[0][1] != "DMARC1":
        errors.append("v tag must be DMARC1")
    for key in _dupes(tags):
        errors.append(f"duplicate DMARC tag {key}")
    stored = {}
    for key, value in tags:
        if key not in stored:
            stored[key] = value
    if "p" not in stored:
        warnings.append(
            "A missing p tag is equivalent to p=none in RFC 9989, but a p tag is required in older versions of DMARC."
        )
    elif keys.index("p") != 1:
        warnings.append("p tag is not immediately after v")
    policy = stored.get("p", "")
    if policy and policy not in DMARC_POLICIES:
        errors.append(f"invalid p tag {policy}")
    elif policy == "none":
        warnings.append(
            f"A p tag value of none makes DMARC unenforced on email sent as {domain}."
        )
    for key in ("sp", "np"):
        value = stored.get(key, "")
        if value and value not in DMARC_POLICIES:
            errors.append(f"invalid {key} tag {value}")
        elif value == "none":
            warnings.append(
                f"A {key} tag value of none makes DMARC unenforced on mail for {domain}."
            )
    for key in ("adkim", "aspf"):
        if key in stored and stored[key] not in ("r", "s"):
            warnings.append(f"invalid {key} tag {stored[key]}; raw value kept")
    if "fo" in stored:
        tokens = [item for item in stored["fo"].split(":") if item]
        allowed = {"0", "1", "d", "s"}
        if any(item not in allowed for item in tokens):
            errors.append(f"invalid fo tag {stored['fo']}")
        if "0" in tokens and "1" in tokens:
            warnings.append("fo contains both 0 and 1")
        if len(tokens) != len(set(tokens)):
            warnings.append("fo contains a duplicate token")
    for key in DMARC_REMOVED:
        if key in stored:
            warnings.append(f"Support for the {key} tag was removed in RFC 9989")
    if "rua" not in stored or not stored["rua"]:
        warnings.append("rua tag (destination for aggregate reports) not found.")
    for key in ("rua", "ruf"):
        if key not in stored or not stored[key]:
            continue
        uris = [item.strip() for item in stored[key].split(",") if item.strip()]
        if len(uris) > 2:
            warnings.append(f"more than two {key} URIs")
        for uri in uris:
            if "!" in uri:
                warnings.append(f"size limit on {key} URI is obsolete in RFC 9989")
            addr = _mailto(uri)
            if "@" not in addr:
                continue
            host = addr.rsplit("@", 1)[1].rstrip(".").lower()
            if host != domain:
                warnings.append(
                    f"external report destination {addr} is not verified"
                )
    for key in stored:
        if key not in {
            "v", "p", "sp", "np", "adkim", "aspf", "fo", "rua", "ruf",
            "pct", "rf", "ri", "psd", "t",
        }:
            warnings.append(f"unknown DMARC tag {key}")
    return {
        "record": record,
        "policy": policy,
        "warnings": warnings,
        "errors": errors,
        "tags": stored,
    }


def _is_ip(host):
    if ":" in host:
        return True
    parts = host.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or int(part) > 255:
            return False
    return True


def parse_mx(lines):
    warnings = []
    errors = []
    if lines is None:
        return {"mx": [], "null_mx": False, "warnings": warnings, "errors": ["MX lookup failed"]}
    parsed = []
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            warnings.append(f"ignored MX line {line}")
            continue
        try:
            pref = int(parts[0])
        except ValueError:
            warnings.append(f"ignored MX line {line}")
            continue
        parsed.append((pref, parts[1]))
    if not parsed:
        warnings.append("no MX records; implicit MX is not used (RFC 5321)")
        return {"mx": [], "null_mx": False, "warnings": warnings, "errors": errors}

    def _root(exchange):
        return exchange == "." or exchange.rstrip(".") == ""

    if len(parsed) == 1 and parsed[0][0] == 0 and _root(parsed[0][1]):
        warnings.append("null MX (RFC 7505): the domain explicitly does not accept mail")
        return {"mx": [], "null_mx": True, "warnings": warnings, "errors": errors}
    if any(pref == 0 and _root(exchange) for pref, exchange in parsed):
        warnings.append("null MX is present but is not the only MX record (RFC 7505)")
    hosts = []
    for pref, exchange in parsed:
        if _root(exchange):
            if pref != 0:
                warnings.append(f"MX preference {pref} points at the root, which is malformed")
            continue
        hosts.append((pref, exchange.rstrip(".")))
    seen = set()
    ordered = []
    for _pref, host in sorted(hosts, key=lambda item: (item[0], item[1].lower())):
        key = host.lower()
        if key in seen:
            warnings.append(f"duplicate MX hostname {host}")
            continue
        seen.add(key)
        if _is_ip(host):
            warnings.append(f"MX exchange {host} is an IP address (RFC 5321)")
        ordered.append(host)
    return {"mx": ordered, "null_mx": False, "warnings": warnings, "errors": errors}


def _mx_pattern_ok(value):
    name = value[2:] if value.startswith("*.") else value
    if "*" in value and not value.startswith("*."):
        return False
    if not name or len(name) > 253:
        return False
    labels = name.split(".")
    pattern = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
    return all(label and len(label) <= 63 and pattern.fullmatch(label) for label in labels)


def _policy_keys(body):
    found = {}
    mx = []
    warnings = []
    errors = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            warnings.append(f"ignored policy line {line}")
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "mx":
            mx.append(value)
            if not _mx_pattern_ok(value):
                errors.append(f"invalid mx pattern {value}")
            continue
        if key in found:
            warnings.append(f"duplicate policy key {key}")
            continue
        found[key] = value
        if key not in ("version", "mode", "max_age"):
            warnings.append(f"unknown policy key {key}")
    if found.get("version") != "STSv1":
        errors.append("version must be STSv1")
    mode = found.get("mode", "")
    if mode not in ("enforce", "testing", "none"):
        errors.append("mode must be enforce, testing, or none")
    age = found.get("max_age", "")
    if (
        not age.isdigit()
        or len(age) > 10
        or int(age) > MTA_STS_MAX_AGE
    ):
        errors.append("max_age must be an integer from 0 to 31557600")
    if mode in ("enforce", "testing") and not mx:
        errors.append("mode other than none requires an mx key")
    return {
        "mode": mode if mode in ("enforce", "testing", "none") else "",
        "max_age": int(age) if age.isdigit() else None,
        "mx": mx,
        "warnings": warnings,
        "errors": errors,
    }


def mta_sts(domain, lookup, fetch):
    found = _txt(lookup, f"_mta-sts.{domain}")
    if found is None:
        return {
            "valid": False,
            "mode": "",
            "id": "",
            "error": "DNS lookup failed",
            "warnings": [],
            "errors": ["DNS lookup failed"],
            "mx": [],
        }
    records = [item for item in found if _starts(item, "v=STSv1")]
    if not records:
        return None
    if len(records) > 1:
        return {
            "valid": False,
            "mode": "",
            "id": "",
            "error": "Multiple MTA-STS records are not permitted",
            "warnings": [],
            "errors": ["Multiple MTA-STS records are not permitted"],
            "mx": [],
        }
    tags = _tags(records[0])
    warnings = []
    errors = []
    stored = {}
    for key, value in tags:
        if key in stored:
            warnings.append(f"duplicate MTA-STS tag {key}")
            continue
        stored[key] = value
        if key not in ("v", "id"):
            warnings.append(f"unknown MTA-STS tag {key}")
    if stored.get("v") != "STSv1":
        errors.append("v must be STSv1")
    ident = stored.get("id", "")
    if not re.fullmatch(r"[A-Za-z0-9]{1,32}", ident):
        errors.append("id must be 1 to 32 letters or digits")
    if errors:
        return {
            "valid": False,
            "mode": "",
            "id": ident,
            "error": "; ".join(errors),
            "warnings": warnings,
            "errors": errors,
            "mx": [],
        }
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        status, body = fetch(url)
    except Exception as exc:
        return {
            "valid": False,
            "mode": "",
            "id": ident,
            "error": str(exc) or "policy fetch failed",
            "warnings": warnings,
            "errors": ["policy fetch failed"],
            "mx": [],
        }
    if status != 200:
        return {
            "valid": False,
            "mode": "",
            "id": ident,
            "error": f"HTTP {status}",
            "warnings": warnings,
            "errors": [f"HTTP {status}"],
            "mx": [],
        }
    parsed = _policy_keys(body)
    errors.extend(parsed["errors"])
    warnings.extend(parsed["warnings"])
    return {
        "valid": not errors,
        "mode": parsed["mode"] if not errors else parsed["mode"],
        "id": ident,
        "error": "; ".join(errors),
        "warnings": warnings,
        "errors": errors,
        "mx": parsed["mx"],
        "max_age": parsed["max_age"],
    }


def bimi(domain, lookup, dmarc_result):
    found = _txt(lookup, f"default._bimi.{domain}")
    if found is None:
        return {
            "record": "",
            "warnings": [],
            "errors": ["DNS lookup failed"],
            "tags": {},
        }
    records = [item for item in found if _starts(item, "v=BIMI1") or "l=" in item.lower()]
    if not records:
        return None
    if len([item for item in found if _starts(item, "v=BIMI1")]) > 1:
        return {
            "record": "",
            "warnings": [],
            "errors": ["multiple BIMI records"],
            "tags": {},
        }
    record = records[0]
    tags = _tags(record)
    warnings = []
    errors = []
    for key in _dupes(tags):
        errors.append(f"duplicate BIMI tag {key}")
    stored = {}
    for key, value in tags:
        stored.setdefault(key, value)
    if stored.get("v") != "BIMI1":
        errors.append("v must be BIMI1")
    if "l" not in stored:
        errors.append(
            "missing the required l tag; publish the l tag with an empty value (l=;)"
        )
    elif stored["l"] and not stored["l"].lower().startswith("https://"):
        errors.append("l must be empty or an https URI")
    if "a" in stored and stored["a"] and not stored["a"].lower().startswith("https://"):
        errors.append("a must be empty or an https URI")
    for key in stored:
        if key not in ("v", "l", "a", "avp"):
            warnings.append(f"unknown BIMI tag {key}")
    if dmarc_result is not None and dmarc_result.get("policy") not in ("quarantine", "reject"):
        warnings.append(
            "DMARC p must be quarantine or reject before a BIMI logo is displayed"
        )
    return {"record": record, "warnings": warnings, "errors": errors, "tags": stored}


def dkim(domain, lookup, selector):
    if not selector:
        return {
            "checked": False,
            "selector": "",
            "found": False,
            "revoked": False,
            "has_key": False,
            "error": "",
        }
    found = _txt(lookup, f"{selector}._domainkey.{domain}")
    result = {
        "checked": True,
        "selector": selector,
        "found": False,
        "revoked": False,
        "has_key": False,
        "error": "",
    }
    if found is None:
        result["error"] = "DNS lookup failed"
        return result
    if not found:
        return result
    result["found"] = True
    for record in found:
        stored = dict(_tags(record))
        if "p" not in stored:
            continue
        if stored["p"] == "":
            result["revoked"] = True
            result["has_key"] = False
            return result
        result["has_key"] = True
        return result
    return result


def tls_rpt(domain, lookup):
    found = _txt(lookup, f"_smtp._tls.{domain}")
    if found is None:
        return {
            "valid": False,
            "error": "DNS lookup failed",
            "warnings": [],
            "errors": ["DNS lookup failed"],
            "tags": {},
        }
    records = [item for item in found if _starts(item, "v=TLSRPTv1")]
    if not records:
        return None
    if len(records) > 1:
        return {
            "valid": False,
            "error": "Multiple SMTP TLS Reporting records are not permitted",
            "warnings": [],
            "errors": ["Multiple SMTP TLS Reporting records are not permitted"],
            "tags": {},
        }
    record = records[0]
    warnings = []
    errors = []
    if re.search(r"\s;", record):
        warnings.append("whitespace before semicolon")
    tags = _tags(record)
    stored = {}
    for key, value in tags:
        if key in stored:
            warnings.append(f"duplicate TLS-RPT tag {key}")
            continue
        stored[key] = value
        if key not in ("v", "rua"):
            warnings.append(f"unknown TLS-RPT tag {key}")
    if stored.get("v") != "TLSRPTv1":
        errors.append("v must be TLSRPTv1")
    if not stored.get("rua"):
        errors.append("rua is required")
    return {
        "valid": not errors,
        "error": "; ".join(errors),
        "warnings": warnings,
        "errors": errors,
        "tags": stored,
        "record": record,
    }


def _no_redirect(req, fp, code, msg, headers, newurl):
    raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    redirect_request = staticmethod(_no_redirect)


def default_fetch(url):
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": "email-audit"})
    try:
        with opener.open(request, timeout=2) as response:
            return response.status, response.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""


def audit(domain, lookup=None, fetch=None, dkim_selector=None, dkim_selectors=None):
    domain = _norm(domain)
    if lookup is None:
        lookup = dig
    if fetch is None:
        fetch = default_fetch
    dmarc_result = dmarc(domain, lookup)
    selectors = [item for item in (dkim_selectors or []) if item]
    if not selectors and dkim_selector:
        selectors = [dkim_selector]
    dkim_results = [dkim(domain, lookup, selector) for selector in selectors]
    if not dkim_results:
        dkim_results = [dkim(domain, lookup, None)]
    return {
        "domain": domain,
        "mx": parse_mx(lookup("MX", domain)),
        "spf": spf(domain, lookup),
        "dmarc": dmarc_result,
        "dkim": dkim_results[0],
        "dkim_all": dkim_results,
        "bimi": bimi(domain, lookup, dmarc_result),
        "mta_sts": mta_sts(domain, lookup, fetch),
        "tls_rpt": tls_rpt(domain, lookup),
    }


def _join(items):
    return "; ".join(items)


def report(result):
    lines = [result["domain"]]
    mx = result["mx"]
    if mx["null_mx"]:
        lines.append(f"{'MX':<10} null MX (RFC 7505)")
    elif mx["mx"]:
        lines.append(f"{'MX':<10} {', '.join(mx['mx'])}")
    else:
        lines.append(f"{'MX':<10} none")
    for warning in mx["warnings"]:
        lines.append(f"{'':<10} warning: {warning}")
    for error in mx["errors"]:
        lines.append(f"{'':<10} error: {error}")
    spf_result = result["spf"]
    if spf_result is None:
        lines.append(f"{'SPF':<10} none")
    else:
        policy = spf_result["policy"] or "(no all)"
        lines.append(
            f"{'SPF':<10} policy {policy}; lookups {spf_result['dns_lookups']}; "
            f"voids {spf_result['void_lookups']}"
        )
        if spf_result["error"]:
            lines.append(f"{'':<10} error: {spf_result['error']}")
        for warning in spf_result["warnings"]:
            lines.append(f"{'':<10} warning: {warning}")
    dmarc_result = result["dmarc"]
    if dmarc_result is None:
        lines.append(f"{'DMARC':<10} none")
    else:
        lines.append(f"{'DMARC':<10} policy {dmarc_result['policy'] or '(none)'}")
        for warning in dmarc_result["warnings"]:
            lines.append(f"{'':<10} warning: {warning}")
        for error in dmarc_result["errors"]:
            lines.append(f"{'':<10} error: {error}")
    dkim_result = result["dkim"]
    dkim_results = result.get("dkim_all") or [dkim_result]
    if len(dkim_results) > 1:
        for item in dkim_results:
            if not item["checked"]:
                continue
            if item["revoked"]:
                lines.append(f"{'DKIM':<10} {item['selector']} revoked (empty p=)")
            elif item["has_key"]:
                lines.append(f"{'DKIM':<10} {item['selector']} key present")
            else:
                lines.append(f"{'DKIM':<10} {item['selector']} no record")
        return "\n".join(lines)
    if not dkim_result["checked"]:
        lines.append(f"{'DKIM':<10} not checked (no selector)")
    elif dkim_result["revoked"]:
        lines.append(f"{'DKIM':<10} {dkim_result['selector']} revoked (empty p=)")
    elif dkim_result["has_key"]:
        lines.append(f"{'DKIM':<10} {dkim_result['selector']} key present")
    else:
        lines.append(f"{'DKIM':<10} {dkim_result['selector']} no record")
    bimi_result = result["bimi"]
    if bimi_result is None:
        lines.append(f"{'BIMI':<10} none")
    else:
        lines.append(f"{'BIMI':<10} default selector")
        for warning in bimi_result["warnings"]:
            lines.append(f"{'':<10} warning: {warning}")
        for error in bimi_result["errors"]:
            lines.append(f"{'':<10} error: {error}")
    sts = result["mta_sts"]
    if sts is None:
        lines.append(f"{'MTA-STS':<10} none")
    else:
        lines.append(f"{'MTA-STS':<10} mode {sts['mode'] or '(empty)'}")
        if sts["error"]:
            lines.append(f"{'':<10} error: {sts['error']}")
        for warning in sts["warnings"]:
            lines.append(f"{'':<10} warning: {warning}")
    tls = result["tls_rpt"]
    if tls is None:
        lines.append(f"{'TLS-RPT':<10} none")
    else:
        state = "present" if tls["valid"] else "invalid"
        lines.append(f"{'TLS-RPT':<10} {state}")
        if tls["error"]:
            lines.append(f"{'':<10} error: {tls['error']}")
        for warning in tls["warnings"]:
            lines.append(f"{'':<10} warning: {warning}")
    return "\n".join(lines)


def main(argv):
    parser = argparse.ArgumentParser(description="Audit MX, SPF, DMARC, MTA-STS, TLS-RPT, and BIMI.")
    parser.add_argument("domains", nargs="+")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--dkim-selector", default="", help="legacy single DKIM selector")
    parser.add_argument(
        "--selectors",
        default="",
        help="comma-separated DKIM selectors to check, e.g. google,selector1",
    )
    args = parser.parse_args(argv)
    selectors = [item.strip() for item in args.selectors.split(",") if item.strip()]
    code = 0
    for domain in args.domains:
        result = audit(domain, dkim_selectors=selectors, dkim_selector=args.dkim_selector or None)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(report(result))
            print()
        findings = []
        if result["mx"]["errors"] or result["mx"].get("null_mx"):
            findings.append("mx")
        if result["spf"] is None or not result["spf"]["valid"]:
            findings.append("spf")
        if result["dmarc"] is None or result["dmarc"].get("policy") == "none":
            findings.append("dmarc")
        if findings:
            print(f"  critical: {', '.join(findings)} (exit 1)", file=sys.stderr)
            code = 1
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

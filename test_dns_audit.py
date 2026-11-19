#!/usr/bin/env python3
"""Regression tests for DNS posture rules. No network, no dig."""

import unittest

import dns_audit


def _table(rows):
    def lookup(kind, name):
        return rows.get((kind, name.rstrip(".").lower()), [])
    return lookup


def _calls():
    seen = []

    def lookup(kind, name):
        seen.append((kind, name))
        return []

    return seen, lookup


class SpfTests(unittest.TestCase):
    def test_eleven_includes_error_contains_ten(self):
        rows = {("TXT", "example.com"): [
            "v=spf1 " + " ".join(f"include:i{n}.example" for n in range(11))
        ]}
        for n in range(11):
            rows[("TXT", f"i{n}.example")] = ["v=spf1 -all"]
        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail)
        error = result["spf"]["error"]
        self.assertIn("10", error)
        self.assertIsNot(result["spf"]["valid"], True)
        self.assertGreater(result["spf"]["dns_lookups"], 10)

    def test_three_void_includes_error_contains_two(self):
        rows = {("TXT", "example.com"): ["v=spf1 include:a.example include:b.example include:c.example"]}
        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail)
        self.assertIn("2", result["spf"]["error"])
        self.assertEqual(result["spf"]["dns_lookups"], 3)
        self.assertGreater(result["spf"]["void_lookups"], 2)

    def test_redirect_with_all_is_not_a_lookup(self):
        seen = []

        def lookup(kind, name):
            seen.append((kind, name))
            if (kind, name) == ("TXT", "example.com"):
                return ["v=spf1 redirect=other.example -all"]
            return []

        result = dns_audit.audit("example.com", lookup=lookup, fetch=self.fail)
        self.assertEqual(result["spf"]["dns_lookups"], 0)
        self.assertFalse(any("other.example" in name for _kind, name in seen))
        self.assertTrue(any("redirect" in item.lower() and "ignored" in item.lower()
                            for item in result["spf"]["warnings"]))

    def test_ptr_counts_one_and_warns(self):
        rows = {
            ("TXT", "example.com"): ["v=spf1 ptr -all"],
            ("A", "example.com"): ["192.0.2.1"],
        }
        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail)
        self.assertEqual(result["spf"]["dns_lookups"], 1)
        self.assertTrue(any("ptr" in item.lower() for item in result["spf"]["warnings"]))

    def test_all_does_not_count_as_a_lookup(self):
        rows = {("TXT", "example.com"): ["v=spf1 -all"]}
        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail)
        self.assertEqual(result["spf"]["dns_lookups"], 0)
        self.assertEqual(result["spf"]["policy"], "-")
        self.assertIs(result["spf"]["valid"], True)

    def test_missing_all_does_not_invent_plus(self):
        rows = {("TXT", "example.com"): ["v=spf1 ip4:192.0.2.1"]}
        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail)
        self.assertEqual(result["spf"]["policy"], "")
        self.assertEqual(result["spf"]["dns_lookups"], 0)

    def test_three_mechanisms_count_three(self):
        rows = {
            ("TXT", "example.com"): ["v=spf1 a mx include:x.example ip4:1.2.3.4 -all"],
            ("A", "example.com"): ["192.0.2.1"],
            ("MX", "example.com"): ["10 mail.example.com."],
            ("TXT", "x.example"): ["v=spf1 -all"],
        }
        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail)
        self.assertEqual(result["spf"]["dns_lookups"], 3)
        self.assertEqual(result["spf"]["void_lookups"], 0)

    def test_dig_failure_is_not_a_zero_count(self):
        def lookup(kind, name):
            return None

        result = dns_audit.audit("example.com", lookup=lookup, fetch=self.fail)
        self.assertIsNone(result["spf"]["dns_lookups"])
        self.assertNotEqual(result["spf"]["dns_lookups"], 0)
        self.assertIsNot(result["spf"]["valid"], True)

    def test_missing_spf_stays_empty(self):
        result = dns_audit.audit("example.com", lookup=_table({}), fetch=self.fail)
        self.assertIsNone(result["spf"])


class DmarcTests(unittest.TestCase):
    def _audit(self, record):
        rows = {("TXT", "_dmarc.example.com"): [record]} if record is not None else {}
        return dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail)

    def test_missing_p_stays_blank_and_warns(self):
        result = self._audit("v=DMARC1; rua=mailto:dmarc@example.com")
        self.assertEqual(result["dmarc"]["policy"], "")
        self.assertTrue(result["dmarc"]["warnings"])
        self.assertTrue(any("p" in item for item in result["dmarc"]["warnings"]))

    def test_p_none_warns(self):
        result = self._audit("v=DMARC1; p=none")
        self.assertEqual(result["dmarc"]["policy"], "none")
        self.assertTrue(any("none" in item for item in result["dmarc"]["warnings"]))

    def test_p_bogus_is_an_error(self):
        result = self._audit("v=DMARC1; p=bogus")
        self.assertTrue(result["dmarc"]["errors"])

    def test_removed_pct_warns_rfc_9989(self):
        result = self._audit("v=DMARC1; p=reject; pct=100")
        self.assertTrue(any("RFC 9989" in item for item in result["dmarc"]["warnings"]))

    def test_missing_ruf_is_not_a_warning(self):
        result = self._audit("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
        self.assertFalse(any("ruf" in item.lower() for item in result["dmarc"]["warnings"]))

    def test_duplicate_p_is_an_error(self):
        result = self._audit("v=DMARC1; p=reject; p=none")
        self.assertTrue(result["dmarc"]["errors"])

    def test_external_rua_is_warned_not_verified(self):
        result = self._audit("v=DMARC1; p=reject; rua=mailto:dmarc@other.example")
        text = " ".join(result["dmarc"]["warnings"]).lower()
        self.assertIn("not verified", text)
        self.assertNotIn("verified as valid", text)


class MxTests(unittest.TestCase):
    def test_sole_null_mx(self):
        rows = {("MX", "example.com"): ["0 ."]}
        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail)
        self.assertTrue(result["mx"]["null_mx"])
        self.assertEqual(result["mx"]["mx"], [])
        self.assertNotIn(".", result["mx"]["mx"])

    def test_null_mx_plus_real_host_is_not_null(self):
        rows = {("MX", "example.com"): ["0 .", "10 mail.example.com."]}
        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail)
        self.assertFalse(result["mx"]["null_mx"])
        self.assertIn("mail.example.com", result["mx"]["mx"])

    def test_no_mx_does_not_query_a(self):
        seen, lookup = _calls()
        dns_audit.audit("example.com", lookup=lookup, fetch=self.fail)
        self.assertFalse(any(kind == "A" for kind, _name in seen))


class MtaStsTests(unittest.TestCase):
    def test_no_txt_does_not_fetch(self):
        fetched = []

        def fetch(url):
            fetched.append(url)
            return 200, ""

        result = dns_audit.audit("example.com", lookup=_table({}), fetch=fetch)
        self.assertEqual(fetched, [])
        self.assertIsNone(result["mta_sts"])

    def test_fetch_error_leaves_mode_empty(self):
        rows = {("TXT", "_mta-sts.example.com"): ["v=STSv1; id=abc123"]}

        def fetch(url):
            raise OSError("down")

        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=fetch)
        self.assertEqual(result["mta_sts"]["mode"], "")
        self.assertIsNot(result["mta_sts"]["valid"], True)

    def test_enforce_without_mx_is_an_error(self):
        rows = {("TXT", "_mta-sts.example.com"): ["v=STSv1; id=abc123"]}

        def fetch(url):
            return 200, "version: STSv1\nmode: enforce\nmax_age: 604800\n"

        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=fetch)
        self.assertTrue(result["mta_sts"]["errors"])

    def test_testing_with_mx_keeps_mode(self):
        rows = {("TXT", "_mta-sts.example.com"): ["v=STSv1; id=abc123"]}

        def fetch(url):
            self.assertEqual(url, "https://mta-sts.example.com/.well-known/mta-sts.txt")
            return 200, "version: STSv1\nmode: testing\nmax_age: 604800\nmx: *.example.com\n"

        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=fetch)
        self.assertEqual(result["mta_sts"]["mode"], "testing")
        self.assertEqual(result["mta_sts"]["errors"], [])


class BimiDkimTlsTests(unittest.TestCase):
    def test_bimi_queries_only_the_default_selector(self):
        seen = []

        def lookup(kind, name):
            seen.append(name)
            if name == "default._bimi.example.com":
                return ["v=BIMI1; l=https://example.com/logo.svg"]
            return []

        dns_audit.audit("example.com", lookup=lookup, fetch=self.fail)
        self.assertIn("default._bimi.example.com", seen)
        self.assertNotIn("selector1._bimi.example.com", seen)

    def test_bimi_missing_l_is_an_error(self):
        rows = {("TXT", "default._bimi.example.com"): ["v=BIMI1; a=https://cdn.example/a.svg"]}
        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail)
        self.assertTrue(result["bimi"]["errors"])
        self.assertTrue(any("l" in item for item in result["bimi"]["errors"]))

    def test_no_selector_does_not_query_domainkey(self):
        seen, lookup = _calls()
        result = dns_audit.audit("example.com", lookup=lookup, fetch=self.fail)
        self.assertFalse(any("_domainkey" in name for name in seen))
        self.assertFalse(result["dkim"]["checked"])

    def test_empty_p_is_revoked(self):
        rows = {("TXT", "s1._domainkey.example.com"): ["v=DKIM1; p="]}
        result = dns_audit.audit(
            "example.com", lookup=_table(rows), fetch=self.fail, dkim_selector="s1"
        )
        self.assertTrue(result["dkim"]["revoked"])
        self.assertFalse(result["dkim"]["has_key"])

    def test_tlsrpt_missing_rua_is_an_error(self):
        rows = {("TXT", "_smtp._tls.example.com"): ["v=TLSRPTv1"]}
        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail)
        self.assertTrue(result["tls_rpt"]["errors"])

    def test_tlsrpt_whitespace_before_semicolon_warns(self):
        rows = {("TXT", "_smtp._tls.example.com"): ["v=TLSRPTv1 ; rua=mailto:tls@example.com"]}
        result = dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail)
        self.assertTrue(any("whitespace" in item for item in result["tls_rpt"]["warnings"]))

    def test_missing_tlsrpt_stays_empty(self):
        result = dns_audit.audit("example.com", lookup=_table({}), fetch=self.fail)
        self.assertIsNone(result["tls_rpt"])

    def test_report_shows_warning_and_drops_old_claims(self):
        rows = {("TXT", "example.com"): ["v=spf1 ptr -all"], ("A", "example.com"): ["192.0.2.1"]}
        text = dns_audit.report(dns_audit.audit("example.com", lookup=_table(rows), fetch=self.fail))
        self.assertIn("warning", text.lower())
        self.assertNotIn("over 8", text)
        self.assertNotIn("no key on common selectors", text)


if __name__ == "__main__":
    unittest.main()

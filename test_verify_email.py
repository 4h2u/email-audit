#!/usr/bin/env python3
"""Reply-class and same-session dialogue tests. No network."""
import unittest

from verify_email import _dialogue, _leftover, classify_reply, is_role


class FakeSMTP:
    def __init__(self, replies):
        self.replies = list(replies)
        self.rcpts = []
        self.mails = []
        self.rsets = 0

    def mail(self, sender, options=()):
        self.mails.append(sender)
        return (250, b"OK")

    def rcpt(self, address, options=()):
        self.rcpts.append(address)
        code, text = self.replies.pop(0)
        if isinstance(text, str):
            text = text.encode("utf-8")
        return (code, text)

    def rset(self):
        self.rsets += 1
        return (250, b"OK")


class DialogueTests(unittest.TestCase):
    def _run(self, replies, email="alice@example.com"):
        smtp = FakeSMTP(replies)
        done, retry, saw_blocked, saw_grey = _dialogue(
            smtp, "example.com", [email], False
        )
        return smtp, done, retry, saw_blocked, saw_grey

    def test_probe_250_is_catch_all_without_real_rcpt(self):
        email = "alice@example.com"
        smtp, done, retry, _blocked, _grey = self._run(
            [(250, "2.1.5 ok"), (250, "2.1.5 ok")],
            email,
        )
        self.assertEqual(len(smtp.rcpts), 1)
        self.assertNotIn(email, smtp.rcpts)
        self.assertNotEqual(smtp.rcpts[0], email)
        self.assertEqual(len(smtp.replies), 1)
        self.assertEqual(smtp.rsets, 0)
        self.assertEqual(smtp.mails, [""])
        self.assertEqual(done[email][0], "catch-all")
        self.assertNotEqual(done[email][0], "accepted")
        self.assertEqual(retry, [])

    def test_probe_user_unknown_real_250_is_accepted(self):
        email = "alice@example.com"
        smtp, done, retry, blocked, grey = self._run(
            [(550, "5.1.1 user unknown"), (250, "2.1.5 ok")],
            email,
        )
        self.assertEqual(len(smtp.rcpts), 2)
        self.assertNotEqual(smtp.rcpts[0], email)
        self.assertEqual(smtp.rcpts[1], email)
        self.assertEqual(smtp.mails, ["", ""])
        self.assertEqual(smtp.rsets, 1)
        self.assertEqual(done[email][0], "accepted")
        self.assertEqual(retry, [])
        self.assertFalse(blocked)
        self.assertFalse(grey)

    def test_probe_spamhaus_skips_real_rcpt(self):
        email = "alice@example.com"
        smtp, done, retry, blocked, grey = self._run(
            [(550, "blocked using spamhaus"), (250, "2.1.5 ok")],
            email,
        )
        self.assertEqual(len(smtp.rcpts), 1)
        self.assertNotIn(email, smtp.rcpts)
        self.assertEqual(len(smtp.replies), 1)
        self.assertEqual(smtp.rsets, 0)
        self.assertNotIn(email, done)
        self.assertIn(email, retry)
        self.assertTrue(blocked)
        self.assertFalse(grey)
        self.assertNotEqual(done.get(email, (None,))[0], "accepted")
        self.assertNotEqual(done.get(email, (None,))[0], "rejected")

    def test_probe_user_unknown_real_552_is_full_inbox(self):
        email = "alice@example.com"
        smtp, done, retry, _blocked, _grey = self._run(
            [(550, "no such user"), (552, "")],
            email,
        )
        self.assertEqual(smtp.rcpts[-1], email)
        self.assertEqual(done[email][0], "full-inbox")
        self.assertNotEqual(done[email][0], "rejected")
        self.assertEqual(retry, [])

    def test_probe_mailbox_full_skips_real_rcpt(self):
        email = "alice@example.com"
        smtp, done, retry, _blocked, _grey = self._run(
            [(552, "mailbox full"), (250, "2.1.5 ok")],
            email,
        )
        self.assertEqual(len(smtp.rcpts), 1)
        self.assertNotIn(email, smtp.rcpts)
        self.assertEqual(len(smtp.replies), 1)
        self.assertEqual(smtp.rsets, 0)
        self.assertEqual(done[email][0], "unconfirmed")
        self.assertNotEqual(done[email][0], "accepted")
        self.assertNotEqual(done[email][0], "full-inbox")
        self.assertEqual(retry, [])

    def test_probe_user_unknown_real_451_is_deferred(self):
        email = "alice@example.com"
        smtp, done, retry, blocked, grey = self._run(
            [(550, "no such user"), (451, "try again later")],
            email,
        )
        self.assertEqual(smtp.rcpts[-1], email)
        self.assertNotIn(email, done)
        self.assertIn(email, retry)
        self.assertTrue(grey)
        self.assertFalse(blocked)
        self.assertNotEqual(done.get(email, (None,))[0], "accepted")
        self.assertNotEqual(done.get(email, (None,))[0], "rejected")

    def test_probe_user_unknown_real_252_is_unconfirmed(self):
        email = "alice@example.com"
        smtp, done, _retry, _blocked, _grey = self._run(
            [(550, "no such user"), (252, "cannot verify")],
            email,
        )
        self.assertEqual(smtp.rcpts[-1], email)
        self.assertEqual(len(smtp.replies), 0)
        self.assertEqual(done[email][0], "unconfirmed")
        self.assertNotEqual(done[email][0], "accepted")

    def test_probe_user_unknown_real_disabled(self):
        email = "alice@example.com"
        smtp, done, retry, _blocked, _grey = self._run(
            [(550, "no such user"), (550, "5.2.1 mailbox disabled")],
            email,
        )
        self.assertEqual(smtp.rcpts[-1], email)
        self.assertEqual(done[email][0], "disabled")
        self.assertNotEqual(done[email][0], "rejected")
        self.assertEqual(retry, [])

    def test_real_554_is_unconfirmed_not_rejected(self):
        email = "alice@example.com"
        smtp, done, retry, _blocked, _grey = self._run(
            [(550, "no such user"), (554, "transaction failed")],
            email,
        )
        self.assertEqual(smtp.rcpts[-1], email)
        self.assertEqual(done[email][0], "unconfirmed")
        self.assertNotEqual(done[email][0], "rejected")
        self.assertNotEqual(done[email][0], "disabled")
        self.assertEqual(retry, [])

    def test_real_3xx_is_not_accepted(self):
        email = "alice@example.com"
        _smtp, done, _retry, _blocked, _grey = self._run(
            [(550, "no such user"), (354, "start mail input")],
            email,
        )
        self.assertEqual(done[email][0], "unconfirmed")
        self.assertNotEqual(done[email][0], "accepted")

    def test_probe_policy_block_skips_real_rcpt(self):
        email = "alice@example.com"
        smtp, done, retry, blocked, grey = self._run(
            [(550, "5.7.1 delivery not authorized"), (250, "2.1.5 ok")],
            email,
        )
        self.assertEqual(len(smtp.rcpts), 1)
        self.assertNotIn(email, smtp.rcpts)
        self.assertNotIn(email, done)
        self.assertIn(email, retry)
        self.assertTrue(blocked)
        self.assertFalse(grey)


class ClassifierTests(unittest.TestCase):
    def test_direct_cases(self):
        self.assertEqual(classify_reply(452, "over quota"), "full-inbox")
        self.assertEqual(classify_reply(452, "too many recipients"), "greylisted")
        kind = classify_reply(554, "transaction failed")
        self.assertNotEqual(kind, "disabled")
        self.assertNotEqual(kind, "rejected")
        self.assertEqual(kind, "unconfirmed")
        self.assertEqual(classify_reply(550, "5.7.1 user unknown"), "rejected")
        self.assertNotEqual(classify_reply(550, "5.7.1 user unknown"), "blocked")
        self.assertEqual(classify_reply(550, "5.7.1 delivery not authorized"), "blocked")

    def test_block_keywords_are_substrings_not_bare_words(self):
        for text in ("denied", "blocked", "spam", "address rejected"):
            self.assertNotEqual(classify_reply(550, text), "blocked", text)
        self.assertEqual(classify_reply(550, "address rejected"), "rejected")
        self.assertEqual(classify_reply(550, "Blocked using Spamhaus"), "blocked")
        self.assertEqual(classify_reply(550, "listed on a block list"), "blocked")

    def test_bare_full_or_space_is_not_full_inbox(self):
        self.assertNotEqual(classify_reply(451, "full"), "full-inbox")
        self.assertNotEqual(classify_reply(451, "space"), "full-inbox")
        self.assertEqual(classify_reply(451, "full"), "greylisted")
        self.assertEqual(classify_reply(451, "space"), "greylisted")
        self.assertEqual(classify_reply(552, ""), "full-inbox")
        self.assertEqual(classify_reply(450, "4.2.2"), "full-inbox")

    def test_disabled_beats_bare_550_and_is_a_whole_word(self):
        self.assertEqual(classify_reply(550, "5.2.1"), "disabled")
        self.assertEqual(classify_reply(550, "mailbox inactive"), "disabled")
        self.assertNotEqual(classify_reply(554, "notdisabled"), "disabled")
        self.assertEqual(classify_reply(550, "notdisabled"), "rejected")

    def test_other_5xx_and_enhanced_user_unknown(self):
        self.assertEqual(classify_reply(550, "mailbox unavailable"), "rejected")
        self.assertEqual(classify_reply(553, "5.1.0 bad address"), "rejected")
        self.assertEqual(classify_reply(551, "user not local"), "unconfirmed")
        self.assertEqual(classify_reply(354, "start mail input"), "unconfirmed")
        self.assertEqual(classify_reply(250, "ok"), "positive")
        self.assertEqual(classify_reply(251, "ok"), "positive")
        self.assertEqual(classify_reply(252, "ok"), "ambiguous")

    def test_leftover_priority(self):
        self.assertEqual(_leftover(True, True), "blocked")
        self.assertEqual(_leftover(True, False), "blocked")
        self.assertEqual(_leftover(False, True), "greylisted")
        self.assertEqual(_leftover(False, False), "unreachable")


class RoleTests(unittest.TestCase):
    def test_exact_local_part(self):
        self.assertTrue(is_role("postmaster"))
        self.assertFalse(is_role("alice"))
        self.assertFalse(is_role("admin-team"))
        for name in (
            "abuse",
            "hostmaster",
            "webmaster",
            "noc",
            "security",
            "admin",
            "administrator",
            "root",
        ):
            self.assertTrue(is_role(name), name)
        for name in ("info", "sales", "support", "postmaster2", "rootkit"):
            self.assertFalse(is_role(name), name)

    def test_role_address_stays_accepted(self):
        email = "postmaster@example.com"
        smtp = FakeSMTP([(550, "5.1.1 user unknown"), (250, "2.1.5 ok")])
        done, retry, _blocked, _grey = _dialogue(
            smtp, "example.com", [email], False
        )
        self.assertEqual(smtp.rcpts[-1], email)
        self.assertEqual(done[email][0], "accepted")
        self.assertIn("role", done[email][1].split())
        self.assertEqual(retry, [])


if __name__ == "__main__":
    unittest.main()

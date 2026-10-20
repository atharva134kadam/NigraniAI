"""Tests for pii_engine: validators, text scanning, fusion. Run: python3 -m unittest test_pii_engine -v"""
import unittest

import pii_engine as P


def with_check(prefix, ok, alphabet="0123456789"):
    """The one completion of `prefix` that passes `ok`, and one that doesn't."""
    good = [prefix + c for c in alphabet if ok(prefix + c)]
    bad = [prefix + c for c in alphabet if not ok(prefix + c)]
    return good[0], bad[0]


class Checksums(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(P.luhn_ok("4111111111111111"))
        self.assertTrue(P.luhn_ok("5555555555554444"))
        self.assertFalse(P.luhn_ok("4111111111111112"))

    def test_verhoeff(self):
        good, bad = with_check("23456789012", P.verhoeff_ok)
        self.assertTrue(P.verhoeff_ok(good))
        self.assertFalse(P.verhoeff_ok(bad))

    def test_gstin(self):
        good, bad = with_check("27AAPFU0939F1Z", P.gstin_ok, P._B36)
        self.assertTrue(P.gstin_ok(good))
        self.assertFalse(P.gstin_ok(bad))
        self.assertFalse(P.gstin_ok("99AAPFU0939F1ZV" if good != "99AAPFU0939F1ZV" else "00AAPFU0939F1ZV"[:15]))

    def test_epoch_ms(self):
        self.assertTrue(P.is_epoch_ms("1729317600000"))
        self.assertFalse(P.is_epoch_ms("4111111111111"))


class Values(unittest.TestCase):
    def k(self, v, t=""):
        return P.classify_value(v, t)

    def test_contact(self):
        self.assertIn("email", self.k("ramesh.k@gmail.com"))
        self.assertIn("phone", self.k("+91 98765 43210"))
        self.assertIn("phone", self.k("9876543210"))
        self.assertNotIn("phone", self.k("1234567890"))
        self.assertNotIn("phone", self.k("9999999999"))
        self.assertIn("upi", self.k("ramesh@okaxis"))
        self.assertNotIn("email", self.k("ramesh@okaxis"))

    def test_financial_and_ids(self):
        self.assertIn("card", self.k("4111 1111 1111 1111"))
        self.assertNotIn("card", self.k("1729317600000"))          # a timestamp, not a card
        self.assertIn("pan", self.k("ABCPE1234F"))
        self.assertNotIn("pan", self.k("ABCXE1234F"))               # X is not a PAN holder type
        self.assertIn("ifsc", self.k("HDFC0001234"))
        self.assertIn("passport", self.k("J8369854"))
        good, _ = with_check("23456789012", P.verhoeff_ok)
        self.assertIn("aadhaar", self.k(good))
        self.assertIn("aadhaar", self.k(f"{good[:4]} {good[4:8]} {good[8:]}"))

    def test_secrets(self):
        self.assertIn("password_hash", self.k("$2b$12$" + "a" * 53))
        self.assertIn("jwt", self.k("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"))
        self.assertIn("token", self.k("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"))

    def test_places_and_dates(self):
        self.assertIn("address", self.k("Flat 12, Shanti Nagar, MG Road"))
        self.assertIn("city_state", self.k("Pune"))
        self.assertIn("city_state", self.k("Maharashtra"))
        self.assertIn("adult_age_date", self.k("1990-05-14", "date"))
        self.assertIn("ip", self.k("8.8.8.8"))
        self.assertIn("ip_private", self.k("10.0.0.5"))


class Text(unittest.TestCase):
    def kinds(self, s):
        return [k for k, *_ in P.scan_text(s)]

    def test_timestamps_are_not_cards(self):
        self.assertEqual(self.kinds("Saw local status change event StatusChangeEvent [timestamp=1729317600000, current=UP, previous=STARTING]"), [])
        self.assertEqual(self.kinds("Discovery Client initialized at timestamp 1729317600123 with initial instances count: 0"), [])

    def test_real_leaks(self):
        k = self.kinds("Payment failed for card 4111 1111 1111 1111, customer ramesh.k@gmail.com, phone +91 98765 43210")
        self.assertEqual(k, ["card", "email", "phone"])
        self.assertIn("jwt", self.kinds("auth header Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"))

    def test_context_and_private(self):
        self.assertEqual(self.kinds("request took 9876543210 ns"), [])
        self.assertEqual(self.kinds("connecting to 10.0.0.5:5432"), [])
        self.assertEqual(self.kinds("client 8.8.8.8 connected"), ["ip"])
        self.assertEqual(self.kinds("already masked [EMAIL] and [PHONE]"), [])
        self.assertEqual(self.kinds("admin@example.com seeded"), [])

    def test_numbers_inside_ids_and_hashes(self):
        self.assertEqual(self.kinds('{"rawMessageSha256": "f7446d77d85e66e2a5d3434590f843828192a62346b03c5dd25dcc0b8f32f907"}'), [])
        self.assertEqual(self.kinds('{"eventId": "1e3d0328-5961-4406-9b3e-c51bd05f6cb6", "traceId": "46e0a9a1-5d8e-4039-8012-b4cd01b768a5"}'), [])
        self.assertEqual(self.kinds('{"durationNanos": 4111111111111111, "rowCount": 9876543210}'), [])
        self.assertEqual(self.kinds('{"phone": "9876543210"}'), ["phone"])

    def test_masked_tokens(self):
        v = P.masked_token_verdicts("StatusChangeEvent [timestamp=[CARD], current=UP] and card [CARD] declined")
        self.assertEqual([x["false_positive"] for x in v], [True, False])


class Fusion(unittest.TestCase):
    def test_hidden_phone(self):
        r = P.score_column("customers", "ref", "text", ["98765432%02d" % i for i in range(40)], person_table=True)
        self.assertEqual((r["kind"], r["verdict"]), ("phone", "confirmed"))
        self.assertTrue(any("hidden" in e for e in r["evidence"]))

    def test_product_name_is_not_personal(self):
        r = P.score_column("products", "name", "text", ["Running Shoes", "Steel Bottle", "Cotton Kurta"] * 10, person_table=False, v1="name")
        self.assertEqual(r["verdict"], "not_personal")

    def test_name_says_phone_values_dont(self):
        r = P.score_column("orders", "phone", "text", ["N/A", "unknown", "-", "pending"] * 5, person_table=True)
        self.assertIn(r["verdict"], ("not_personal", "possible"))

    def test_fk_link(self):
        r = P.score_column("orders", "buyer", "int8", list(range(30)), fk="customers.id", person_table=True)
        self.assertEqual((r["kind"], r["verdict"]), ("person_link", "confirmed"))

    def test_empty_table_falls_back_to_name(self):
        r = P.score_column("product_reviews", "reviewer_name", "text", [], person_table=True)
        self.assertEqual((r["kind"], r["verdict"]), ("person_name", "likely"))
        r = P.score_column("audit_rows", "comment", "text", [], person_table=False)
        self.assertEqual(r["verdict"], "possible")

    def test_small_sample_still_uses_values(self):
        r = P.score_column("customer_addresses", "phone", "text", ["9876543210", "8765432109"], person_table=True)
        self.assertEqual((r["kind"], r["verdict"]), ("phone", "confirmed"))
        self.assertTrue(any("small sample" in e for e in r["evidence"]))

    def test_payment_refs_and_addresses(self):
        r = P.score_column("payments", "provider_payment_id", "text", ["pay_%014d" % i for i in range(8)], person_table=False)
        self.assertEqual(r["kind"], "payment_ref")
        r = P.score_column("customer_orders", "ship_line1", "text", ["221B Baker St", "12 Linking Road", "Flat 4, Sunshine Apts", "45 Nehru Marg"] * 3, person_table=True)
        self.assertEqual((r["kind"], r["verdict"]), ("address", "confirmed"))

    def test_flags_and_links(self):
        r = P.score_column("customer_addresses", "default_address", "bool", [True, False, True], person_table=True, v1="address")
        self.assertEqual(r["verdict"], "not_personal")
        self.assertIn("true/false", r["evidence"][0])
        r = P.score_column("payments", "customer_id", "int8", [3, 5, 5, 3], fk="customers.id (inferred …)", person_table=False)
        self.assertEqual((r["kind"], r["verdict"]), ("person_link", "confirmed"))
        r = P.score_column("payments", "customer_id", "int8", [101, 102], person_table=False)
        self.assertEqual((r["kind"], r["verdict"]), ("person_link", "likely"))

    def test_staff_links_need_review(self):
        r = P.score_column("product_stock_adjustments", "actor_user_id", "int8", [], person_table=False)
        self.assertEqual((r["kind"], r["verdict"]), ("person_link", "possible"))
        r = P.score_column("product_stock_adjustments", "actor_user_id", "int8", [1, 2], fk="auth_users.id (inferred …)")
        self.assertEqual(r["verdict"], "confirmed")

    def test_address_lines_without_numbers(self):
        r = P.score_column("customer_addresses", "line1", "text", ["Baner Hills", "Koregaon Park East Lane", "Model Colony", "Aundh Gaon"], person_table=True)
        self.assertEqual((r["kind"], r["verdict"]), ("address", "likely"))

    def test_feedback_wins(self):
        r = P.score_column("customers", "nickname", "text", ["Rocky"] * 10, feedback={"verdict": "not_personal", "by": "admin@x.com"})
        self.assertEqual((r["verdict"], r["confidence"]), ("not_personal", 100))

    def test_password_hash(self):
        r = P.score_column("auth_users", "password_hash", "text", ["$2b$10$" + (str(i) * 60)[:53] for i in range(1, 9)], person_table=True)
        self.assertEqual((r["kind"], r["verdict"]), ("password_hash", "confirmed"))


if __name__ == "__main__":
    unittest.main()

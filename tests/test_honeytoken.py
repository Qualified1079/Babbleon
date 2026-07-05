import unittest

from babbleon import honeytoken as ht


class HoneytokenTests(unittest.TestCase):
    def test_api_key_contains_mark_and_is_unique(self):
        a = ht.make_api_key()
        b = ht.make_api_key()
        self.assertIn(ht.TOKEN_MARK, a.value)
        self.assertNotEqual(a.value, b.value)
        self.assertNotEqual(a.id, b.id)

    def test_db_password_shape(self):
        token = ht.make_db_password()
        self.assertEqual(token.kind, "db_password")
        self.assertGreater(len(token.value), 10)
        self.assertIn(token.id, token.value)

    def test_admin_override_value_embeds_id(self):
        token = ht.make_admin_override()
        self.assertIn(token.id, token.value)

    def test_internal_url_shape(self):
        token = ht.make_internal_url("svc.internal.corp")
        self.assertTrue(token.value.startswith("https://svc.internal.corp/"))
        self.assertIn(token.id, token.value)
        self.assertFalse(token.live)

    def test_internal_url_with_callback_base_url_is_live(self):
        token = ht.make_internal_url(
            "svc.internal.corp", callback_base_url="https://hooks.example.com/abc/"
        )
        self.assertTrue(token.live)
        self.assertTrue(token.value.startswith("https://hooks.example.com/abc/babbleon/"))
        self.assertIn("svc.internal.corp", token.value)
        self.assertIn(token.id, token.value)

    def test_default_honeytoken_is_not_live(self):
        for maker in (ht.make_api_key, ht.make_db_password, ht.make_admin_override):
            self.assertFalse(maker().live)

    def test_to_dict_roundtrip_fields(self):
        token = ht.make_api_key()
        d = token.to_dict()
        self.assertEqual(d["id"], token.id)
        self.assertEqual(d["value"], token.value)
        self.assertEqual(d["kind"], "api_key")

    def test_no_real_provider_prefix(self):
        for _ in range(10):
            self.assertFalse(ht.make_api_key().value.startswith("AKIA"))


if __name__ == "__main__":
    unittest.main()

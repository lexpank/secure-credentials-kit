import unittest

from secure_credentials.secrets_loader import CredentialsContainer, normalize_credentials


class CredentialsContainerTests(unittest.TestCase):
    def test_empty_credentials_are_normalized_to_dict(self):
        container = CredentialsContainer(None)

        self.assertIsNone(container.get("SOME_ENV_VAR"))

    def test_mapping_credentials_support_get_and_dig(self):
        container = CredentialsContainer({"database": {"url": "postgres://example"}})

        self.assertEqual(container.get("database"), {"url": "postgres://example"})
        self.assertEqual(container.dig("database", "url"), "postgres://example")

    def test_string_credentials_raise_clear_error(self):
        with self.assertRaisesRegex(ValueError, "mapping at the root"):
            CredentialsContainer("SOME_ENV_VAR=secret")

    def test_list_credentials_raise_clear_error(self):
        with self.assertRaisesRegex(ValueError, "mapping at the root"):
            normalize_credentials(["secret"])


if __name__ == "__main__":
    unittest.main()

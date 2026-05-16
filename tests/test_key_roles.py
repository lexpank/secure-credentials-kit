import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secure_credentials.credentials import (
    generate_credentials_key,
    resolve_master_key_path,
    resolve_read_key_path,
)
from secure_credentials.utils import (
    KEY_FORMAT_VERSION,
    MASTER_KEY_ROLE,
    READONLY_KEY_ROLE,
    decrypt_credentials_data,
    encrypt_credentials_data,
    is_master_key,
    is_readonly_key,
    serialize_key,
)


def make_master_key() -> str:
    return serialize_key(
        {
            "version": KEY_FORMAT_VERSION,
            "role": MASTER_KEY_ROLE,
            "encryption_key": "encryption",
            "signing_key": "signing",
            "verification_key": "verification",
        }
    )


def make_readonly_key() -> str:
    return serialize_key(
        {
            "version": KEY_FORMAT_VERSION,
            "role": READONLY_KEY_ROLE,
            "encryption_key": "encryption",
            "verification_key": "verification",
        }
    )


class KeyRoleTests(unittest.TestCase):
    def test_generated_key_roles_are_identified(self):
        self.assertTrue(is_master_key(make_master_key()))
        self.assertTrue(is_readonly_key(make_readonly_key()))

    def test_readonly_key_cannot_encrypt_credentials(self):
        with self.assertRaises(PermissionError):
            encrypt_credentials_data(make_readonly_key(), "api_key: secret")

    def test_master_key_encrypts_signed_envelope(self):
        with patch("secure_credentials.utils.encrypt_data", return_value="encrypted"):
            with patch("secure_credentials.utils._sign_data", return_value="signed"):
                encrypted = encrypt_credentials_data(make_master_key(), "api_key: secret")

        envelope = json.loads(encrypted)
        self.assertEqual(envelope["version"], KEY_FORMAT_VERSION)
        self.assertEqual(envelope["payload"], "encrypted")
        self.assertEqual(envelope["signature"], "signed")

    def test_readonly_key_decrypts_after_signature_verification(self):
        encrypted = json.dumps(
            {
                "version": KEY_FORMAT_VERSION,
                "payload": "encrypted",
                "signature": "signed",
            }
        )

        with patch("secure_credentials.utils._verify_signature") as verify_signature:
            with patch("secure_credentials.utils.decrypt_data", return_value="plain"):
                plain = decrypt_credentials_data(make_readonly_key(), encrypted)

        self.assertEqual(plain, "plain")
        verify_signature.assert_called_once_with(
            "verification",
            "encrypted",
            "signed",
        )

    def test_version_two_keys_reject_unsigned_credentials(self):
        with self.assertRaises(ValueError):
            decrypt_credentials_data(make_readonly_key(), "unsigned-ciphertext")

    def test_generate_credentials_key_writes_master_and_readonly_by_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch(
                "secure_credentials.credentials.generate_credentials_key_pair",
                return_value=("master-key", "readonly-key"),
            ):
                generated = generate_credentials_key("production", tmpdir)

            master_path = Path(tmpdir) / "production.master.key"
            readonly_path = Path(tmpdir) / "production.readonly.key"
            self.assertEqual(
                generated,
                {"master": str(master_path), "readonly": str(readonly_path)},
            )
            self.assertEqual(master_path.read_text(), "master-key")
            self.assertEqual(readonly_path.read_text(), "readonly-key")

    def test_read_key_prefers_readonly_and_master_key_rejects_readonly_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            readonly_path = Path(tmpdir) / "production.readonly.key"
            readonly_path.write_text(make_readonly_key())

            self.assertEqual(resolve_read_key_path("production", tmpdir), str(readonly_path))
            with self.assertRaises(PermissionError):
                resolve_master_key_path("production", tmpdir)


if __name__ == "__main__":
    unittest.main()
